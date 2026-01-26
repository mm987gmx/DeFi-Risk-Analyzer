import argparse
from rich import print
from rich.console import Console

from defi_risk_analyzer.analysis.static_analysis import (
    analyze_bytecode,
    analyze_source,
)
from defi_risk_analyzer.clients.blockchain_rpc import BlockchainRPC
from defi_risk_analyzer.clients.etherscan import EtherscanClient
from defi_risk_analyzer.config import load_settings
from defi_risk_analyzer.evaluation.exploit_test import (
    evaluate_exploit_contract,
    generate_exploit_report,
    load_expected_flags,
)
from defi_risk_analyzer.llm.risk_engine import enrich_with_llm
from defi_risk_analyzer.models import RiskReport
from defi_risk_analyzer.report.generator import (
    compute_overall_risk,
    to_json,
)
from defi_risk_analyzer.report.report_generator import generate_security_report


def build_arg_parser() -> argparse.ArgumentParser:
    # Define CLI arguments for the main workflow.
    parser = argparse.ArgumentParser(
        description="DeFi Risk Analyzer - engineering version"
    )
    parser.add_argument(
        "--address",
        help="Smart contract address (0x...)",
    )
    parser.add_argument(
        "--chain",
        default="ethereum",
        help="Chain name (default: ethereum)",
    )
    parser.add_argument(
        "--format",
        choices=["json", "markdown"],
        default="json",
        help="Output format (json or markdown)",
    )
    parser.add_argument(
        "--exploit-test",
        help="Path to a Solidity file for exploit evaluation mode.",
    )
    parser.add_argument(
        "--expected",
        help="Path to JSON file with expected red flags.",
    )
    return parser


def main() -> None:
    # Orchestrate data fetching, analysis, LLM enrichment, and output formatting.
    console = Console()
    args = build_arg_parser().parse_args()
    settings = load_settings()

    if args.exploit_test:
        # Exploit evaluation mode runs a local fixture with expected labels.
        source_code = ""
        with open(args.exploit_test, "r", encoding="utf-8") as handle:
            source_code = handle.read()
        if not args.expected:
            console.print("[red]--expected is required in exploit test mode.[/red]")
            return
        expected = load_expected_flags(args.expected)
        result = evaluate_exploit_contract(source_code, expected)
        print(generate_exploit_report(result))
        return

    if not args.address:
        console.print("[red]--address is required unless --exploit-test is used.[/red]")
        return

    chain_ids = {
        "ethereum": 1,
        "mainnet": 1,
    }
    chain_id = chain_ids.get(args.chain.lower())
    if chain_id is None:
        console.print(
            "[yellow]Unknown chain. Falling back to Ethereum mainnet for Etherscan.[/yellow]"
        )
        chain_id = 1

    bytecode = ""
    source_code = ""

    if settings.rpc_url:
        console.print("[cyan]Fetching bytecode via RPC...[/cyan]")
        rpc = BlockchainRPC(settings.rpc_url)
        bytecode = rpc.get_bytecode(args.address)
        if not bytecode:
            console.print(
                "[yellow]No bytecode found. This address may be an EOA, not a contract.[/yellow]"
            )
    else:
        console.print(
            "[yellow]RPC_URL not set. Bytecode analysis skipped.[/yellow]"
        )

    if settings.etherscan_api_key:
        console.print("[cyan]Fetching source code via Etherscan...[/cyan]")
        etherscan = EtherscanClient(settings.etherscan_api_key, chain_id=chain_id)
        source_code, status, message, detail = etherscan.get_source_code(args.address)
        if not source_code:
            console.print(
                "[yellow]No source code found (not verified or not a contract).[/yellow]"
            )
            if status or message:
                console.print(
                    f"[yellow]Etherscan status: {status}, message: {message}[/yellow]"
                )
            if detail:
                console.print(f"[yellow]Etherscan detail: {detail}[/yellow]")
    else:
        console.print(
            "[yellow]ETHERSCAN_API_KEY not set. Source analysis skipped.[/yellow]"
        )

    if not bytecode and not source_code:
        console.print(
            "[red]No contract code detected. Please provide a contract address.[/red]"
        )
        return

    console.print("[cyan]Running static analysis...[/cyan]")
    flags = analyze_bytecode(bytecode) + analyze_source(source_code)

    report = RiskReport(
        contract_address=args.address,
        chain=args.chain,
        overall_risk=compute_overall_risk(flags),
        red_flags=flags,
    )

    # LLM step is optional and only runs when source code is available.
    report = enrich_with_llm(report, settings, source_code)

    if args.format == "markdown":
        print(generate_security_report(report))
    else:
        print(to_json(report))
