import argparse
from rich import print
from rich.console import Console

from defi_risk_analyzer.analysis.static_analysis import (
    analyze_bytecode,
    analyze_source,
)
from defi_risk_analyzer.analysis.heuristics import check_missing_modifiers
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
from defi_risk_analyzer import console_reporter


CHAIN_IDS = {
    "ethereum": 1,
    "mainnet": 1,
}


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

    if _run_exploit_test(args, console):
        return

    if not _validate_args(args, console):
        return

    chain_id = _resolve_chain_id(args.chain, console)

    bytecode = _fetch_bytecode(settings.rpc_url, args.address, console)
    source_code = _fetch_source_code(
        settings.etherscan_api_key,
        chain_id,
        args.address,
        console,
    )

    if not bytecode and not source_code:
        console_reporter.report_no_code_detected(console)
        return

    console_reporter.report_running_analysis(console)
    findings = (
        analyze_bytecode(bytecode)
        + analyze_source(source_code)
        + check_missing_modifiers(source_code)
    )

    report = RiskReport(
        contract_address=args.address,
        chain=args.chain,
        overall_risk=compute_overall_risk(findings),
        static_findings=findings,
    )

    # LLM step is optional and only runs when source code is available.
    report = enrich_with_llm(report, settings, source_code)

    if args.format == "markdown":
        print(generate_security_report(report))
    else:
        print(to_json(report))


def _validate_args(args: argparse.Namespace, console: Console) -> bool:
    """Validate required CLI arguments for normal analysis mode.
    
    Returns:
        True if validation passes, False otherwise
    """
    if not args.address:
        console.print("[red]--address is required unless --exploit-test is used.[/red]")
        return False
    return True


def _run_exploit_test(args: argparse.Namespace, console: Console) -> bool:
    if not args.exploit_test:
        return False
    # Exploit evaluation mode runs a local fixture with expected labels.
    with open(args.exploit_test, "r", encoding="utf-8") as handle:
        source_code = handle.read()
    if not args.expected:
        console.print("[red]--expected is required in exploit test mode.[/red]")
        return True
    expected = load_expected_flags(args.expected)
    result = evaluate_exploit_contract(source_code, expected)
    print(generate_exploit_report(result))
    return True


def _resolve_chain_id(chain: str, console: Console) -> int:
    chain_id = CHAIN_IDS.get(chain.lower())
    if chain_id is None:
        console_reporter.report_unknown_chain(console)
        return 1
    return chain_id


def _fetch_bytecode(rpc_url: str | None, address: str, console: Console) -> str:
    if not rpc_url:
        console_reporter.report_rpc_skip(console)
        return ""
    console_reporter.report_rpc_fetching(console)
    rpc = BlockchainRPC(rpc_url)
    bytecode = rpc.get_bytecode(address)
    if not bytecode:
        console_reporter.report_no_bytecode(console)
    return bytecode


def _fetch_source_code(
    api_key: str | None,
    chain_id: int,
    address: str,
    console: Console,
) -> str:
    if not api_key:
        console_reporter.report_etherscan_skip(console)
        return ""
    console_reporter.report_etherscan_fetching(console)
    etherscan = EtherscanClient(api_key, chain_id=chain_id)
    source_code, status, message, detail = etherscan.get_source_code(address)
    if not source_code:
        console_reporter.report_no_source(console, status, message, detail)
    return source_code
