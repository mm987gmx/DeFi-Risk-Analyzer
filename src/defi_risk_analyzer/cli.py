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
from defi_risk_analyzer.llm.risk_engine import enrich_with_llm
from defi_risk_analyzer.models import RiskReport
from defi_risk_analyzer.report.generator import (
    compute_overall_risk,
    to_json,
    to_markdown,
)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="DeFi Risk Analyzer - engineering version"
    )
    parser.add_argument(
        "--address",
        required=True,
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
    return parser


def main() -> None:
    console = Console()
    args = build_arg_parser().parse_args()
    settings = load_settings()

    bytecode = ""
    source_code = ""

    if settings.rpc_url:
        console.print("[cyan]Fetching bytecode via RPC...[/cyan]")
        rpc = BlockchainRPC(settings.rpc_url)
        bytecode = rpc.get_bytecode(args.address)
    else:
        console.print(
            "[yellow]RPC_URL not set. Bytecode analysis skipped.[/yellow]"
        )

    if settings.etherscan_api_key:
        console.print("[cyan]Fetching source code via Etherscan...[/cyan]")
        etherscan = EtherscanClient(settings.etherscan_api_key)
        source_code = etherscan.get_source_code(args.address)
    else:
        console.print(
            "[yellow]ETHERSCAN_API_KEY not set. Source analysis skipped.[/yellow]"
        )

    console.print("[cyan]Running static analysis...[/cyan]")
    flags = analyze_bytecode(bytecode) + analyze_source(source_code)

    report = RiskReport(
        contract_address=args.address,
        chain=args.chain,
        overall_risk=compute_overall_risk(flags),
        red_flags=flags,
    )

    report = enrich_with_llm(report, settings)

    if args.format == "markdown":
        print(to_markdown(report))
    else:
        print(to_json(report))
