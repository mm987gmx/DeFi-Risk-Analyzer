"""Console reporting utilities for CLI output."""
from rich.console import Console


def report_rpc_skip(console: Console) -> None:
    console.print("[yellow]RPC_URL not set. Bytecode analysis skipped.[/yellow]")


def report_rpc_fetching(console: Console) -> None:
    console.print("[cyan]Fetching bytecode via RPC...[/cyan]")


def report_no_bytecode(console: Console) -> None:
    console.print(
        "[yellow]No bytecode found. This address may be an EOA, not a contract.[/yellow]"
    )


def report_etherscan_skip(console: Console) -> None:
    console.print(
        "[yellow]ETHERSCAN_API_KEY not set. Source analysis skipped.[/yellow]"
    )


def report_etherscan_fetching(console: Console) -> None:
    console.print("[cyan]Fetching source code via Etherscan...[/cyan]")


def report_no_source(console: Console, status: str, message: str, detail: str) -> None:
    console.print(
        "[yellow]No source code found (not verified or not a contract).[/yellow]"
    )
    if status or message:
        console.print(f"[yellow]Etherscan status: {status}, message: {message}[/yellow]")
    if detail:
        console.print(f"[yellow]Etherscan detail: {detail}[/yellow]")


def report_no_code_detected(console: Console) -> None:
    console.print(
        "[red]No contract code detected. Please provide a contract address.[/red]"
    )


def report_running_analysis(console: Console) -> None:
    console.print("[cyan]Running static analysis...[/cyan]")


def report_unknown_chain(console: Console) -> None:
    console.print(
        "[yellow]Unknown chain. Falling back to Ethereum mainnet for Etherscan.[/yellow]"
    )
