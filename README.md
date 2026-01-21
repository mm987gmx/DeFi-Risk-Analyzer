# DeFi Risk Analyzer (Engineering Version)

This is a starter project for a DeFi risk analysis tool. It accepts a smart contract address, retrieves on-chain data and optional source code, runs simple static checks, and produces a risk report in JSON or Markdown.

## What this project does
- Takes a contract address from the user (CLI).
- Fetches bytecode via RPC and source code via Etherscan (if keys are provided).
- Detects basic red flags with rule-based heuristics.
- Produces a structured risk report.
- Optionally prepares the report for LLM enrichment (stub for now).

## Quick start
1. Create a virtual environment and install dependencies:
   - `python3 -m venv .venv`
   - `source .venv/bin/activate`
   - `python -m pip install -r requirements.txt`
2. Copy `env.example` to `.env` and set your API keys (the app loads them automatically).
3. Run the CLI:
   - `PYTHONPATH=src python -m defi_risk_analyzer --address 0x... --format markdown`

## Environment variables
- `RPC_URL` — Ethereum JSON-RPC endpoint used to fetch bytecode.
- `ETHERSCAN_API_KEY` — API key used to fetch verified source code.
- `OPENAI_API_KEY` — optional, used only for the LLM summary stub.

## Running tests
1. Install the test runner:
   - `python -m pip install pytest`
2. Run the test suite:
   - `PYTHONPATH=src python -m pytest`

## How the static checks work
- Source rules live in `src/defi_risk_analyzer/analysis/rules.py`.
- The engine scans source code for keywords/regex and bytecode for opcode patterns.
- Each match becomes a `RedFlag` entry with evidence (line number and snippet).
## Project layout
- `src/defi_risk_analyzer/cli.py` — CLI entrypoint and main workflow
- `src/defi_risk_analyzer/clients/` — RPC and Etherscan clients
- `src/defi_risk_analyzer/analysis/` — static analysis heuristics
- `src/defi_risk_analyzer/llm/` — LLM risk engine (placeholder)
- `src/defi_risk_analyzer/report/` — report formatting
- `src/defi_risk_analyzer/models.py` — Pydantic models for reports

## Notes
This is an initial skeleton meant for extension. The LLM integration is intentionally minimal.
