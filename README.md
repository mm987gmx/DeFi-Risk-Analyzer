# DeFi Risk Analyzer

A production-ready DeFi security analysis tool that combines rule-based static analysis with AI-powered insights. Analyzes smart contracts for common vulnerabilities and produces comprehensive security reports.

## Tech Stack

| Category | Technology |
|----------|------------|
| Language | Python 3.10+ |
| Data Validation | Pydantic |
| Blockchain | web3.py |
| HTTP Client | requests |
| CLI Output | rich |
| Testing | pytest |

## Features

### Core Analysis
- **Rule-Based Detection**: Scans for risky patterns like `delegatecall`, `tx.origin`, `call.value`
- **Heuristic Checks**: Identifies missing security modifiers (`nonReentrant`, `onlyOwner`)
- **Bytecode Analysis**: Detects dangerous opcodes (DELEGATECALL, SELFDESTRUCT)
- **AI Insights**: Integrates with OpenAI for contextual security analysis

### Performance & Reliability
- **Smart Caching**: File-based cache with TTL (1 hour default) for API responses
- **Automatic Retry**: Exponential backoff for API calls (Etherscan, RPC)
- **Multi-Chain Support**: Configurable chain ID for different networks

### Output Formats
- **Markdown Report**: Human-readable security report with scoring
- **JSON Export**: Structured data for programmatic analysis
- **Exploit Testing**: Evaluate analyzer against known vulnerable contracts

## Requirements

- **Python**: 3.10 or higher
- **OS**: macOS, Linux, Windows
- **API Keys**: At least one of Etherscan API key or RPC endpoint

## Quick Start

### Installation
```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Configuration
```bash
# Copy example config
cp env.example .env

# Edit .env and add your API keys:
# - RPC_URL (required for bytecode analysis)
# - ETHERSCAN_API_KEY (required for source code)
# - OPENAI_API_KEY (optional, for AI insights)
```

### Usage

**Basic analysis:**
```bash
# Analyze a verified contract (example: a DeFi token)
PYTHONPATH=src python -m defi_risk_analyzer \
  --address 0x6f52d2694ab0131b81f4c3476c7bc4f67ab36418 \
  --format markdown
```

**JSON output:**
```bash
PYTHONPATH=src python -m defi_risk_analyzer \
  --address 0x6f52d2694ab0131b81f4c3476c7bc4f67ab36418 \
  --format json
```

> **Note**: Use any verified contract address from [Etherscan](https://etherscan.io). The example address is a real token contract.

**Exploit testing mode:**
```bash
PYTHONPATH=src python -m defi_risk_analyzer \
  --exploit-test tests/fixtures/reentrancy_vault.sol \
  --expected tests/fixtures/reentrancy_expected.json
```

### Example Output

```markdown
# Security Report

## Summary
The contract has **4** static findings and **3** AI findings. 
Most critical risks: Use of delegatecall; Missing nonReentrant modifier; Unsafe external call.

## Technical Issues
- **Use of delegatecall** | Function: `upgrade` | Severity: **high**
  - Delegatecall can allow code execution in caller's context.
- **Missing nonReentrant modifier** | Function: `withdraw` | Severity: **medium**
  - External functions with external calls detected, but no nonReentrant modifier found.

## AI Findings
- **Reentrancy vulnerability** | Function: `withdraw` | Severity: **high**
  - State changes after external call allow reentrant attacks.
  - Recommendation: Use checks-effects-interactions pattern or nonReentrant modifier.

## Security Score
**65.0 / 100** — Score starts at 100 and subtracts weighted points per severity...
```

## Environment Variables

| Variable | Required | Description | Default |
|----------|----------|-------------|---------|
| `RPC_URL` | Yes* | Ethereum JSON-RPC endpoint for bytecode | - |
| `ETHERSCAN_API_KEY` | Yes* | Etherscan API key for source code | - |
| `OPENAI_API_KEY` | No | OpenAI API key for AI insights | - |
| `OPENAI_MODEL` | No | OpenAI model name | `gpt-4o-mini` |

*At least one of RPC_URL or ETHERSCAN_API_KEY is required for analysis.

> **Get free API keys:**
> - Etherscan: [etherscan.io/apis](https://etherscan.io/apis)
> - RPC: [Alchemy](https://www.alchemy.com/), [Infura](https://www.infura.io/), or [QuickNode](https://www.quicknode.com/)

## Testing

### Run all tests:
```bash
PYTHONPATH=src python -m pytest -v
```

### Run specific test:
```bash
PYTHONPATH=src python -m pytest tests/test_static_analysis.py -v
```

### Test coverage:
- Static analysis (rule-based + heuristic checks)
- Report generation (Markdown structure validation)
- Exploit evaluation (false negative detection)

## How It Works

### Analysis Pipeline
1. **Data Fetching** (with cache & retry)
   - Bytecode via RPC
   - Source code via Etherscan API v2
   
2. **Static Analysis**
   - **Rule-based**: Pattern matching for known vulnerabilities
   - **Heuristic**: Best-effort detection of missing modifiers
   - **Bytecode**: Opcode sequence scanning

3. **AI Enhancement** (optional)
   - Structured prompt to OpenAI
   - Parsed JSON findings with severity, function, and recommendations

4. **Report Generation**
   - Security score (0-100) with severity weights
   - Markdown report with Summary, Technical Issues, AI Findings, Security Score
   - JSON export for programmatic use

### Detection Rules

#### Source Code Patterns
- `delegatecall` — Dangerous delegate calls
- `call.value` — Unsafe value transfers
- `tx.origin` — Authentication using tx.origin

#### Heuristic Checks
- Missing `nonReentrant` modifier when external calls present
- Missing `onlyOwner` modifier when ownership patterns detected

#### Bytecode Patterns
- `f4` opcode (DELEGATECALL)
- `ff` opcode (SELFDESTRUCT)

## Project Structure

```
src/defi_risk_analyzer/
├── analysis/
│   ├── rules.py              # Rule definitions
│   ├── static_analysis.py    # Rule-based pattern matching
│   └── heuristics.py         # Heuristic checks for missing modifiers
├── clients/
│   ├── blockchain_rpc.py     # RPC client (with cache & retry)
│   └── etherscan.py          # Etherscan API client (with cache & retry)
├── evaluation/
│   └── exploit_test.py       # Real-world exploit evaluation
├── llm/
│   └── risk_engine.py        # OpenAI integration
├── report/
│   ├── generator.py          # JSON/Markdown legacy formatter
│   └── report_generator.py   # Enhanced Markdown report
├── cache.py                  # File-based cache with TTL
├── retry.py                  # Retry decorator for API calls
├── scoring.py                # Unified severity scoring
├── console_reporter.py       # CLI output formatting
├── models.py                 # Pydantic data models
├── config.py                 # Settings management
└── cli.py                    # CLI entrypoint
```

## Cache Management

The analyzer caches API responses in `.cache/` directory:
- **Location**: `.cache/rpc/` and `.cache/etherscan/`
- **TTL**: 1 hour (configurable)
- **Format**: JSON files with timestamps
- **Clear cache**: `rm -rf .cache/`

Disable caching programmatically:
```python
from defi_risk_analyzer.clients.blockchain_rpc import BlockchainRPC
rpc = BlockchainRPC(rpc_url, enable_cache=False)
```

## Security Score

The analyzer computes a 0-100 security score using weighted severity points:
- **Critical**: 25 points
- **High**: 10 points
- **Medium**: 5 points
- **Low**: 1 point

Score = 100 - (sum of all severity points, capped at 100)

## Documentation

Detailed documentation is available in the [`docs/`](docs/) directory:

- **[Architecture](docs/architecture.md)** - System design, component responsibilities, and data flow
- **[Threat Model](docs/threat-model.md)** - Detected vulnerabilities and attack vectors
- **[Adding Rules](docs/adding-rules.md)** - Guide for extending detection capabilities

## Roadmap

**Planned improvements:**
- [ ] More detection rules (flash loan patterns, price oracle manipulation)
- [ ] Slither integration for deeper static analysis
- [ ] Multi-file contract support (imports, inheritance)
- [ ] Web UI dashboard
- [ ] GitHub Actions CI/CD pipeline
- [ ] Docker containerization
- [ ] Support for more chains (Polygon, Arbitrum, BSC)

## Contributing

This project follows clean code principles:
- **Separation of concerns**: Analysis, clients, reporting in separate modules
- **DRY**: Single source of truth for rules, patterns, scoring
- **Resilience**: Retry logic, caching, proper error handling
- **Testability**: Modular design with comprehensive test coverage

See [Adding Rules](docs/adding-rules.md) for guidance on extending detection capabilities.

## License

This project is intended for educational and portfolio demonstration purposes.
