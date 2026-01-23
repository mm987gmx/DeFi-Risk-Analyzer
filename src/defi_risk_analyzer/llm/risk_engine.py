import textwrap
import requests

from defi_risk_analyzer.config import Settings
from defi_risk_analyzer.models import RiskReport


# Base prompt sent to the model for risk analysis.
PROMPT = """You are a smart contract security auditor.

Analyze the following Solidity smart contract and identify potential security risks
and bad practices.

Focus especially on:
- Reentrancy risks
- Missing access control (e.g. onlyOwner)
- Unsafe external calls
- Incorrect order of state changes and external interactions
- Missing input validation
- Any other common DeFi vulnerabilities you notice

For each issue:
- Specify the function name
- Classify severity (LOW / MEDIUM / HIGH)
- Explain why this is a risk in simple, clear language
- Suggest a concrete mitigation or best practice

Return the result as a JSON array with the following structure:
[
  {
    "issue": "...",
    "function": "...",
    "severity": "...",
    "explanation": "...",
    "recommendation": "..."
  }
]

Smart contract code:
"""


def _build_user_message(source_code: str) -> str:
    # Trim the prompt payload to a safe size to avoid oversized requests.
    snippet = textwrap.shorten(source_code, width=6000, placeholder="\n... [truncated]")
    return f"{PROMPT}{snippet}"


def _call_openai(model: str, api_key: str, user_message: str) -> str:
    # Minimal chat-completions call using the OpenAI REST API.
    response = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}"},
        json={
            "model": model,
            "messages": [{"role": "user", "content": user_message}],
            "temperature": 0.2,
        },
        timeout=30,
    )
    response.raise_for_status()
    payload = response.json()
    return payload["choices"][0]["message"]["content"].strip()


def enrich_with_llm(
    report: RiskReport,
    settings: Settings,
    source_code: str,
) -> RiskReport:
    # Enrich the report with model-generated insights when possible.
    if not settings.openai_api_key:
        report.llm_summary = (
            "LLM summary skipped because OPENAI_API_KEY is not set."
        )
        return report

    if not source_code:
        report.llm_summary = (
            "LLM summary skipped because no source code is available."
        )
        return report

    try:
        report.llm_summary = _call_openai(
            settings.openai_model,
            settings.openai_api_key,
            _build_user_message(source_code),
        )
    except requests.RequestException as exc:
        report.llm_summary = f"LLM request failed: {exc}"
    return report
