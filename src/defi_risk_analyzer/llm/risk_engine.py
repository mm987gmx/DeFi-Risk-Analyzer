from defi_risk_analyzer.config import Settings
from defi_risk_analyzer.models import RiskReport


def enrich_with_llm(report: RiskReport, settings: Settings) -> RiskReport:
    if not settings.openai_api_key:
        report.llm_summary = (
            "LLM summary skipped because OPENAI_API_KEY is not set."
        )
        return report

    # Placeholder: here you would call your LLM provider and enrich the report.
    report.llm_summary = (
        "LLM summary is not implemented yet. "
        "Connect your preferred model here."
    )
    return report
