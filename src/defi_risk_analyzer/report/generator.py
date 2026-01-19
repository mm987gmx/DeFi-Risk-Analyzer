import json
from defi_risk_analyzer.models import RiskReport, RedFlag, Severity


SEVERITY_ORDER: dict[Severity, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def compute_overall_risk(flags: list[RedFlag]) -> Severity:
    if not flags:
        return "low"
    highest = max(flags, key=lambda flag: SEVERITY_ORDER[flag.severity])
    return highest.severity


def to_json(report: RiskReport) -> str:
    return json.dumps(report.model_dump(), indent=2, default=str)


def to_markdown(report: RiskReport) -> str:
    lines = [
        f"# Risk Report",
        f"- Contract: `{report.contract_address}`",
        f"- Chain: `{report.chain}`",
        f"- Generated at: `{report.generated_at.isoformat()}`",
        f"- Overall risk: **{report.overall_risk}**",
        "",
        "## Red flags",
    ]
    if not report.red_flags:
        lines.append("- No red flags detected by static heuristics.")
    else:
        for flag in report.red_flags:
            lines.append(
                f"- **{flag.title}** ({flag.severity}) — {flag.description}"
            )
            if flag.evidence:
                lines.append(f"  - Evidence: {flag.evidence}")

    if report.llm_summary:
        lines.extend(["", "## LLM summary", report.llm_summary])

    return "\n".join(lines)
