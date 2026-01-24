import json
from defi_risk_analyzer.models import RiskReport, RedFlag, Severity, LLMFinding


SEVERITY_ORDER: dict[Severity, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def compute_overall_risk(flags: list[RedFlag]) -> Severity:
    # Returns the highest severity among the given red flags, or "low" if none exist.
    if not flags:
        return "low"
    highest = max(flags, key=lambda flag: SEVERITY_ORDER[flag.severity])
    return highest.severity


def to_json(report: RiskReport) -> str:
    # Emit the full report as pretty-printed JSON.
    return json.dumps(report.model_dump(), indent=2, default=str)


def to_markdown(report: RiskReport) -> str:
    # Human-friendly report with separate static and LLM sections.
    lines = [
        f"# Risk Report",
        f"- Contract: `{report.contract_address}`",
        f"- Chain: `{report.chain}`",
        f"- Generated at: `{report.generated_at.isoformat()}`",
        f"- Overall risk: **{report.overall_risk}**",
        f"- Static findings: **{len(report.red_flags)}**",
        f"- LLM findings: **{len(report.llm_findings)}**",
        "",
        "## Static findings",
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

    if report.llm_findings:
        lines.append("")
        lines.append("## LLM findings")
        for finding in report.llm_findings:
            lines.append(
                f"- **{finding.issue}** ({finding.severity}) — {finding.function}"
            )
            lines.append(f"  - Explanation: {finding.explanation}")
            lines.append(f"  - Recommendation: {finding.recommendation}")
    elif report.llm_summary:
        lines.extend(["", "## LLM summary", report.llm_summary])

    return "\n".join(lines)
