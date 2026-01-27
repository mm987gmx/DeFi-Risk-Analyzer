import json
from defi_risk_analyzer.models import RiskReport, RedFlag, Severity, LLMFinding
from defi_risk_analyzer.scoring import SEVERITY_RANK, LEGACY_SEVERITY_SCORES


def compute_overall_risk(findings: list[RedFlag]) -> Severity:
    """Returns a severity bucket based on the aggregate risk score."""
    score = compute_risk_score(findings)
    if score < 2.0:
        return "low"
    if score < 4.0:
        return "medium"
    return "high"


def compute_risk_score(findings: list[RedFlag | LLMFinding]) -> float:
    """Return the sum of severity scores for the provided findings.

    Scoring: high=2.0, medium=1.0, low=0.5. Unknown severities are ignored.
    """
    return sum(LEGACY_SEVERITY_SCORES.get(finding.severity, 0.0) for finding in findings)


def to_json(report: RiskReport) -> str:
    # Emit the full report as pretty-printed JSON.
    return json.dumps(report.model_dump(), indent=2, default=str)


def to_markdown(report: RiskReport) -> str:
    """Human-friendly report with separate static and LLM sections."""
    lines = [
        f"# Risk Report",
        f"- Contract: `{report.contract_address}`",
        f"- Chain: `{report.chain}`",
        f"- Generated at: `{report.generated_at.isoformat()}`",
        f"- Overall risk: **{report.overall_risk}**",
        f"- Static findings: **{len(report.static_findings)}**",
        f"- LLM findings: **{len(report.llm_findings)}**",
        "",
        "## Static findings",
    ]
    if not report.static_findings:
        lines.append("- No findings detected by static heuristics.")
    else:
        for finding in report.static_findings:
            lines.append(
                f"- **{finding.title}** ({finding.severity}) — {finding.description}"
            )
            if finding.evidence:
                lines.append(f"  - Evidence: {finding.evidence}")

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
