import re
from defi_risk_analyzer.models import RiskReport, RedFlag, LLMFinding
from defi_risk_analyzer.scoring import SEVERITY_WEIGHTS, SEVERITY_RANK
from defi_risk_analyzer.analysis.static_analysis import PATTERNS


def generate_security_report(report: RiskReport) -> str:
    """Generate a human-readable Markdown security report."""
    summary = _build_summary(report)
    technical = _build_technical_issues(report.static_findings)
    ai_findings = _build_ai_findings(report.llm_findings)
    score_section = _build_security_score(report)

    return "\n".join(
        [
            "# Security Report",
            "",
            "## Summary",
            summary,
            "",
            "## Technical Issues",
            technical,
            "",
            "## AI Findings",
            ai_findings,
            "",
            "## Security Score",
            score_section,
        ]
    )


def _build_summary(report: RiskReport) -> str:
    if not report.static_findings and not report.llm_findings:
        return "No issues were detected by static or AI analysis."

    critical = _collect_top_issues(report)
    overview = (
        f"The contract has **{len(report.static_findings)}** static findings and "
        f"**{len(report.llm_findings)}** AI findings."
    )
    if critical:
        top = "; ".join(critical[:3])
        return f"{overview} Most critical risks: {top}."
    return f"{overview} No high-severity risks were detected."


def _build_technical_issues(findings: list[RedFlag]) -> str:
    if not findings:
        return "- No static issues detected."
    lines: list[str] = []
    for finding in findings:
        function_name = _extract_function_name(finding.evidence or "")
        lines.append(
            f"- **{finding.title}** | Function: `{function_name}` | "
            f"Severity: **{finding.severity}**"
        )
        lines.append(f"  - {finding.description}")
    return "\n".join(lines)


def _build_ai_findings(findings: list[LLMFinding]) -> str:
    if not findings:
        return "- No AI findings available."
    lines: list[str] = []
    for finding in findings:
        lines.append(
            f"- **{finding.issue}** | Function: `{finding.function}` | "
            f"Severity: **{finding.severity}**"
        )
        lines.append(f"  - {finding.explanation}")
        lines.append(f"  - Recommendation: {finding.recommendation}")
    return "\n".join(lines)


def _build_security_score(report: RiskReport) -> str:
    score, total_points, capped_deduction = _compute_security_score(
        report.static_findings, report.llm_findings
    )
    raw_deduction = total_points
    explanation = (
        "Score starts at 100 and subtracts weighted points per severity "
        "(low=1, medium=5, high=10, critical=25), then clamps at 0.0 "
        f"(total points: {total_points:.1f}, raw deduction: {raw_deduction:.1f}, "
        f"capped deduction: {capped_deduction:.1f})."
    )
    return f"**{score:.1f} / 100** — {explanation}"


def _compute_security_score(
    static_findings: list[RedFlag],
    llm_findings: list[LLMFinding],
) -> tuple[float, float, float]:
    total = _sum_severity_points(static_findings) + _sum_severity_points(llm_findings)
    capped_deduction = min(100.0, total)
    score = max(0.0, 100.0 - capped_deduction)
    return score, total, capped_deduction


def _collect_top_issues(report: RiskReport) -> list[str]:
    issues: list[tuple[Severity, str]] = []
    for finding in report.static_findings:
        issues.append((finding.severity, finding.title))
    for finding in report.llm_findings:
        issues.append((finding.severity, finding.issue))

    issues.sort(key=lambda item: SEVERITY_RANK[item[0]], reverse=True)
    return [name for _, name in issues]


def _sum_severity_points(findings: list[RedFlag | LLMFinding]) -> float:
    return sum(SEVERITY_WEIGHTS.get(item.severity, 0.0) for item in findings)


def _extract_function_name(evidence: str) -> str:
    match = re.search(PATTERNS["function_name"], evidence)
    if match:
        return match.group(1)
    return "Unknown"
