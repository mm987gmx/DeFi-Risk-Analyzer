from defi_risk_analyzer.models import LLMFinding, RedFlag, RiskReport
from defi_risk_analyzer.report.report_generator import generate_security_report


def test_report_structure_sections_in_order() -> None:
    report = RiskReport(
        contract_address="0x123",
        chain="ethereum",
        overall_risk="medium",
        static_findings=[
            RedFlag(
                id="source:delegatecall",
                title="Use of delegatecall",
                description="delegatecall can allow code execution in caller context.",
                severity="high",
                evidence="Line 1: function foo() { delegatecall(...) }",
            )
        ],
        llm_findings=[
            LLMFinding(
                issue="Missing access control",
                function="upgradeTo",
                severity="high",
                explanation="Upgrade is callable by anyone.",
                recommendation="Add onlyOwner.",
            )
        ],
    )

    output = generate_security_report(report)

    summary_idx = output.find("## Summary")
    tech_idx = output.find("## Technical Issues")
    ai_idx = output.find("## AI Findings")
    score_idx = output.find("## Security Score")

    assert summary_idx != -1
    assert tech_idx != -1
    assert ai_idx != -1
    assert score_idx != -1
    assert summary_idx < tech_idx < ai_idx < score_idx
