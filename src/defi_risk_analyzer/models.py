from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field


Severity = Literal["low", "medium", "high", "critical"]


class RedFlag(BaseModel):
    # Static analysis finding.
    id: str
    title: str
    description: str
    severity: Severity
    evidence: str | None = None


class LLMFinding(BaseModel):
    # LLM-derived finding parsed from structured JSON output.
    issue: str
    function: str
    severity: Severity
    explanation: str
    recommendation: str


class RiskReport(BaseModel):
    # Unified report containing static and LLM findings.
    contract_address: str
    chain: str
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    overall_risk: Severity
    red_flags: list[RedFlag] = Field(default_factory=list)
    llm_findings: list[LLMFinding] = Field(default_factory=list)
    llm_summary: str | None = None
