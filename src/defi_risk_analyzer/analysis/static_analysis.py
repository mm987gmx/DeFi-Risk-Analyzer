import re
from defi_risk_analyzer.models import RedFlag
from defi_risk_analyzer.analysis.rules import BYTECODE_RULES, SOURCE_RULES, Rule


# Centralized regex patterns for source code analysis.
PATTERNS = {
    "external_function": r"\bfunction\b[^{;]*\b(external|public)\b",
    "non_reentrant": r"\bnonReentrant\b",
    "reentrancy_risk": r"\bdelegatecall\b|call\s*\.\s*value|\.\s*call\b",
    "owner_reference": r"\b(owner|Ownable|transferOwnership)\b",
    "only_owner": r"\bonlyOwner\b",
    "function_name": r"\bfunction\s+([A-Za-z0-9_]+)\b",
}


def _match_source_rule(rule: Rule, source_code: str) -> re.Match | None:
    # Decide how to match a rule against source code: whole-word or regex.
    if rule.match_type == "word":
        pattern = rf"\b{re.escape(rule.pattern)}\b"
        return re.search(pattern, source_code, re.IGNORECASE)
    if rule.match_type == "regex":
        return re.search(rule.pattern, source_code, re.IGNORECASE)
    raise ValueError(f"Unsupported match type for source rule: {rule.match_type}")


def _build_evidence_from_match(source_code: str, match: re.Match, label: str) -> str:
    """Build human-readable evidence string pointing to the match location.
    
    Args:
        source_code: Full source code text
        match: Regex match object containing the position
        label: Descriptive label for the evidence (e.g., rule ID or check name)
    
    Returns:
        Formatted evidence string with line number and snippet
    """
    line_number, line_text = _extract_line_context(source_code, match)
    return f"Line {line_number}: {line_text} ({label})"


def analyze_source(source_code: str) -> list[RedFlag]:
    """Scan Solidity source for risky patterns using rule-based matching."""
    findings: list[RedFlag] = []
    if not source_code:
        return findings

    for rule in SOURCE_RULES:
        match = _match_source_rule(rule, source_code)
        if match:
            # Evidence includes the line number and snippet for quick review.
            findings.append(
                RedFlag(
                    id=f"source:{rule.id}",
                    title=rule.title,
                    description=rule.description,
                    severity=rule.severity,
                    evidence=_build_evidence_from_match(source_code, match, f"matched '{rule.id}'"),
                )
            )
    return findings


def analyze_bytecode(bytecode: str) -> list[RedFlag]:
    """Scan EVM bytecode for known opcode sequences (e.g., delegatecall)."""
    findings: list[RedFlag] = []
    if not bytecode:
        return findings

    normalized = bytecode.lower().replace("0x", "")
    for rule in BYTECODE_RULES:
        if rule.match_type != "substring":
            raise ValueError(f"Unsupported match type for bytecode rule: {rule.match_type}")
        if rule.pattern in normalized:
            findings.append(
                RedFlag(
                    id=f"bytecode:{rule.id}",
                    title=rule.title,
                    description=rule.description,
                    severity=rule.severity,
                    evidence=f"Found opcode sequence '{rule.pattern}'.",
                )
            )
    return findings


def _extract_line_context(source_code: str, match: re.Match) -> tuple[int, str]:
    """Extract line number and trimmed line text from a regex match."""
    line_number = source_code[: match.start()].count("\n") + 1
    line_text = source_code.splitlines()[line_number - 1].strip()
    return line_number, line_text


def _find_external_function(source_code: str) -> re.Match | None:
    """Find the first external/public function for evidence purposes."""
    return re.search(PATTERNS["external_function"], source_code, re.IGNORECASE)


def _find_owner_reference(source_code: str) -> re.Match | None:
    """Find the first owner-related pattern in source code."""
    return re.search(PATTERNS["owner_reference"], source_code)
