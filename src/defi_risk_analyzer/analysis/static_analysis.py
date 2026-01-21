import re
from defi_risk_analyzer.models import RedFlag
from defi_risk_analyzer.analysis.rules import BYTECODE_RULES, SOURCE_RULES, Rule


def _match_source_rule(rule: Rule, source_code: str) -> re.Match | None:
    # Decide how to match a rule against source code: whole-word or regex.
    if rule.match_type == "word":
        pattern = rf"\b{re.escape(rule.pattern)}\b"
        return re.search(pattern, source_code, re.IGNORECASE)
    if rule.match_type == "regex":
        return re.search(rule.pattern, source_code, re.IGNORECASE)
    return None


def _build_source_evidence(source_code: str, match: re.Match, rule: Rule) -> str:
    # Create a human-readable clue that points to where the match occurred.
    line_number = source_code[: match.start()].count("\n") + 1
    line_text = source_code.splitlines()[line_number - 1].strip()
    return (
        f"Line {line_number}: {line_text} (matched '{rule.id}')"
    )


def analyze_source(source_code: str) -> list[RedFlag]:
    # Scan the Solidity source for risky patterns and build RedFlag entries.
    flags: list[RedFlag] = []
    if not source_code:
        return flags

    for rule in SOURCE_RULES:
        match = _match_source_rule(rule, source_code)
        if match:
            # Evidence includes the line number and snippet for quick review.
            flags.append(
                RedFlag(
                    id=f"source:{rule.id}",
                    title=rule.title,
                    description=rule.description,
                    severity=rule.severity,
                    evidence=_build_source_evidence(source_code, match, rule),
                )
            )
    return flags


def analyze_bytecode(bytecode: str) -> list[RedFlag]:
    # Scan EVM bytecode for known opcode sequences (e.g., delegatecall).
    flags: list[RedFlag] = []
    if not bytecode:
        return flags

    normalized = bytecode.lower().replace("0x", "")
    for rule in BYTECODE_RULES:
        if rule.match_type == "substring" and rule.pattern in normalized:
            flags.append(
                RedFlag(
                    id=f"bytecode:{rule.id}",
                    title=rule.title,
                    description=rule.description,
                    severity=rule.severity,
                    evidence=f"Found opcode sequence '{rule.pattern}'.",
                )
            )
    return flags
