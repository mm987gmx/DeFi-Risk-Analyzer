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
    raise ValueError(f"Unsupported match type for source rule: {rule.match_type}")


def _build_source_evidence(source_code: str, match: re.Match, rule: Rule) -> str:
    # Create a human-readable clue that points to where the match occurred.
    line_number, line_text = _get_line_context(source_code, match)
    return (
        f"Line {line_number}: {line_text} (matched '{rule.id}')"
    )


def _build_line_evidence(source_code: str, match: re.Match, label: str) -> str:
    # Similar to _build_source_evidence but for heuristic checks without a Rule.
    line_number, line_text = _get_line_context(source_code, match)
    return f"Line {line_number}: {line_text} ({label})"


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

    # Heuristic checks for missing security modifiers (best-effort).
    external_match = _first_external_function_match(source_code)
    if (
        external_match
        and _references_reentrancy_risk(source_code)
        and not _has_non_reentrant(source_code)
    ):
        flags.append(
            RedFlag(
                id="source:missing-nonreentrant",
                title="Missing nonReentrant modifier",
                description=(
                    "External functions with external calls detected, but no "
                    "nonReentrant modifier found."
                ),
                severity="medium",
                evidence=_build_line_evidence(
                    source_code, external_match, "missing nonReentrant"
                ),
            )
        )

    owner_match = _first_owner_reference_match(source_code)
    if owner_match and not _has_only_owner(source_code):
        flags.append(
            RedFlag(
                id="source:missing-onlyowner",
                title="Missing onlyOwner modifier",
                description=(
                    "Owner-related patterns detected, but no onlyOwner modifier found."
                ),
                severity="medium",
                evidence=_build_line_evidence(
                    source_code, owner_match, "missing onlyOwner"
                ),
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
        if rule.match_type != "substring":
            raise ValueError(f"Unsupported match type for bytecode rule: {rule.match_type}")
        if rule.pattern in normalized:
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


def _get_line_context(source_code: str, match: re.Match) -> tuple[int, str]:
    line_number = source_code[: match.start()].count("\n") + 1
    line_text = source_code.splitlines()[line_number - 1].strip()
    return line_number, line_text


def _first_external_function_match(source_code: str) -> re.Match | None:
    # Grab the first external/public function signature for evidence purposes.
    return re.search(
        r"\bfunction\b[^{;]*\b(external|public)\b",
        source_code,
        re.IGNORECASE,
    )


def _has_non_reentrant(source_code: str) -> bool:
    # Detect the presence of the nonReentrant modifier.
    return bool(re.search(r"\bnonReentrant\b", source_code))


def _references_reentrancy_risk(source_code: str) -> bool:
    # Look for low-level calls that often require reentrancy protection.
    return bool(
        re.search(
            r"\bdelegatecall\b|call\s*\.\s*value|\.\s*call\b",
            source_code,
            re.IGNORECASE,
        )
    )


def _first_owner_reference_match(source_code: str) -> re.Match | None:
    return re.search(r"\b(owner|Ownable|transferOwnership)\b", source_code)


def _has_only_owner(source_code: str) -> bool:
    # Detect the presence of onlyOwner modifier usage.
    return bool(re.search(r"\bonlyOwner\b", source_code))
