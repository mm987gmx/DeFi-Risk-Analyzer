"""Heuristic security checks for missing modifiers and patterns.

These checks use best-effort pattern matching to identify potential issues
that may not be caught by simple rule-based matching.
"""
import re
from defi_risk_analyzer.models import RedFlag
from defi_risk_analyzer.analysis.static_analysis import (
    PATTERNS,
    _build_evidence_from_match,
    _find_external_function,
    _find_owner_reference,
)


def check_missing_modifiers(source_code: str) -> list[RedFlag]:
    """Run heuristic checks for missing security modifiers.
    
    Checks for:
    - Missing nonReentrant when external calls are present
    - Missing onlyOwner when owner patterns are detected
    
    Args:
        source_code: Solidity source code to analyze
        
    Returns:
        List of RedFlag findings from heuristic checks
    """
    findings: list[RedFlag] = []
    
    # Check for missing nonReentrant
    external_match = _find_external_function(source_code)
    if (
        external_match
        and _contains_reentrancy_risk(source_code)
        and not _contains_non_reentrant(source_code)
    ):
        findings.append(
            RedFlag(
                id="heuristic:missing-nonreentrant",
                title="Missing nonReentrant modifier",
                description=(
                    "External functions with external calls detected, but no "
                    "nonReentrant modifier found."
                ),
                severity="medium",
                evidence=_build_evidence_from_match(
                    source_code, external_match, "missing nonReentrant"
                ),
            )
        )
    
    # Check for missing onlyOwner
    owner_match = _find_owner_reference(source_code)
    if owner_match and not _contains_only_owner(source_code):
        findings.append(
            RedFlag(
                id="heuristic:missing-onlyowner",
                title="Missing onlyOwner modifier",
                description=(
                    "Owner-related patterns detected, but no onlyOwner modifier found."
                ),
                severity="medium",
                evidence=_build_evidence_from_match(
                    source_code, owner_match, "missing onlyOwner"
                ),
            )
        )
    
    return findings


def _contains_non_reentrant(source_code: str) -> bool:
    """Check if nonReentrant modifier is present in source code."""
    return bool(re.search(PATTERNS["non_reentrant"], source_code))


def _contains_reentrancy_risk(source_code: str) -> bool:
    """Check if source contains low-level calls that may need reentrancy protection."""
    return bool(re.search(PATTERNS["reentrancy_risk"], source_code, re.IGNORECASE))


def _contains_only_owner(source_code: str) -> bool:
    """Check if onlyOwner modifier is present in source code."""
    return bool(re.search(PATTERNS["only_owner"], source_code))
