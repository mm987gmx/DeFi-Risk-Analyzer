"""Unified severity scoring configuration."""
from defi_risk_analyzer.models import Severity


# Severity weights for security score computation (0-100 scale).
SEVERITY_WEIGHTS: dict[Severity, float] = {
    "low": 1.0,
    "medium": 5.0,
    "high": 10.0,
    "critical": 25.0,
}

# Severity ordering for sorting and prioritization.
SEVERITY_RANK: dict[Severity, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# Legacy scoring for overall risk threshold computation.
LEGACY_SEVERITY_SCORES: dict[str, float] = {
    "low": 0.5,
    "medium": 1.0,
    "high": 2.0,
    "critical": 3.0,
}
