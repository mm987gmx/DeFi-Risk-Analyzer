from dataclasses import dataclass
from typing import Literal

from defi_risk_analyzer.models import Severity


# The match type tells the engine how to interpret the pattern.
MatchType = Literal["word", "regex", "substring"]


@dataclass(frozen=True)
class Rule:
    # Unique identifier used in reports and tests.
    id: str
    # Pattern used for matching (plain word, regex, or substring).
    pattern: str
    # Human-readable label shown in the report.
    title: str
    # Explanation for why the rule is risky.
    description: str
    # Risk severity used in the final report.
    severity: Severity
    # How the pattern should be matched.
    match_type: MatchType


# Rules applied to Solidity source code (Etherscan verified source).
SOURCE_RULES: list[Rule] = [
    Rule(
        id="delegatecall",
        pattern="delegatecall",
        title="Use of delegatecall",
        description="delegatecall can allow code execution in caller context.",
        severity="high",
        match_type="word",
    ),
    Rule(
        id="selfdestruct",
        pattern="selfdestruct",
        title="Use of selfdestruct",
        description="selfdestruct can permanently remove contract code.",
        severity="high",
        match_type="word",
    ),
    Rule(
        id="tx.origin",
        pattern="tx.origin",
        title="Use of tx.origin",
        description="tx.origin is unsafe for authorization checks.",
        severity="medium",
        match_type="word",
    ),
    Rule(
        id="call.value",
        pattern=r"call\s*\.\s*value",
        title="Use of call.value",
        description="call.value can be unsafe and is discouraged in modern Solidity.",
        severity="high",
        match_type="regex",
    ),
    Rule(
        id="upgradeable",
        pattern="upgradeable",
        title="Upgradeable pattern",
        description="Upgradeable contracts can change logic after deployment.",
        severity="medium",
        match_type="word",
    ),
    Rule(
        id="owner",
        pattern="owner",
        title="Owner privileges",
        description="Owner-only controls can enable privileged actions.",
        severity="low",
        match_type="word",
    ),
]


# Rules applied to raw bytecode when source code is unavailable.
BYTECODE_RULES: list[Rule] = [
    Rule(
        id="opcode:selfdestruct",
        pattern="ff",
        title="Possible selfdestruct opcode",
        description="Bytecode contains 0xFF, which can represent SELFDESTRUCT.",
        severity="high",
        match_type="substring",
    ),
    Rule(
        id="opcode:delegatecall",
        pattern="f4",
        title="Possible delegatecall opcode",
        description="Bytecode contains 0xF4, which can represent DELEGATECALL.",
        severity="high",
        match_type="substring",
    ),
]
