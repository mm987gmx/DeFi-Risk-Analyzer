import re
from defi_risk_analyzer.models import RedFlag


SOURCE_RULES: list[tuple[str, str, str, str]] = [
    (
        "delegatecall",
        "Use of delegatecall",
        "delegatecall can allow code execution in caller context.",
        "high",
    ),
    (
        "selfdestruct",
        "Use of selfdestruct",
        "selfdestruct can permanently remove contract code.",
        "high",
    ),
    (
        "tx.origin",
        "Use of tx.origin",
        "tx.origin is unsafe for authorization checks.",
        "medium",
    ),
    (
        "upgradeable",
        "Upgradeable pattern",
        "Upgradeable contracts can change logic after deployment.",
        "medium",
    ),
    (
        "owner",
        "Owner privileges",
        "Owner-only controls can enable privileged actions.",
        "low",
    ),
]


BYTECODE_PATTERNS: list[tuple[str, str, str, str]] = [
    (
        "ff",
        "Possible selfdestruct opcode",
        "Bytecode contains 0xFF, which can represent SELFDESTRUCT.",
        "high",
    ),
    (
        "f4",
        "Possible delegatecall opcode",
        "Bytecode contains 0xF4, which can represent DELEGATECALL.",
        "high",
    ),
]


def analyze_source(source_code: str) -> list[RedFlag]:
    flags: list[RedFlag] = []
    if not source_code:
        return flags

    for keyword, title, description, severity in SOURCE_RULES:
        if re.search(rf"\\b{re.escape(keyword)}\\b", source_code, re.IGNORECASE):
            flags.append(
                RedFlag(
                    id=f"source:{keyword}",
                    title=title,
                    description=description,
                    severity=severity,
                    evidence=f"Matched keyword '{keyword}'.",
                )
            )
    return flags


def analyze_bytecode(bytecode: str) -> list[RedFlag]:
    flags: list[RedFlag] = []
    if not bytecode:
        return flags

    normalized = bytecode.lower().replace("0x", "")
    for opcode, title, description, severity in BYTECODE_PATTERNS:
        if opcode in normalized:
            flags.append(
                RedFlag(
                    id=f"bytecode:{opcode}",
                    title=title,
                    description=description,
                    severity=severity,
                    evidence=f"Found opcode sequence '{opcode}'.",
                )
            )
    return flags
