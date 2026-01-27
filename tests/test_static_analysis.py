from defi_risk_analyzer.analysis.static_analysis import (
    analyze_bytecode,
    analyze_source,
)
from defi_risk_analyzer.analysis.heuristics import check_missing_modifiers


def test_analyze_source_detects_basic_red_flags() -> None:
    # Given: a minimal Solidity snippet containing three risky constructs.
    source = """
    contract Example {
        function dangerous(address target) external {
            (bool ok, ) = target.delegatecall("");
            require(ok);
        }

        function send(address payable to) external {
            to.call.value(1 ether)("");
        }

        function auth() external view returns (address) {
            return tx.origin;
        }
    }
    """
    # When: we run static analysis on the source.
    rule_findings = analyze_source(source)
    heuristic_findings = check_missing_modifiers(source)
    all_findings = rule_findings + heuristic_findings
    ids = {flag.id for flag in all_findings}

    # Then: all patterns are detected.
    assert "source:delegatecall" in ids
    assert "source:call.value" in ids
    assert "source:tx.origin" in ids
    assert "heuristic:missing-nonreentrant" in ids

    # Evidence should be human-readable and include a line reference.
    for flag in all_findings:
        assert flag.evidence is not None
        assert "Line" in flag.evidence


def test_analyze_bytecode_detects_opcodes() -> None:
    # Given: bytecode containing DELEGATECALL (f4) and SELFDESTRUCT (ff).
    bytecode = "0x6000f4ff"
    # When: we scan bytecode rules.
    flags = analyze_bytecode(bytecode)
    ids = {flag.id for flag in flags}

    # Then: both opcode-based flags should be present.
    assert "bytecode:opcode:delegatecall" in ids
    assert "bytecode:opcode:selfdestruct" in ids


def test_analyze_source_detects_missing_only_owner() -> None:
    # Given: contract refers to ownership but does not use onlyOwner.
    source = """
    contract Vault is Ownable {
        address public owner;

        function setOwner(address next) external {
            owner = next;
        }
    }
    """
    heuristic_findings = check_missing_modifiers(source)
    ids = {flag.id for flag in heuristic_findings}

    assert "heuristic:missing-onlyowner" in ids
