# Adding Detection Rules

This guide explains how to extend DeFi Risk Analyzer with new vulnerability detection rules.

## Rule System Overview

The analyzer uses a declarative rule system defined in `src/defi_risk_analyzer/analysis/rules.py`. Each rule specifies:

- **Pattern**: What to look for
- **Match Type**: How to match (word, regex, or substring)
- **Metadata**: Title, description, severity

## Adding a Source Code Rule

Source rules scan verified Solidity code from Etherscan.

### Step 1: Define the Rule

Add to `SOURCE_RULES` in `rules.py`:

```python
Rule(
    id="unchecked-send",           # Unique identifier
    pattern=r"\.send\s*\(",        # Regex pattern
    title="Unchecked send()",
    description="send() returns bool but failure is not checked.",
    severity="medium",
    match_type="regex",            # Options: "word", "regex"
)
```

### Step 2: Test the Rule

Create a test fixture in `tests/fixtures/`:

```solidity
// tests/fixtures/unchecked_send.sol
contract Vulnerable {
    function withdraw() external {
        msg.sender.send(balance);  // Should trigger rule
    }
}
```

Add test case in `tests/test_static_analysis.py`:

```python
def test_unchecked_send_detected():
    source = open("tests/fixtures/unchecked_send.sol").read()
    findings = analyze_source(source)
    assert any(f.id == "source:unchecked-send" for f in findings)
```

## Adding a Bytecode Rule

Bytecode rules scan raw EVM opcodes when source is unavailable.

### Example: Detecting CREATE2

```python
Rule(
    id="opcode:create2",
    pattern="f5",                   # CREATE2 opcode
    title="Possible CREATE2 usage",
    description="Contract may deploy other contracts at deterministic addresses.",
    severity="low",
    match_type="substring",
)
```

Add to `BYTECODE_RULES` in `rules.py`.

## Adding a Heuristic Check

Heuristics detect patterns that require context (e.g., missing modifiers).

### Location

`src/defi_risk_analyzer/analysis/heuristics.py`

### Example: Detecting Missing Pausable

```python
def check_missing_pausable(source_code: str) -> list[RedFlag]:
    """Detect if contract handles funds but lacks pause mechanism."""
    findings = []
    
    has_transfers = re.search(r"\.transfer\(|\.send\(|\.call\{value:", source_code)
    has_pausable = re.search(r"\bwhenNotPaused\b|\bPausable\b", source_code)
    
    if has_transfers and not has_pausable:
        findings.append(RedFlag(
            id="heuristic:missing-pausable",
            title="Missing pause mechanism",
            description="Contract transfers value but has no pause functionality.",
            severity="low",
            evidence="Fund transfers detected without Pausable pattern.",
        ))
    
    return findings
```

### Integrate into Pipeline

Update `cli.py` to include the new check:

```python
findings = (
    analyze_bytecode(bytecode)
    + analyze_source(source_code)
    + check_missing_modifiers(source_code)
    + check_missing_pausable(source_code)  # Add here
)
```

## Best Practices

1. **Start with low severity** - Tune up after validating accuracy
2. **Avoid false positives** - Be specific with patterns
3. **Add context** - Include evidence in findings
4. **Test thoroughly** - Both positive and negative cases
5. **Document intent** - Explain why the pattern is risky

## Rule ID Conventions

| Prefix | Source |
|--------|--------|
| `source:` | Solidity source code patterns |
| `bytecode:` | EVM opcode patterns |
| `heuristic:` | Contextual/logical checks |
| `llm:` | AI-generated findings |
