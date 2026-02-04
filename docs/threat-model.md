# Threat Model

This document describes the security vulnerabilities and attack vectors that DeFi Risk Analyzer is designed to detect.

## Detection Categories

### 1. Reentrancy Vulnerabilities

**Risk Level**: High to Critical

Reentrancy occurs when a contract makes an external call before updating its state, allowing the callee to re-enter the function and drain funds.

| Detection Method | Pattern |
|------------------|---------|
| Static Analysis | `call.value`, `.call{value:}` patterns |
| Heuristic Check | Missing `nonReentrant` modifier on external functions |
| LLM Analysis | State changes after external calls |

**Historical Example**: The DAO hack (2016) - $60M lost due to recursive withdrawals.

---

### 2. Dangerous Delegate Calls

**Risk Level**: High

`delegatecall` executes code in the context of the calling contract, preserving `msg.sender` and `msg.value`. Malicious use can lead to storage corruption or unauthorized access.

| Detection Method | Pattern |
|------------------|---------|
| Static Analysis | `delegatecall` keyword |
| Bytecode Scan | `0xF4` opcode (DELEGATECALL) |

**Legitimate Use**: Proxy patterns (EIP-1967) use delegatecall intentionally. Context matters.

---

### 3. Self-Destruct Risk

**Risk Level**: High

`selfdestruct` permanently removes contract code and sends remaining ETH to a specified address. Can be exploited if access control is missing.

| Detection Method | Pattern |
|------------------|---------|
| Static Analysis | `selfdestruct` keyword |
| Bytecode Scan | `0xFF` opcode (SELFDESTRUCT) |

**Note**: Deprecated in Solidity but still functional on mainnet.

---

### 4. Unsafe Authentication

**Risk Level**: Medium

Using `tx.origin` for authorization is dangerous because it returns the original external account, not the immediate caller. This enables phishing attacks.

| Detection Method | Pattern |
|------------------|---------|
| Static Analysis | `tx.origin` keyword |

**Attack Vector**: Attacker deploys malicious contract that calls victim's contract while `tx.origin` is the victim's address.

---

### 5. Missing Access Control

**Risk Level**: Medium

Functions that modify critical state should be protected by access control modifiers.

| Detection Method | Pattern |
|------------------|---------|
| Heuristic Check | Owner patterns without `onlyOwner` modifier |
| LLM Analysis | Privileged functions without access control |

---

### 6. Upgradeable Contract Risks

**Risk Level**: Medium

Upgradeable contracts can have their logic changed post-deployment, which is a centralization risk.

| Detection Method | Pattern |
|------------------|---------|
| Static Analysis | `upgradeable` keyword, proxy patterns |

**Trade-off**: Upgradeability enables bug fixes but requires trust in admin keys.

---

## Severity Scoring

The analyzer computes a security score (0-100) using weighted deductions:

| Severity | Point Deduction | Examples |
|----------|-----------------|----------|
| Critical | 25 | Active exploit pattern |
| High | 10 | delegatecall, selfdestruct, reentrancy |
| Medium | 5 | tx.origin, missing modifiers |
| Low | 1 | Informational findings |

**Formula**: `Score = max(0, 100 - Σ(severity_points))`

---

## Limitations

This tool provides automated detection but is **not a replacement for manual audit**:

- **False Positives**: Some patterns (e.g., delegatecall in proxies) are intentional
- **False Negatives**: Novel attack vectors may not be detected
- **Context Blindness**: Static analysis cannot understand business logic
- **Incomplete Coverage**: Multi-contract interactions not fully analyzed

Always combine automated tools with expert review for production contracts.

---

## References

- [SWC Registry](https://swcregistry.io/) - Smart Contract Weakness Classification
- [Consensys Known Attacks](https://consensys.github.io/smart-contract-best-practices/attacks/)
- [Rekt News](https://rekt.news/) - DeFi exploit database
