# Sample Vulnerable Contracts (for testing AuditQuant)

Upload any of these `.sol` files via the AuditQuant Dashboard to test the analysis pipeline (Slither, Mythril, RiskQuant, AI validation, remediation).

| File | Vulnerability | What to expect |
|------|---------------|----------------|
| `VulnerableBank.sol` | Reentrancy (ETH) | State updated after external call; Slither/Mythril flag reentrancy. |
| `VulnerableVault.sol` | Access control | `withdrawAll()` has no access control; anyone can drain. |
| `UncheckedCall.sol` | Unchecked return value | Low-level `call` return value ignored; can fail silently. |
| `SimpleStorage.sol` | Minor / gas | Used for quick “no critical issue” runs; optional naming/gas notes. |

**How to test:** Start the backend and frontend, open the Dashboard, and upload any `.sol` file from this folder. Ensure Docker Slither/Mythril images are built for full analysis.
