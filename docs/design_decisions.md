# AuditQuant - Design Decisions & Research Backing

This document explains the reasoning behind specific design choices that aren't obvious from the code. Each section covers what we chose, why, and what research supports it.

---

## 1. Tool Selection: Slither + Slitherin + Semgrep + Mythril

### Why four tools using different techniques

| Tool | Technique | Specialty |
|------|-----------|-----------|
| Slither | Static / AST analysis | Fast, broad coverage; high recall, higher FP rate |
| Slitherin | Static / pattern (DeFi-specific) | DeFi detectors not in base Slither: readonly-reentrancy, ERC4626 inflation, permit DoS |
| Semgrep | Pattern matching (explicit rules) | Low-FP rules from Trail of Bits + p/solidity ruleset; different FP profile from Slither |
| Mythril | Symbolic execution | Proves exploitability with concrete transaction sequences; generates exploit traces |

Using tools with **fundamentally different underlying methods** is the ensemble principle applied to security analysis. If two tools with independent false-positive profiles both flag the same location for the same reason, the probability of both being wrong simultaneously is much lower than either being wrong alone.

**Reference:** Durieux, Ferreira, Abreu & Cruz, "Empirical Review of Automated Analysis Tools on 47,587 Ethereum Smart Contracts," ICSE 2020. Table 4 shows that tool intersection significantly improves precision over any single tool.

**Reference:** Schapire, "The Strength of Weak Learnability," Machine Learning 1990 - foundational ensemble learning result: independent weak classifiers combined outperform any individual.

### Why Slitherin in addition to Slither

Slither's base detector set covers general Solidity patterns. Slitherin extends it with DeFi-specific detectors (readonly-reentrancy, ERC4626 inflation attack, price oracle manipulation, permit DoS) that do not exist in the Slither base. For DeFi contracts, these are high-severity vulnerability classes absent from any other tool in the pipeline.

### Why Semgrep in addition to Slither

Slither performs semantic analysis on the AST; Semgrep matches explicit rule patterns. These two approaches produce different false-positive profiles. A finding flagged by both is a higher-confidence signal than one flagged by either alone. Semgrep's Trail of Bits ruleset is hand-curated with explicit HIGH/MEDIUM/LOW confidence annotations.

**Reference:** Semgrep rule-writing documentation (semgrep.dev/docs/writing-rules) - confidence field semantics mirror Slither's tier definitions.

### Why Oyente Was Removed

Oyente only supports Solidity ≤ 0.4.x. Every modern DeFi contract uses 0.6.x–0.8.x. On our benchmark of 100 real contracts: **0 findings, precision = 0.0, recall = 0.0.** It was consuming Docker startup time with zero contribution.

---

## 2. Confidence Score Calibration System

### Overview

Every confidence value in the system - initial per-finding confidence, tier multipliers, and cross-validation boosts - comes from a calibration pipeline:

```
ablation_study.json  →  confidence_calibration.json  →  confidence_loader.py  →  adapters + orchestrator
```

No confidence value is hardcoded in adapter or orchestrator code.

### Tool base confidence: precision as P(TP | retrieved)

Each tool's base confidence is its empirical precision on the benchmark - the fraction of reported findings that are true positives. This is the standard definition of precision in information retrieval.

**Reference:** Manning, Raghavan & Schütze, "Introduction to Information Retrieval," Cambridge UP 2008, §8 - precision P(relevant | retrieved) is the canonical estimator for the correctness of a retrieval system.

### Slither / Slitherin confidence tiers (High / Medium / Low)

Slither assigns each detector a confidence tier reflecting its expected false-positive rate. Feist et al. characterise the tiers as:

- **High** - "almost no false positives"
- **Medium** - "can have some false positives"
- **Low** - "can have a high number of false positives"

Durieux et al. (ICSE 2020) measured per-detector precision across 47k contracts and confirmed that high-confidence detectors have systematically higher precision. We operationalise this as monotone multiplicative scaling anchored at the tool's empirical base precision:

```
High   = min(0.99, base × 2.0)
Medium = base
Low    = max(0.01, base × 0.5)
```

The multipliers 2.0 and 0.5 correspond to the characterisation that High detectors have roughly half the false-positive rate of the tool average and Low detectors have roughly double.

**Reference:** Feist, Grieco & Groce, "Slither: A Static Analysis Framework For Smart Contracts," WETSEB 2019.

**Reference:** Durieux, Ferreira, Abreu & Cruz, "Empirical Review of Automated Analysis Tools on 47,587 Ethereum Smart Contracts," ICSE 2020.

### Semgrep tier confidence (HIGH / MEDIUM / LOW rule metadata)

Semgrep rule authors annotate each rule with a confidence field following the same High/Medium/Low semantics as Slither. We apply the same tier multipliers (2.0 / 1.0 / 0.5) scaled from Semgrep's empirical base precision. When no confidence metadata is present, the base precision is used as the default.

### Mythril reachable vs. non-reachable confidence

When Mythril produces a concrete exploit trace, symbolic execution has proven the vulnerability path is reachable. King (1976) established that a symbolic counterexample constitutes a formal proof of program behaviour.

```
reachable     = min(0.95, base × 1.4)
not_reachable = base
```

The 1.4× uplift is conservative: traced paths have higher precision than the tool average, but implementation limits mean the proof is not always sound in practice.

**Reference:** King, "Symbolic Execution and Program Testing," CACM 1976.

**Reference:** Cadar & Sen, "Symbolic Execution for Software Testing: Three Decades Later," CACM 2013.

**Reference:** Mueller, "Smashing Ethereum Smart Contracts for Fun and Real Profit," HITB 2018.

---

## 3. Cross-Validation: 4-Tool Weighted Confidence Boosts

### Tiers

| Tier | Condition | Effect |
|------|-----------|--------|
| HIGH_CONFIDENCE | Same vulnerability type AND same location, reported by 2+ tools | Confidence boosted by `BOOST_HIGH` |
| MEDIUM_CONFIDENCE | Same location, reported by 2+ tools, different vulnerability types | Confidence boosted by `BOOST_MEDIUM` |
| LONE_SIGNAL | Reported by exactly one tool | No boost; confidence unchanged |

### Boost values (data-derived)

Boost values are computed from `evaluation/results/ablation_study.json`, comparing the union (unfiltered) pipeline stage against the cross-validated stage:

```
cv_prec   = tp_cv / (tp_cv + fp_cv)            # P(TP | passes cross-validation)
lone_prec = (tp_union − tp_cv) / (total_union − total_cv)  # P(TP | filtered out)
BOOST_HIGH   = cv_prec − lone_prec
BOOST_MEDIUM = ((cv_prec + lone_prec) / 2) − lone_prec
```

Current calibrated values: **BOOST_HIGH = 0.2593**, **BOOST_MEDIUM = 0.1297**

The medium tier uses the midpoint precision because same-location agreement with different types is weaker corroboration than same-type agreement - the tools disagree on what the vulnerability is, only that something at that location is suspicious.

Boost values are stored in `backend/app/services/data/confidence_calibration.json`.

**Reference:** Durieux et al., ICSE 2020, Table 4 - tool intersection improves precision over any single tool.

### Weighted boost scaling with 4 tools

A flat boost would treat 2/4 tool agreement the same as 4/4 agreement. Instead, the boost is scaled by the fraction of precision weight that agrees:

```
boost = max_boost × (Σ precision(agreeing tools)) / (Σ precision(all tools that ran))
```

This means Mythril + Semgrep agreement (both high-precision tools) produces a larger boost than Slither + Slitherin agreement (both lower-precision tools). The precision weights come from the same calibration benchmark.

---

## 4. LLM Role: Report Writer + Claim Filter, Not Detector

### What the LLM does

The LLM (GPT-4o-mini) receives the cross-validated findings from the tools, then:
1. Generates a human-readable structured audit report
2. Makes claims about each finding (exploitability, loss %, fix recommendation)

The anti-hallucination verifier checks every claim against actual tool evidence and rejects unsupported ones.

### Does it help? - Ablation Study Results

We ran a before/after comparison on 100 contracts (results in `evaluation/results/ablation_study.json`):

| Metric | LLM OFF | LLM ON | Delta |
|---|---|---|---|
| Precision | 0.336 | 0.415 | **+0.079** |
| Recall | 0.850 | 0.709 | -0.141 |
| F1 | 0.481 | 0.524 | **+0.042** |
| False Positives | 101 | 55 | **-46** |
| True Positives | 51 | 39 | -12 |

The LLM filter removes 46 false positives but incorrectly removes 12 true positives. Net F1 gain: +4.2%.

**Key finding:** The LLM standalone has precision 0.168 - worse than Mythril alone (0.673). The LLM is not a good detector. It's a good filter when grounded against tool evidence.

### What the LLM should NOT do

- Claim exploitability without a Mythril exploit trace
- Claim loss percentages as ground truth (these are estimates, not measurements)
- Invent vulnerabilities not found by any tool

These are enforced by the anti-hallucination verifier.

**Reference:** Gou et al., "CRITIC: LLMs Can Self-Correct with Tool-Interactive Critiquing," ICLR 2024.

**Reference:** Asai et al., "Self-RAG: Learning to Retrieve, Generate, and Critique," ICLR 2024.

---

## 5. Business Risk Rubric

### Structure

Four dimensions scored 0–5, then weighted by DeFi category:
- **Exploitability** - can an attacker realistically trigger this?
- **Financial Impact** - what fraction of funds could drain?
- **Exposure** - how many users/functions are affected?
- **Evidence Strength** - fraction of tools that agree; dynamic proof present?

This mirrors CVSS v3.1 (NIST/FIRST, 2019) which uses Exploitability + Impact sub-scores. Evidence Strength is our addition, analogous to CVSS Temporal metrics.

### Evidence Strength scoring

Evidence Strength uses the ratio of reporting tools to total tools that ran, rather than an absolute count:

```
ratio = tools_reporting / total_tools_run
score = 3.0 if ratio >= 0.5 else 1.5
```

Using a ratio ensures the score is comparable regardless of how many tools succeeded on a given contract.

### Loss estimation

Loss percentage is estimated from the vulnerability type using empirical data on DeFi exploits (reentrancy → up to 100%, oracle manipulation → up to 90%, etc.). This is merged directly into the business risk rubric - it is an input to Financial Impact scoring, not a separate engine. Loss percentages are estimates, not measurements; the LLM report makes this explicit.

### Why weights differ by DeFi category

Weights are derived from historical DeFi exploit distributions:

**AMM/DEX** (`financial_impact`: 0.40, `exploitability`: 0.25)
Flash-loan + price-oracle manipulation attacks dominate AMM exploits. A single attack can drain the entire liquidity pool. Flash loans require attacker sophistication, so exploitability is slightly lower.
- Source: Zhou et al., "SoK: Decentralized Finance (DeFi) Incidents," IEEE S&P 2023 - AMMs account for 56.9% of all stolen DeFi assets.
- Source: Qin et al., "Attacking the DeFi Ecosystem with Flash Loans for Fun and Profit," Financial Cryptography 2021.

**Lending** (`financial_impact`: 0.40, `exploitability`: 0.30)
Oracle manipulation + reentrancy dominate. Reentrancy is simpler to execute than a flash loan attack, so exploitability gets a higher weight. Full collateral drain is possible.
- Source: Zhou et al. 2023 (second-largest loss category).

**Vault/Yield** (`financial_impact`: 0.35, `exploitability`: 0.30)
Strategy-level exploits typically drain a subset of funds, not the entire pool. Access-control misconfigurations in strategy contracts are common.
- Source: Wüst et al., "SoK: Yield Aggregator Protocols," 2022 - vault exploits are typically partial, not pool-level.

**Staking** (`financial_impact`: 0.25, `exposure`: 0.30)
Reward inflation and withdrawal attacks affect every staker proportionally, giving exposure the highest weight of any category. Absolute loss per exploit is lower because the reward pool is much smaller than the principal pool.
- Source: Zhou et al. 2023 - staking protocols show highest victim count per exploit, lower per-victim loss.

**Evidence weight fixed at 0.15 across all categories** - this is a meta-signal about toolchain confidence, not about the DeFi archetype itself.

---

## 6. Risk Scoring Formulas (R_SAST, R_DAST, R_COMP)

### R_SAST
Sum of `impact_weight × confidence_weight` for all static findings. Impact weights (High=10, Medium=5, Low=2) roughly follow CVSS severity bands. Capped at 100.

### R_DAST
Max severity score among findings where Mythril proved reachability (has exploit trace). If no reachable findings, R_DAST = 0. Taking the max instead of sum because a single proven exploit is a hard blocker regardless of other findings.

### R_COMP
Cyclomatic complexity estimated by counting branch keywords (if, for, while, &&, ||, etc.), then passed through a sigmoid centered at CC=20. Higher complexity = harder to reason about = higher inherent risk. Sigmoid was chosen so the score doesn't blow up for very complex contracts.

CC=20 as the center was chosen based on McCabe's original threshold of 10 per function, assuming ~2 functions on average in the analysis scope.

**Reference:** McCabe, "A Complexity Measure," IEEE Transactions on Software Engineering 1976.

### Composite
- If Mythril found reachable exploits: `0.30 × R_SAST + 0.50 × R_DAST + 0.20 × R_COMP`
- Otherwise: `0.50 × R_SAST + 0.50 × R_COMP`

Dynamic proof (exploit trace) is weighted highest when it exists because it's the strongest possible evidence. When it doesn't exist, static analysis and complexity share the score equally.

---

## 7. DeFi Contract Classification

### Pattern weight tiers

Patterns are assigned one of three weights based on signal strength:

| Weight | Tier | Description |
|--------|------|-------------|
| 3.0 | EIP-defined canonical names | Function/variable names mandated by a finalized EIP or standard interface  -  unambiguous classification signals |
| 2.0 | Protocol identifiers / EIP-derived state variables | Named protocol strings and canonical state variable names from reference implementations |
| 1.0 | Semantic keywords | English words with lower discriminative power; "deposit" and "withdraw" appear across multiple categories |

The score for a category is the sum of `count(matches) × weight` across all its patterns, then normalized to a 0–1 fraction. A contract must score ≥ 15% share to receive a category label; below that it falls into OTHER.

### AMM / DEX patterns

**Weight 3.0 source:** Adams, Zinsmeister, Robinson, Koon & Salem, "Uniswap v2 Core" (2020). The IUniswapV2Pair interface mandates `getReserves`, `token0`, `token1`, `reserve0`, `reserve1`, `kLast`, `MINIMUM_LIQUIDITY`, `price0CumulativeLast`, `price1CumulativeLast`. The IUniswapV2Router02 interface mandates `swapExactTokensForTokens`, `swapTokensForExactTokens`, `addLiquidity`, `removeLiquidity`, `getAmountsOut`.

**Weight 2.0 source:** Protocol names catalogued in Zhou, Qin et al., "SoK: Decentralized Finance (DeFi) Incidents," IEEE S&P 2023, Table 1. AMM/DEX category.

### Lending patterns

**Weight 3.0 source:** Leshner & Hayes, "Compound: The Money Market Protocol" (2019). CToken interface: `liquidateBorrow`, `repayBorrow`, `redeemUnderlying`, `exchangeRateStored`, `borrowRatePerBlock`, `supplyRatePerBlock`, `comptroller`.
Aave, "Aave Protocol Whitepaper v1.0" (2020). LendingPool interface: `liquidationCall`, `getUserAccountData`, and `healthFactor`, `liquidationThreshold`, `loanToValue` (return fields of getUserAccountData).

**Weight 2.0 source:** Protocol names from Zhou et al. S&P 2023 Table 1. Lending/borrowing category.

### Vault / Yield patterns

**Weight 3.0 source:** Santoro, Allen, Kasabian et al., "ERC-4626: Tokenized Vault Standard," Ethereum Improvement Proposal 4626, 2022. Canonical view functions: `totalAssets`, `convertToShares`, `convertToAssets`, `previewDeposit`, `previewMint`, `previewWithdraw`, `previewRedeem`, `maxDeposit`, `maxMint`, `maxWithdraw`, `maxRedeem`. Mutable functions: `deposit`, `mint`, `withdraw`, `redeem`. The `ERC4626` identifier itself.
Yearn Finance v2 vault (github.com/yearn/yearn-vaults): `pricePerShare`, `totalDebt`, `harvest`, `earn`.

**Weight 2.0 source:** Protocol names from Zhou et al. S&P 2023 Table 1. Yield/aggregator category.

### Staking / Rewards patterns

**Weight 3.0 source:** Synthetix Core Contributors, StakingRewards.sol (github.com/Synthetixio/synthetix). The contract that is the canonical staking reference implementation, forked by hundreds of protocols. State variables: `rewardPerTokenStored`, `userRewardPerTokenPaid`, `rewardsDuration`, `periodFinish`, `rewardRate`. Functions: `notifyRewardAmount`, `rewardPerToken`, `earned`.
SushiSwap, MasterChef.sol (github.com/sushiswap/masterchef). State: `accSushiPerShare`. Functions: `pendingSushi`, `massUpdatePools`, `updatePool`.

**Weight 2.0 source:** Protocol names from Zhou et al. S&P 2023 Table 1.

### Token patterns

**Weight 3.0 source:** Buterin & Vogelsteller, Ethereum Improvement Proposal 20, 2015. Internal hooks `_beforeTokenTransfer`, `_afterTokenTransfer` from OpenZeppelin ERC20 v4+.
Entriken, Shirley, Evans & Sachs, Ethereum Improvement Proposal 721, 2018. Functions: `ownerOf`, `safeTransferFrom`, `tokenURI`, `isApprovedForAll`.
Recchia, "ERC-20 Permit Extension," Ethereum Improvement Proposal 2612, 2019. State: `DOMAIN_SEPARATOR`, `nonces`.
Nogueira & Giry, "Voting with delayed delegation," Ethereum Improvement Proposal 5805, 2022. Functions: `numCheckpoints`, `getPriorVotes`, `delegateBySig`.

**Weight 2.0 source:** OpenZeppelin Contracts v4/v5 standard contract identifiers (`ERC20`, `ERC721`, `ERC1155`, `Ownable`, `AccessControl`, etc.).

### Loss percentage estimates

Source: Zhou, Qin et al., "SoK: Decentralized Finance (DeFi) Incidents," IEEE S&P 2023. The paper analyzes 181 real-world incidents with $3.24B in total losses. Loss percentages in `CATEGORY_LOSS_IMPACT` represent the observed fraction of protocol TVL drained in representative incidents for each (category, attack-vector) pairing, supplemented by:
- Qin, Zhou et al., "Attacking the DeFi Ecosystem with Flash Loans for Fun and Profit," Financial Cryptography 2021  -  for AMM flash-loan oracle attacks (90% pool drain)
- Wüst et al., "SoK: Yield Aggregator Protocols" (2022)  -  for vault share-price calculation errors (50% partial loss)
- MEV front-running impact measured as slippage extraction only, not pool drain (10%)

---

## 8. Benchmark & Evaluation

**Dataset:** SmartBugs Curated + real DeFi contracts (n=100 for benchmark runs)

**Ground truth:** Known vulnerability labels from the SmartBugs dataset + manual annotations in `evaluation/labels/dataset_manifest.json`

**Statistical significance:** Bootstrap confidence intervals (10,000 resamples) and McNemar's test on paired contract outcomes.

**Key benchmark result (all 4 tools):**

| System | Precision | Recall | F1 |
|---|---|---|---|
| Slitherin only | - | - | - |
| Slither only | 0.160 | 0.291 | 0.207 |
| Semgrep only | - | - | - |
| Mythril only | 0.673 | 0.636 | 0.654 |
| Union (no filter) | 0.331 | 0.836 | 0.474 |
| Cross-validated (no LLM) | 0.415 | 0.709 | 0.524 |
| Full AuditQuant (+ LLM) | 0.415 | 0.709 | 0.524 |

Semgrep and Slitherin standalone metrics are tracked separately in `evaluation/results/semgrep_standalone_metrics.json` and `evaluation/results/slitherin_standalone_metrics.json`.

**Reference:** SmartBugs dataset - Ferreira et al., "SmartBugs: A Framework to Analyze Solidity Smart Contracts," ASE 2020.
