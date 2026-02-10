"""
DeFi Contract Classifier

Classifies contracts into DeFi application categories to enable
business-context-aware risk assessment.

Categories:
- AMM/DEX: Reserve manipulation, reentrancy, oracle misuse
- Lending: Liquidation bypass, bad debt, oracle attacks
- Vault/Yield: Share price manipulation, reentrancy
- Staking/Rewards: Reward inflation, access control drains
- Other: Generic contracts
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any


class DeFiCategory(str, Enum):
    AMM_DEX = "amm_dex"
    LENDING = "lending"
    VAULT_YIELD = "vault_yield"
    STAKING_REWARDS = "staking_rewards"
    OTHER = "other"


# Keywords and patterns for each category
CATEGORY_PATTERNS: dict[DeFiCategory, list[str]] = {
    DeFiCategory.AMM_DEX: [
        r"\bswap\b", r"\bpair\b", r"\bliquidity\b", r"\breserve[s]?\b",
        r"\bgetReserves\b", r"\baddLiquidity\b", r"\bremoveLiquidity\b",
        r"\bUniswap\b", r"\bSushiSwap\b", r"\bCurve\b", r"\bBalancer\b",
        r"\bAMM\b", r"\bDEX\b", r"\bpool\b", r"\btoken[0-1]\b",
        r"\bsyncReserves\b", r"\bmint\s*\(\s*address\b",
    ],
    DeFiCategory.LENDING: [
        r"\bborrow\b", r"\blend\b", r"\brepay\b", r"\bliquidat\w*\b",
        r"\bcollateral\b", r"\bdebt\b", r"\bhealthFactor\b",
        r"\bAave\b", r"\bCompound\b", r"\bMaker\b",
        r"\bcToken\b", r"\baToken\b", r"\binterestRate\b",
        r"\boracle\b", r"\bpriceFeed\b", r"\bgetPrice\b",
    ],
    DeFiCategory.VAULT_YIELD: [
        r"\bvault\b", r"\bdeposit\b", r"\bwithdraw\b", r"\bshares?\b",
        r"\byield\b", r"\bharvest\b", r"\bstrategy\b",
        r"\bYearn\b", r"\bconvex\b", r"\bautocompound\b",
        r"\bpricePerShare\b", r"\btotalAssets\b", r"\bERC4626\b",
    ],
    DeFiCategory.STAKING_REWARDS: [
        r"\bstake\b", r"\bunstake\b", r"\breward[s]?\b", r"\bclaim\b",
        r"\bemission\b", r"\brewardRate\b", r"\brewardPerToken\b",
        r"\bStaking\b", r"\bMasterChef\b", r"\bfarm\b",
        r"\bpendingReward\b", r"\buserInfo\b", r"\bpoolInfo\b",
    ],
}

# Business impact mapping per category + vulnerability type
CATEGORY_LOSS_IMPACT: dict[tuple[DeFiCategory, str], float] = {
    # AMM/DEX vulnerabilities
    (DeFiCategory.AMM_DEX, "reentrancy"): 100.0,
    (DeFiCategory.AMM_DEX, "access-control"): 100.0,
    (DeFiCategory.AMM_DEX, "oracle"): 80.0,
    (DeFiCategory.AMM_DEX, "integer-overflow"): 50.0,
    (DeFiCategory.AMM_DEX, "front-running"): 30.0,
    
    # Lending vulnerabilities
    (DeFiCategory.LENDING, "reentrancy"): 100.0,
    (DeFiCategory.LENDING, "oracle"): 100.0,  # Oracle attacks can drain lending pools
    (DeFiCategory.LENDING, "access-control"): 100.0,
    (DeFiCategory.LENDING, "integer-overflow"): 70.0,
    (DeFiCategory.LENDING, "liquidation"): 80.0,
    
    # Vault vulnerabilities
    (DeFiCategory.VAULT_YIELD, "reentrancy"): 100.0,
    (DeFiCategory.VAULT_YIELD, "share-manipulation"): 100.0,
    (DeFiCategory.VAULT_YIELD, "access-control"): 100.0,
    (DeFiCategory.VAULT_YIELD, "integer-overflow"): 60.0,
    
    # Staking vulnerabilities
    (DeFiCategory.STAKING_REWARDS, "reentrancy"): 100.0,
    (DeFiCategory.STAKING_REWARDS, "reward-inflation"): 80.0,
    (DeFiCategory.STAKING_REWARDS, "access-control"): 100.0,
    (DeFiCategory.STAKING_REWARDS, "integer-overflow"): 50.0,
}


@dataclass
class ClassificationResult:
    """Result of DeFi contract classification."""
    primary_category: DeFiCategory
    confidence: float
    all_scores: dict[DeFiCategory, float]
    detected_patterns: list[str]
    
    def get_loss_impact(self, vulnerability_type: str) -> float | None:
        """Get expected loss % for a vulnerability type in this category."""
        # Normalize vulnerability type
        vuln_key = vulnerability_type.lower().replace("_", "-")
        
        # Try exact match first
        key = (self.primary_category, vuln_key)
        if key in CATEGORY_LOSS_IMPACT:
            return CATEGORY_LOSS_IMPACT[key]
        
        # Try partial match
        for (cat, vuln), loss in CATEGORY_LOSS_IMPACT.items():
            if cat == self.primary_category and vuln in vuln_key:
                return loss
        
        # Default based on vulnerability type alone
        default_losses = {
            "reentrancy": 100.0,
            "access-control": 100.0,
            "integer-overflow": 50.0,
            "unchecked-return": 30.0,
        }
        for pattern, loss in default_losses.items():
            if pattern in vuln_key:
                return loss
        
        return None


def classify_contract(source_code: str) -> ClassificationResult:
    """
    Classify a smart contract into a DeFi category.
    
    Uses pattern matching on function names, variable names, and imports
    to determine the contract type.
    """
    source_lower = source_code.lower()
    
    scores: dict[DeFiCategory, float] = {cat: 0.0 for cat in DeFiCategory}
    detected_patterns: list[str] = []
    
    for category, patterns in CATEGORY_PATTERNS.items():
        for pattern in patterns:
            matches = re.findall(pattern, source_code, re.IGNORECASE)
            if matches:
                score_add = len(matches) * 2.0
                scores[category] += score_add
                detected_patterns.extend(matches[:3])
    
    # Normalize scores
    total_score = sum(scores.values())
    if total_score > 0:
        for cat in scores:
            scores[cat] /= total_score
    
    # Get primary category
    primary = max(scores, key=lambda c: scores[c])
    confidence = scores[primary]
    
    # If confidence is too low, fall back to OTHER
    if confidence < 0.15:
        primary = DeFiCategory.OTHER
        confidence = 1.0 - sum(s for s in scores.values())
    
    return ClassificationResult(
        primary_category=primary,
        confidence=confidence,
        all_scores=scores,
        detected_patterns=list(set(detected_patterns))[:10],
    )


def get_business_context(
    classification: ClassificationResult,
) -> dict[str, Any]:
    """
    Get business context description for the classified contract.
    
    Used to provide context to the LLM for better risk assessment.
    """
    context_templates = {
        DeFiCategory.AMM_DEX: {
            "description": "Automated Market Maker / Decentralized Exchange",
            "assets_at_risk": "Liquidity pool reserves, user swap funds",
            "attack_vectors": ["Reserve manipulation", "Sandwich attacks", "Oracle manipulation"],
            "critical_functions": ["swap", "addLiquidity", "removeLiquidity"],
        },
        DeFiCategory.LENDING: {
            "description": "Lending/Borrowing Protocol",
            "assets_at_risk": "Deposited collateral, borrowed assets, protocol reserves",
            "attack_vectors": ["Liquidation bypass", "Bad debt accumulation", "Oracle attacks"],
            "critical_functions": ["borrow", "repay", "liquidate", "deposit"],
        },
        DeFiCategory.VAULT_YIELD: {
            "description": "Vault / Yield Aggregator",
            "assets_at_risk": "Deposited user funds, yield earnings",
            "attack_vectors": ["Share price manipulation", "Reentrancy on withdraw", "Strategy exploits"],
            "critical_functions": ["deposit", "withdraw", "harvest"],
        },
        DeFiCategory.STAKING_REWARDS: {
            "description": "Staking / Rewards Distribution",
            "assets_at_risk": "Staked tokens, reward pool",
            "attack_vectors": ["Reward inflation", "Unauthorized claims", "Reentrancy"],
            "critical_functions": ["stake", "unstake", "claim", "getReward"],
        },
        DeFiCategory.OTHER: {
            "description": "Generic Smart Contract",
            "assets_at_risk": "Contract-held funds",
            "attack_vectors": ["Reentrancy", "Access control bypass"],
            "critical_functions": [],
        },
    }
    
    template = context_templates.get(classification.primary_category, context_templates[DeFiCategory.OTHER])
    
    return {
        "category": classification.primary_category.value,
        "confidence": classification.confidence,
        **template,
        "detected_patterns": classification.detected_patterns,
    }
