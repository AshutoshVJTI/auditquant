# DeFi contract category classifier using weighted regex patterns.
# Pattern weights: 3.0 = EIP-mandated identifiers, 2.0 = protocol-specific,
# 1.0 = general semantic keywords. See docs/design_decisions.md for rationale.

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any


class DeFiCategory(str, Enum):
    AMM_DEX         = "amm_dex"
    LENDING         = "lending"
    VAULT_YIELD     = "vault_yield"
    STAKING_REWARDS = "staking_rewards"
    TOKEN           = "token"
    OTHER           = "other"


CATEGORY_PATTERNS: dict[DeFiCategory, list[tuple[str, float]]] = {


    DeFiCategory.AMM_DEX: [
        # EIP interface
        (r"\bgetReserves\b",               3.0),
        (r"\btoken0\b",                    3.0),
        (r"\btoken1\b",                    3.0),
        (r"\breserve0\b",                  3.0),
        (r"\breserve1\b",                  3.0),
        (r"\bkLast\b",                     3.0),
        (r"\bMINIMUM_LIQUIDITY\b",         3.0),
        (r"\bprice0CumulativeLast\b",      3.0),
        (r"\bprice1CumulativeLast\b",      3.0),
        (r"\bswapExactTokensForTokens\b",  3.0),
        (r"\bswapTokensForExactTokens\b",  3.0),
        (r"\baddLiquidity\b",              3.0),
        (r"\bremoveLiquidity\b",           3.0),
        (r"\bgetAmountsOut\b",             3.0),
        # protocol names
        (r"\bUniswapV[23]\b",              2.0),
        (r"\bUniswap\b",                   2.0),
        (r"\bSushiSwap\b",                 2.0),
        (r"\bPancakeSwap\b",               2.0),
        (r"\bCurvePool\b",                 2.0),
        (r"\bCurve\b",                     2.0),
        (r"\bBalancerVault\b",             2.0),
        (r"\bBalancer\b",                  2.0),
        (r"\bsyncReserves\b",              2.0),
        # keywords
        (r"\bswap\b",                      1.0),
        (r"\bliquidity\b",                 1.0),
        (r"\breserve[s]?\b",               1.0),
        (r"\bpair\b",                      1.0),
        (r"\bpool\b",                      1.0),
        (r"\bAMM\b",                       1.0),
        (r"\bDEX\b",                       1.0),
    ],


    DeFiCategory.LENDING: [
        # EIP interface
        (r"\bliquidateBorrow\b",           3.0),
        (r"\brepayBorrow\b",               3.0),
        (r"\bredeemUnderlying\b",          3.0),
        (r"\bexchangeRateStored\b",        3.0),
        (r"\bborrowRatePerBlock\b",        3.0),
        (r"\bsupplyRatePerBlock\b",        3.0),
        (r"\bcomptroller\b",               3.0),
        (r"\bliquidationCall\b",           3.0),
        (r"\bgetUserAccountData\b",        3.0),
        (r"\bhealthFactor\b",              3.0),
        (r"\bliquidationThreshold\b",      3.0),
        (r"\bloanToValue\b",               3.0),
        # protocol names
        (r"\bcToken\b",                    2.0),
        (r"\baToken\b",                    2.0),
        (r"\bdebtToken\b",                 2.0),
        (r"\bAave\b",                      2.0),
        (r"\bCompound\b",                  2.0),
        (r"\bMakerDAO\b",                  2.0),
        (r"\bMaker\b",                     2.0),
        (r"\bCREAM\b",                     2.0),
        (r"\bliquidationBonus\b",          2.0),
        (r"\binterestRateModel\b",         2.0),
        # keywords
        (r"\bborrow\b",                    1.0),
        (r"\blend\b",                      1.0),
        (r"\brepay\b",                     1.0),
        (r"\bliquidat\w*\b",               1.0),
        (r"\bcollateral\b",                1.0),
        (r"\bdebt\b",                      1.0),
        (r"\boracle\b",                    1.0),
        (r"\bpriceFeed\b",                 1.0),
    ],


    DeFiCategory.VAULT_YIELD: [
        # EIP-4626 interface
        (r"\btotalAssets\b",               3.0),
        (r"\bconvertToShares\b",           3.0),
        (r"\bconvertToAssets\b",           3.0),
        (r"\bpreviewDeposit\b",            3.0),
        (r"\bpreviewMint\b",               3.0),
        (r"\bpreviewWithdraw\b",           3.0),
        (r"\bpreviewRedeem\b",             3.0),
        (r"\bmaxDeposit\b",                3.0),
        (r"\bmaxMint\b",                   3.0),
        (r"\bmaxWithdraw\b",               3.0),
        (r"\bmaxRedeem\b",                 3.0),
        (r"\bERC4626\b",                   3.0),
        # Yearn v2 canonical names (weight 3.0)
        (r"\bpricePerShare\b",             3.0),
        (r"\btotalDebt\b",                 3.0),
        # protocol names
        (r"\bYearn\b",                     2.0),
        (r"\bConvex\b",                    2.0),
        (r"\bHarvest\b",                   2.0),
        (r"\bstrategy\b",                  2.0),
        (r"\bharvest\b",                   2.0),
        (r"\bearn\b",                      2.0),
        (r"\bautocompound\b",              2.0),
        (r"\bpricePerFullShare\b",         2.0),
        # keywords
        (r"\bvault\b",                     1.0),
        (r"\bdeposit\b",                   1.0),
        (r"\bwithdraw\b",                  1.0),
        (r"\byield\b",                     1.0),
        (r"\bshares?\b",                   1.0),
    ],


    DeFiCategory.STAKING_REWARDS: [
        # Synthetix StakingRewards canonical state variables (weight 3.0)
        (r"\brewardPerTokenStored\b",      3.0),
        (r"\buserRewardPerTokenPaid\b",    3.0),
        (r"\bnotifyRewardAmount\b",        3.0),
        (r"\brewardsDuration\b",           3.0),
        (r"\bperiodFinish\b",              3.0),
        (r"\brewardRate\b",                3.0),
        # MasterChef canonical names (weight 3.0)
        (r"\bpendingSushi\b",              3.0),
        (r"\baccSushiPerShare\b",          3.0),
        (r"\bmassUpdatePools\b",           3.0),
        (r"\bupdatePool\b",                3.0),
        # protocol names
        (r"\bMasterChef\b",                2.0),
        (r"\bSynthetix\b",                 2.0),
        (r"\ballocPoint\b",                2.0),
        (r"\buserInfo\b",                  2.0),
        (r"\bpoolInfo\b",                  2.0),
        (r"\brewardPerToken\b",            2.0),
        (r"\bearned\(",                    2.0),
        (r"\bpendingReward\b",             2.0),
        # keywords
        (r"\bstake\b",                     1.0),
        (r"\bunstake\b",                   1.0),
        (r"\breward[s]?\b",                1.0),
        (r"\bgetReward\b",                 1.0),
        (r"\bemission\b",                  1.0),
        (r"\bfarm\b",                      1.0),
    ],

    DeFiCategory.TOKEN: [
        # ERC-20 internal hooks  -  OpenZeppelin ERC20 v4+ (weight 3.0)
        (r"\b_beforeTokenTransfer\b",      3.0),
        (r"\b_afterTokenTransfer\b",       3.0),
        # ERC-721 standard functions  -  EIP-721 (weight 3.0)
        (r"\bownerOf\b",                   3.0),
        (r"\bsafeTransferFrom\b",          3.0),
        (r"\btokenURI\b",                  3.0),
        (r"\bisApprovedForAll\b",          3.0),
        # ERC-2612 permit extension (weight 3.0)
        (r"\bDOMAIN_SEPARATOR\b",          3.0),
        (r"\bnonces\b",                    3.0),
        # EIP-5805
        (r"\bnumCheckpoints\b",            3.0),
        (r"\bgetPriorVotes\b",             3.0),
        (r"\bdelegateBySig\b",             3.0),
        # OpenZeppelin contract identifiers (weight 2.0)
        (r"\bERC20\b",                     2.0),
        (r"\bERC721\b",                    2.0),
        (r"\bERC1155\b",                   2.0),
        (r"\bMintable\b",                  2.0),
        (r"\bBurnable\b",                  2.0),
        (r"\bPausable\b",                  2.0),
        (r"\bAccessControl\b",             2.0),
        (r"\bOwnable\b",                   2.0),
        # Governance / delegation (EIP-5805) (weight 2.0)
        (r"\bdelegate\b",                  2.0),
        (r"\bcheckpoint\b",                2.0),
        (r"\bvotes\b",                     2.0),
    ],
}


# Estimated loss percentages by (DeFi category, vulnerability type).
CATEGORY_LOSS_IMPACT: dict[tuple[DeFiCategory, str], float] = {
    # AMM/DEX
    (DeFiCategory.AMM_DEX, "reentrancy"):              100.0,
    (DeFiCategory.AMM_DEX, "access-control"):          100.0,
    (DeFiCategory.AMM_DEX, "oracle"):                   90.0,
    (DeFiCategory.AMM_DEX, "integer-overflow"):         40.0,
    (DeFiCategory.AMM_DEX, "front-running"):            10.0,

    # Lending
    (DeFiCategory.LENDING, "reentrancy"):              100.0,
    (DeFiCategory.LENDING, "oracle"):                   90.0,
    (DeFiCategory.LENDING, "access-control"):          100.0,
    (DeFiCategory.LENDING, "integer-overflow"):         60.0,
    (DeFiCategory.LENDING, "liquidation"):              70.0,

    # Vault / Yield
    (DeFiCategory.VAULT_YIELD, "reentrancy"):          100.0,
    (DeFiCategory.VAULT_YIELD, "share-manipulation"):  100.0,
    (DeFiCategory.VAULT_YIELD, "access-control"):      100.0,
    (DeFiCategory.VAULT_YIELD, "integer-overflow"):     50.0,
    (DeFiCategory.VAULT_YIELD, "oracle"):               70.0,

    # Staking / Rewards
    (DeFiCategory.STAKING_REWARDS, "reentrancy"):       80.0,
    (DeFiCategory.STAKING_REWARDS, "reward-inflation"): 60.0,
    (DeFiCategory.STAKING_REWARDS, "access-control"):  100.0,
    (DeFiCategory.STAKING_REWARDS, "integer-overflow"): 30.0,
}


@dataclass
class ClassificationResult:
    primary_category: DeFiCategory
    confidence: float
    all_scores: dict[DeFiCategory, float]
    detected_patterns: list[str]

    def get_loss_impact(self, vulnerability_type: str) -> float | None:
        vuln_key = vulnerability_type.lower().replace("_", "-")

        key = (self.primary_category, vuln_key)
        if key in CATEGORY_LOSS_IMPACT:
            return CATEGORY_LOSS_IMPACT[key]

        for (cat, vuln), loss in CATEGORY_LOSS_IMPACT.items():
            if cat == self.primary_category and vuln in vuln_key:
                return loss

        # cross-category defaults for common vulnerability types
        cross_category_defaults = {
            "reentrancy":      100.0,
            "access-control":  100.0,
            "integer-overflow": 50.0,
            "unchecked-return": 30.0,
            "oracle":           70.0,
        }
        for pattern, loss in cross_category_defaults.items():
            if pattern in vuln_key:
                return loss

        return None


def classify_contract(source_code: str) -> ClassificationResult:
    scores: dict[DeFiCategory, float] = {cat: 0.0 for cat in DeFiCategory}
    detected_patterns: list[str] = []

    for category, weighted_patterns in CATEGORY_PATTERNS.items():
        for pattern, weight in weighted_patterns:
            matches = re.findall(pattern, source_code, re.IGNORECASE)
            if matches:
                scores[category] += len(matches) * weight
                detected_patterns.extend(matches[:2])

    # Don't count OTHER in normalization  -  it has no patterns and would dilute
    scorable = {c: s for c, s in scores.items() if c != DeFiCategory.OTHER}
    total_score = sum(scorable.values())
    normalized: dict[DeFiCategory, float] = {cat: 0.0 for cat in DeFiCategory}
    if total_score > 0:
        for cat in scorable:
            normalized[cat] = scorable[cat] / total_score

    primary = max(scorable, key=lambda c: normalized[c]) if scorable else DeFiCategory.OTHER
    confidence = normalized[primary]

    # Require at least 15% share of total signal to accept a category.
    # Below that threshold the contract has no dominant DeFi pattern.
    if confidence < 0.15:
        primary = DeFiCategory.OTHER
        confidence = 1.0

    return ClassificationResult(
        primary_category=primary,
        confidence=confidence,
        all_scores=normalized,
        detected_patterns=list(set(detected_patterns))[:10],
    )


def get_business_context(classification: ClassificationResult) -> dict[str, Any]:
    context_templates = {
        DeFiCategory.AMM_DEX: {
            "description": "Automated Market Maker / Decentralized Exchange",
            "assets_at_risk": "Liquidity pool reserves, user swap funds",
            "attack_vectors": ["Reserve manipulation", "Flash-loan oracle attack", "Sandwich attacks"],
            "critical_functions": ["swap", "addLiquidity", "removeLiquidity", "getReserves"],
        },
        DeFiCategory.LENDING: {
            "description": "Lending / Borrowing Protocol",
            "assets_at_risk": "Deposited collateral, borrowed assets, protocol reserves",
            "attack_vectors": ["Oracle price manipulation", "Liquidation bypass", "Bad debt accumulation"],
            "critical_functions": ["borrow", "repay", "liquidateBorrow", "liquidationCall"],
        },
        DeFiCategory.VAULT_YIELD: {
            "description": "Vault / Yield Aggregator",
            "assets_at_risk": "Deposited user funds, accrued yield, strategy capital",
            "attack_vectors": ["ERC-4626 share inflation", "Reentrancy on withdraw", "Strategy oracle exploit"],
            "critical_functions": ["deposit", "withdraw", "harvest", "convertToShares"],
        },
        DeFiCategory.STAKING_REWARDS: {
            "description": "Staking / Rewards Distribution",
            "assets_at_risk": "Staked tokens, reward pool",
            "attack_vectors": ["Reward inflation via notifyRewardAmount", "Reentrancy on claim", "Unauthorized stake/unstake"],
            "critical_functions": ["stake", "withdraw", "getReward", "notifyRewardAmount"],
        },
        DeFiCategory.TOKEN: {
            "description": "Token Contract (ERC-20 / ERC-721 / ERC-1155)",
            "assets_at_risk": "Token supply, holder balances",
            "attack_vectors": ["Unauthorized mint/burn", "Permit front-running (EIP-2612)", "Governance manipulation"],
            "critical_functions": ["transfer", "transferFrom", "approve", "permit"],
        },
        DeFiCategory.OTHER: {
            "description": "Generic Smart Contract",
            "assets_at_risk": "Contract-held funds",
            "attack_vectors": ["Reentrancy", "Access control bypass"],
            "critical_functions": [],
        },
    }

    template = context_templates.get(
        classification.primary_category, context_templates[DeFiCategory.OTHER]
    )

    return {
        "category": classification.primary_category.value,
        "confidence": classification.confidence,
        **template,
        "detected_patterns": classification.detected_patterns,
    }
