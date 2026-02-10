"""
Business Risk Rubric

Manual-style rubric for business-aware risk scoring of smart contract
vulnerabilities, particularly in DeFi applications.

The rubric has four dimensions, each scored 0-5:
  1. Exploitability     — how easy is it to exploit?
  2. Financial Impact   — how much value can be lost?
  3. Exposure           — how exposed is this DeFi category?
  4. Evidence Strength  — how strong is the cross-tool consensus?

The four sub-scores are aggregated into a single 0-100 Business Risk Score.

This deterministic rubric is then compared against the LLM loss-bucket
predictions (10%, 50%, 100%) so we can measure consensus and flag
disagreements.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Rubric score dataclass
# ---------------------------------------------------------------------------

@dataclass
class RubricScores:
    """Individual dimension scores (0-5 each) and the derived 0-100 score."""
    exploitability: float = 0.0
    financial_impact: float = 0.0
    exposure: float = 0.0
    evidence_strength: float = 0.0

    @property
    def business_risk_score(self) -> float:
        """
        Weighted aggregation to 0-100 scale.

        Weights reflect audit practice:
          - Financial Impact  35%  (most important for DeFi)
          - Exploitability    30%
          - Exposure          20%
          - Evidence Strength 15%

        Each dimension is first normalised to 0-1 (divide by 5), then the
        weighted sum is scaled to 0-100.
        """
        weights = {
            "exploitability": 0.30,
            "financial_impact": 0.35,
            "exposure": 0.20,
            "evidence_strength": 0.15,
        }
        raw = (
            (self.exploitability / 5.0) * weights["exploitability"]
            + (self.financial_impact / 5.0) * weights["financial_impact"]
            + (self.exposure / 5.0) * weights["exposure"]
            + (self.evidence_strength / 5.0) * weights["evidence_strength"]
        )
        return round(min(100.0, max(0.0, raw * 100.0)), 2)

    def to_dict(self) -> dict[str, Any]:
        return {
            "exploitability": self.exploitability,
            "financial_impact": self.financial_impact,
            "exposure": self.exposure,
            "evidence_strength": self.evidence_strength,
            "business_risk_score": self.business_risk_score,
        }


# ---------------------------------------------------------------------------
# LLM loss-bucket comparison
# ---------------------------------------------------------------------------

class LossAgreement(str, Enum):
    """Degree of consensus between rubric and LLM prediction."""
    STRONG = "strong"        # Both agree on severity band
    MODERATE = "moderate"    # Within one band
    WEAK = "weak"            # Two bands apart
    DISAGREE = "disagree"    # Completely different


class LossBucket(str, Enum):
    """
    Discrete loss-bucket categories used in the research proposal.

    These map continuous loss percentages into the three canonical buckets
    referenced in the paper (10 %, 50 %, 100 %) plus a "negligible" tier.
    """
    NEGLIGIBLE = "negligible"   # ≤ 5 % — informational / low-risk
    LOW_10 = "~10%"             # 6-25 % — limited fund loss
    MEDIUM_50 = "~50%"          # 26-74 % — significant fund loss
    HIGH_100 = "~100%"          # 75-100 % — total fund loss / protocol drain


def classify_loss_bucket(loss_percentage: float | None) -> LossBucket:
    """
    Map a continuous loss percentage (0-100) to a discrete loss bucket.

    | Loss %   | Bucket        | Interpretation                |
    |----------|---------------|-------------------------------|
    | 0-5      | NEGLIGIBLE    | Informational                 |
    | 6-25     | ~10 %         | Limited, recoverable loss     |
    | 26-74    | ~50 %         | Significant partial loss      |
    | 75-100   | ~100 %        | Total / near-total drain      |
    """
    if loss_percentage is None or loss_percentage <= 5:
        return LossBucket.NEGLIGIBLE
    if loss_percentage <= 25:
        return LossBucket.LOW_10
    if loss_percentage <= 74:
        return LossBucket.MEDIUM_50
    return LossBucket.HIGH_100


def _bucket_order(bucket: LossBucket) -> int:
    """Numeric rank for bucket distance calculations."""
    return {
        LossBucket.NEGLIGIBLE: 0,
        LossBucket.LOW_10: 1,
        LossBucket.MEDIUM_50: 2,
        LossBucket.HIGH_100: 3,
    }.get(bucket, 0)


@dataclass
class RubricLLMComparison:
    """Side-by-side comparison of the rubric score and the LLM loss prediction."""
    vulnerability_type: str
    rubric_scores: RubricScores
    rubric_risk_score: float
    llm_loss_percentage: float | None
    rubric_severity_band: str
    llm_severity_band: str
    agreement: LossAgreement
    notes: str = ""
    # Discrete loss buckets (RQ3 — 10 %/50 %/100 % classification)
    rubric_loss_bucket: str = ""
    llm_loss_bucket: str = ""
    bucket_agreement: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "vulnerability_type": self.vulnerability_type,
            "rubric": self.rubric_scores.to_dict(),
            "rubric_risk_score": self.rubric_risk_score,
            "llm_loss_percentage": self.llm_loss_percentage,
            "rubric_severity_band": self.rubric_severity_band,
            "llm_severity_band": self.llm_severity_band,
            "agreement": self.agreement.value,
            "notes": self.notes,
            "rubric_loss_bucket": self.rubric_loss_bucket,
            "llm_loss_bucket": self.llm_loss_bucket,
            "bucket_agreement": self.bucket_agreement,
        }


# ---------------------------------------------------------------------------
# 1. Exploitability  (0-5)
# ---------------------------------------------------------------------------

# Maps normalised vulnerability types to a base exploitability rating.
_EXPLOITABILITY_BASE: dict[str, float] = {
    "reentrancy": 5.0,
    "access-control": 5.0,
    "integer-overflow": 3.0,
    "unchecked-return": 2.5,
    "front-running": 3.0,
    "timestamp-dependency": 2.0,
    "denial-of-service": 2.0,
    "oracle": 4.0,
    "share-manipulation": 4.0,
    "reward-inflation": 3.5,
    "liquidation": 4.0,
}


def score_exploitability(
    vulnerability_type: str,
    has_exploit_proof: bool = False,
    is_reachable: bool = False,
) -> float:
    """
    Rate exploitability 0-5.

    Base score from the vulnerability type, then boosted if dynamic tools
    prove reachability or provide an exploit trace.
    """
    key = vulnerability_type.lower().replace("_", "-")
    base = _EXPLOITABILITY_BASE.get(key, 2.0)

    if has_exploit_proof:
        base = min(5.0, base + 1.0)
    elif is_reachable:
        base = min(5.0, base + 0.5)

    return round(base, 1)


# ---------------------------------------------------------------------------
# 2. Financial Impact  (0-5)
# ---------------------------------------------------------------------------

# Loss percentage thresholds mapped to 0-5 rating.
def score_financial_impact(loss_percentage: float | None) -> float:
    """
    Convert an estimated loss percentage (0-100) to a 0-5 impact score.

    | Loss %     | Score |
    |------------|-------|
    | 80-100     | 5     |
    | 60-79      | 4     |
    | 40-59      | 3     |
    | 20-39      | 2     |
    | 1-19       | 1     |
    | 0 / None   | 0     |
    """
    if loss_percentage is None or loss_percentage <= 0:
        return 0.0
    if loss_percentage >= 80:
        return 5.0
    if loss_percentage >= 60:
        return 4.0
    if loss_percentage >= 40:
        return 3.0
    if loss_percentage >= 20:
        return 2.0
    return 1.0


# ---------------------------------------------------------------------------
# 3. Exposure  (0-5)  — based on DeFi category
# ---------------------------------------------------------------------------

# Categories that handle user funds in high-value pools are more exposed.
_CATEGORY_EXPOSURE: dict[str, float] = {
    "amm_dex": 5.0,       # Massive TVL, constantly attacked
    "lending": 5.0,        # Oracle-dependent, high-value collateral
    "vault_yield": 4.0,    # Share-price manipulation surface
    "staking_rewards": 3.5, # Reward inflation but smaller pools
    "other": 2.0,
}


def score_exposure(defi_category: str) -> float:
    """
    Rate exposure 0-5 based on the DeFi category.

    AMMs and lending protocols have the highest exposure due to large
    liquidity pools and complex interaction surfaces.
    """
    return _CATEGORY_EXPOSURE.get(defi_category.lower(), 2.0)


# ---------------------------------------------------------------------------
# 4. Evidence Strength  (0-5)  — cross-tool consensus
# ---------------------------------------------------------------------------

def score_evidence_strength(
    tools_reporting: int,
    total_tools_run: int,
    is_cross_validated: bool = False,
    has_dynamic_proof: bool = False,
) -> float:
    """
    Rate evidence strength 0-5 based on how many tools agree.

    | Condition                          | Score |
    |------------------------------------|-------|
    | Cross-validated + dynamic proof    | 5     |
    | Cross-validated (no dynamic proof) | 4     |
    | 2+ tools, not formally validated   | 3     |
    | 1 tool only                        | 1.5   |
    | 0 tools (LLM-only)                | 0     |
    """
    if tools_reporting == 0:
        return 0.0

    if is_cross_validated and has_dynamic_proof:
        return 5.0
    if is_cross_validated:
        return 4.0
    if tools_reporting >= 2:
        return 3.0
    # Single tool — penalise but don't zero out
    return 1.5


# ---------------------------------------------------------------------------
# Full rubric computation
# ---------------------------------------------------------------------------

def compute_business_risk_rubric(
    vulnerability_type: str,
    loss_percentage: float | None,
    defi_category: str,
    tools_reporting: int,
    total_tools_run: int,
    is_cross_validated: bool = False,
    has_exploit_proof: bool = False,
    is_reachable: bool = False,
) -> RubricScores:
    """
    Compute the full 4-part business risk rubric for one vulnerability.

    Returns a ``RubricScores`` instance whose ``.business_risk_score``
    property gives the aggregated 0-100 score.
    """
    return RubricScores(
        exploitability=score_exploitability(
            vulnerability_type,
            has_exploit_proof=has_exploit_proof,
            is_reachable=is_reachable,
        ),
        financial_impact=score_financial_impact(loss_percentage),
        exposure=score_exposure(defi_category),
        evidence_strength=score_evidence_strength(
            tools_reporting,
            total_tools_run,
            is_cross_validated=is_cross_validated,
            has_dynamic_proof=has_exploit_proof,
        ),
    )


# ---------------------------------------------------------------------------
# Severity band helpers
# ---------------------------------------------------------------------------

def _risk_to_band(score: float) -> str:
    """Convert a 0-100 risk score to a severity band label."""
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def _loss_pct_to_band(loss: float | None) -> str:
    """Convert an LLM loss-bucket percentage to a severity band."""
    if loss is None:
        return "unknown"
    if loss >= 75:
        return "critical"
    if loss >= 40:
        return "high"
    if loss >= 10:
        return "medium"
    if loss > 0:
        return "low"
    return "none"


_BAND_ORDER = {"none": 0, "unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _band_distance(band_a: str, band_b: str) -> int:
    return abs(_BAND_ORDER.get(band_a, 0) - _BAND_ORDER.get(band_b, 0))


# ---------------------------------------------------------------------------
# Rubric-vs-LLM comparison for a single finding
# ---------------------------------------------------------------------------

def compare_rubric_vs_llm(
    vulnerability_type: str,
    rubric: RubricScores,
    llm_loss_percentage: float | None,
) -> RubricLLMComparison:
    """
    Compare the deterministic rubric score with the LLM loss prediction.

    Agreement levels (severity-band comparison):
      - STRONG:   same severity band
      - MODERATE: one band apart
      - WEAK:     two bands apart
      - DISAGREE: three+ bands apart

    Also classifies both sides into discrete loss buckets (~10 %, ~50 %,
    ~100 %) so the paper can report bucket-level consensus.
    """
    rubric_band = _risk_to_band(rubric.business_risk_score)
    llm_band = _loss_pct_to_band(llm_loss_percentage)

    dist = _band_distance(rubric_band, llm_band)

    if llm_loss_percentage is None:
        agreement = LossAgreement.WEAK
        notes = "LLM did not produce a loss estimate"
    elif dist == 0:
        agreement = LossAgreement.STRONG
        notes = "Rubric and LLM agree on severity band"
    elif dist == 1:
        agreement = LossAgreement.MODERATE
        notes = "Rubric and LLM within one severity band"
    elif dist == 2:
        agreement = LossAgreement.WEAK
        notes = "Rubric and LLM differ by two severity bands"
    else:
        agreement = LossAgreement.DISAGREE
        notes = "Rubric and LLM strongly disagree — manual review recommended"

    # Discrete loss-bucket classification (RQ3)
    rubric_bucket = classify_loss_bucket(rubric.business_risk_score)
    llm_bucket = classify_loss_bucket(llm_loss_percentage)
    bucket_agree = rubric_bucket == llm_bucket

    return RubricLLMComparison(
        vulnerability_type=vulnerability_type,
        rubric_scores=rubric,
        rubric_risk_score=rubric.business_risk_score,
        llm_loss_percentage=llm_loss_percentage,
        rubric_severity_band=rubric_band,
        llm_severity_band=llm_band,
        agreement=agreement,
        notes=notes,
        rubric_loss_bucket=rubric_bucket.value,
        llm_loss_bucket=llm_bucket.value,
        bucket_agreement=bucket_agree,
    )


# ---------------------------------------------------------------------------
# Aggregate comparison across all findings
# ---------------------------------------------------------------------------

@dataclass
class BusinessRiskReport:
    """Full business risk assessment for a contract."""
    per_finding: list[RubricLLMComparison] = field(default_factory=list)

    @property
    def avg_rubric_score(self) -> float:
        if not self.per_finding:
            return 0.0
        return round(
            sum(c.rubric_risk_score for c in self.per_finding) / len(self.per_finding), 2
        )

    @property
    def max_rubric_score(self) -> float:
        if not self.per_finding:
            return 0.0
        return max(c.rubric_risk_score for c in self.per_finding)

    @property
    def strong_agreement_count(self) -> int:
        return sum(1 for c in self.per_finding if c.agreement == LossAgreement.STRONG)

    @property
    def moderate_agreement_count(self) -> int:
        return sum(1 for c in self.per_finding if c.agreement == LossAgreement.MODERATE)

    @property
    def disagree_count(self) -> int:
        return sum(1 for c in self.per_finding if c.agreement == LossAgreement.DISAGREE)

    @property
    def consensus_rate(self) -> float:
        """Fraction of findings where rubric & LLM agree (strong or moderate)."""
        if not self.per_finding:
            return 0.0
        agree = self.strong_agreement_count + self.moderate_agreement_count
        return round(agree / len(self.per_finding), 4)

    @property
    def high_severity_consensus_rate(self) -> float:
        """
        Consensus rate considering only high/critical-band findings.

        For high-impact vulnerabilities like reentrancy or access control
        bypass, the rubric and LLM should agree most strongly.
        """
        high_findings = [
            c for c in self.per_finding
            if c.rubric_severity_band in ("high", "critical")
        ]
        if not high_findings:
            return 0.0
        agree = sum(
            1 for c in high_findings
            if c.agreement in (LossAgreement.STRONG, LossAgreement.MODERATE)
        )
        return round(agree / len(high_findings), 4)

    # ------------------------------------------------------------------
    # Loss-bucket consensus metrics (RQ3 — 10 %/50 %/100 % buckets)
    # ------------------------------------------------------------------

    @property
    def bucket_agreement_count(self) -> int:
        """Number of findings where rubric and LLM land in the same loss bucket."""
        return sum(1 for c in self.per_finding if c.bucket_agreement)

    @property
    def bucket_agreement_rate(self) -> float:
        """Fraction of findings where rubric and LLM agree on loss bucket."""
        if not self.per_finding:
            return 0.0
        return round(self.bucket_agreement_count / len(self.per_finding), 4)

    @property
    def high_severity_bucket_agreement_rate(self) -> float:
        """Bucket agreement rate for high/critical-band findings only."""
        high_findings = [
            c for c in self.per_finding
            if c.rubric_severity_band in ("high", "critical")
        ]
        if not high_findings:
            return 0.0
        agree = sum(1 for c in high_findings if c.bucket_agreement)
        return round(agree / len(high_findings), 4)

    @property
    def bucket_distribution(self) -> dict[str, dict[str, int]]:
        """
        Distribution of findings across loss buckets for both rubric and LLM.

        Returns ``{"rubric": {"~10%": N, ...}, "llm": {"~10%": N, ...}}``.
        """
        rubric_dist: dict[str, int] = {}
        llm_dist: dict[str, int] = {}
        for c in self.per_finding:
            rubric_dist[c.rubric_loss_bucket] = rubric_dist.get(c.rubric_loss_bucket, 0) + 1
            llm_dist[c.llm_loss_bucket] = llm_dist.get(c.llm_loss_bucket, 0) + 1
        return {"rubric": rubric_dist, "llm": llm_dist}

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_findings_assessed": len(self.per_finding),
            "avg_rubric_score": self.avg_rubric_score,
            "max_rubric_score": self.max_rubric_score,
            "strong_agreement": self.strong_agreement_count,
            "moderate_agreement": self.moderate_agreement_count,
            "disagree": self.disagree_count,
            "consensus_rate": self.consensus_rate,
            "high_severity_consensus_rate": self.high_severity_consensus_rate,
            "bucket_agreement_count": self.bucket_agreement_count,
            "bucket_agreement_rate": self.bucket_agreement_rate,
            "high_severity_bucket_agreement_rate": self.high_severity_bucket_agreement_rate,
            "bucket_distribution": self.bucket_distribution,
            "per_finding": [c.to_dict() for c in self.per_finding],
        }
