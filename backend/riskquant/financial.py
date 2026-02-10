"""
Financial Loss Quantification

Implements the L_perc formula from the research proposal:

    L_perc = (Σ(V_vuln × P_drain)) / TVL_projected × 100

Drain probabilities:
  - Total Drain  (P = 1.0): Reentrancy, Access Control bypass
  - Partial Loss (P = 0.5): Integer Overflow, Unchecked Return Values
  - Zero Impact  (P = 0.0): Naming conventions, Gas inefficiencies
"""
from __future__ import annotations

# Drain probability per vulnerability type (P_drain)
DRAIN_PROBABILITY: dict[str, float] = {
    "reentrancy": 1.0,
    "access control": 1.0,
    "access-control": 1.0,
    "integer overflow": 0.5,
    "integer-overflow": 0.5,
    "unchecked return": 0.5,
    "unchecked-return": 0.5,
    "naming convention": 0.0,
    "gas": 0.0,
}

# Legacy flat mapping (used by V1 paths that just need a percentage)
LOSS_MAP = {
    "reentrancy": 100.0,
    "access control": 100.0,
    "integer overflow": 50.0,
    "unchecked return": 50.0,
    "naming convention": 0.0,
    "gas": 0.0,
}


def map_loss_percentage(vuln_type: str) -> float | None:
    """Map a single vulnerability type to a loss percentage (0-100)."""
    key = vuln_type.strip().lower()
    for label, loss in LOSS_MAP.items():
        if label in key:
            return loss
    return None


def _resolve_drain_probability(vuln_type: str) -> float:
    """Resolve the drain probability for a vulnerability type string."""
    key = vuln_type.strip().lower()
    for label, prob in DRAIN_PROBABILITY.items():
        if label in key:
            return prob
    return 0.0


def compute_loss_percentage(
    vulnerabilities: list[tuple[str, float]],
    tvl_projected: float = 100.0,
) -> float:
    """
    Compute L_perc — the projected financial loss percentage.

        L_perc = (Σ(V_vuln × P_drain)) / TVL_projected × 100

    Args:
        vulnerabilities: List of (vuln_type, V_vuln) tuples where V_vuln is the
            severity weight of each vulnerability (e.g. 1.0 per finding, or a
            severity-based weight).
        tvl_projected: Projected Total Value Locked (normalisation base).  When
            the actual TVL is unknown, defaults to 100.0 so the result
            represents a weighted-average drain percentage.

    Returns:
        L_perc capped at 100.0.
    """
    if tvl_projected <= 0:
        return 0.0

    total = 0.0
    for vuln_type, v_vuln in vulnerabilities:
        p_drain = _resolve_drain_probability(vuln_type)
        total += v_vuln * p_drain

    return min(100.0, (total / tvl_projected) * 100)
