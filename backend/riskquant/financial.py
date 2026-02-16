# L_perc computation -- projected financial loss as a percentage of TVL.
# L_perc = sum(V_vuln * P_drain) / TVL * 100

# TODO: these probabilities are rough estimates, refine with real data
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

LOSS_MAP = {
    "reentrancy": 100.0,
    "access control": 100.0,
    "integer overflow": 50.0,
    "unchecked return": 50.0,
    "naming convention": 0.0,
    "gas": 0.0,
}


def map_loss_percentage(vuln_type: str) -> float | None:
    key = vuln_type.strip().lower()
    for label, loss in LOSS_MAP.items():
        if label in key:
            return loss
    return None


def _resolve_drain_probability(vuln_type: str) -> float:
    key = vuln_type.strip().lower()
    for label, prob in DRAIN_PROBABILITY.items():
        if label in key:
            return prob
    return 0.0


def compute_loss_percentage(
    vulnerabilities: list[tuple[str, float]],
    tvl_projected: float = 100.0,
) -> float:
    """L_perc = sum(V_vuln * P_drain) / TVL * 100, capped at 100."""
    if tvl_projected <= 0:
        return 0.0

    total = 0.0
    for vuln_type, v_vuln in vulnerabilities:
        p_drain = _resolve_drain_probability(vuln_type)
        total += v_vuln * p_drain

    return min(100.0, (total / tvl_projected) * 100)
