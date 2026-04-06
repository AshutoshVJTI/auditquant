import math


IMPACT_WEIGHTS = {
    "Critical": 12,
    "High": 10,
    "Medium": 5,
    "Low": 2,
    "Informational": 1,
}

CONFIDENCE_WEIGHTS = {
    "High": 1.0,
    "Medium": 0.8,
    "Low": 0.45,
}


def compute_r_sast(issues: list[tuple[str, str]]) -> float:
    total = 0.0
    for impact, confidence in issues:
        total += IMPACT_WEIGHTS.get(impact, 0) * CONFIDENCE_WEIGHTS.get(confidence, 0)
    return min(100.0, total)


# unreachable issues get partial weight since symbolic engine flagged the path
_DAST_REACHABLE_MULT = 1.0
_DAST_UNREACHABLE_MULT = 0.42


def compute_r_dast(severities: list[tuple[float, bool]]) -> float:
    if not severities:
        return 0.0
    return max(
        severity * (_DAST_REACHABLE_MULT if reachable else _DAST_UNREACHABLE_MULT)
        for severity, reachable in severities
    )


def compute_r_comp(cyclomatic_complexity: float) -> float:
    # sigmoid centered at CC=20
    return 100.0 / (1.0 + math.exp(-0.2 * (cyclomatic_complexity - 20)))


def compute_composite(r_sast: float, r_dast: float, r_comp: float) -> float:
    # weight toward dynamic analysis when Mythril actually found something reachable
    if r_dast > 0:
        return 0.30 * r_sast + 0.50 * r_dast + 0.20 * r_comp
    return 0.50 * r_sast + 0.50 * r_comp
