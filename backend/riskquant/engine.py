from __future__ import annotations

import math
from dataclasses import dataclass


IMPACT_WEIGHTS = {
    "High": 10,
    "Medium": 5,
    "Low": 2,
}

CONFIDENCE_WEIGHTS = {
    "High": 1.0,
    "Medium": 0.8,
}


@dataclass
class RiskScores:
    r_sast: float
    r_dast: float
    r_comp: float


def compute_r_sast(issues: list[tuple[str, str]]) -> float:
    total = 0.0
    for impact, confidence in issues:
        total += IMPACT_WEIGHTS.get(impact, 0) * CONFIDENCE_WEIGHTS.get(confidence, 0)
    return min(100.0, total)


def compute_r_dast(severities: list[tuple[float, bool]]) -> float:
    if not severities:
        return 0.0
    return max(severity * (1.0 if reachable else 0.0) for severity, reachable in severities)


def compute_r_comp(cyclomatic_complexity: float) -> float:
    return 100.0 / (1.0 + math.exp(-0.2 * (cyclomatic_complexity - 20)))
