import json
from functools import lru_cache
from pathlib import Path

_CALIBRATION_PATH = Path(__file__).parent / "data" / "confidence_calibration.json"


@lru_cache(maxsize=1)
def load() -> dict:
    if not _CALIBRATION_PATH.exists():
        raise FileNotFoundError(f"Confidence calibration file not found: {_CALIBRATION_PATH}")
    with open(_CALIBRATION_PATH) as f:
        return json.load(f)


def tool_base(tool: str) -> float:
    return load()["tool_base_confidence"].get(tool, 0.5)


def slither_tier(label: str) -> float:
    tiers = load()["slither_tier_confidence"]
    return tiers.get(label, tiers.get("Medium", tool_base("slither")))


def slitherin_tier(label: str) -> float:
    tiers = load()["slitherin_tier_confidence"]
    return tiers.get(label, tiers.get("Medium", tool_base("slitherin")))


def mythril_confidence(reachable: bool) -> float:
    m = load()["mythril_confidence"]
    return m["reachable"] if reachable else m["not_reachable"]


def semgrep_tier(label: str) -> float:
    tiers = load()["semgrep_tier_confidence"]
    return tiers.get(label.upper(), tiers["default"])


def boost_high() -> float:
    return load()["cross_validation_boosts"]["BOOST_HIGH_CONFIDENCE"]


def boost_medium() -> float:
    return load()["cross_validation_boosts"]["BOOST_MEDIUM_CONFIDENCE"]


def tool_precision_weights() -> dict[str, float]:
    return load()["tool_precision_weights"]
