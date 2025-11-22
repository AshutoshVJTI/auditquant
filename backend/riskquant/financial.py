from __future__ import annotations

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
