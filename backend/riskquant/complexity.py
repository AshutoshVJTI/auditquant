from __future__ import annotations

import re


BRANCH_TOKENS = re.compile(r"\b(if|else if|for|while|case|catch)\b|&&|\|\||\?", re.IGNORECASE)


def estimate_cyclomatic_complexity(source: str) -> int:
    """Lightweight heuristic for Cyclomatic Complexity in Solidity."""
    matches = BRANCH_TOKENS.findall(source)
    return 1 + len(matches)
