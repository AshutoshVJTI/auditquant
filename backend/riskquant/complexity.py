import re


BRANCH_TOKENS = re.compile(r"\b(if|else if|for|while|case|catch)\b|&&|\|\||\?", re.IGNORECASE)


def estimate_cyclomatic_complexity(source: str) -> int:
    """Quick heuristic -- counts branch keywords in the source.
    Not a real CC calculation but good enough for our purposes."""
    matches = BRANCH_TOKENS.findall(source)
    return 1 + len(matches)
