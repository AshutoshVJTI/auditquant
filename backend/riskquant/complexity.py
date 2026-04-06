import re


BRANCH_TOKENS = re.compile(r"\b(if|else if|for|while|case|catch)\b|&&|\|\||\?", re.IGNORECASE)


def estimate_cyclomatic_complexity(source: str) -> int:
    # rough CC estimate - counts branch keywords, good enough for risk scoring
    matches = BRANCH_TOKENS.findall(source)
    return 1 + len(matches)
