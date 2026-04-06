
import re
from pathlib import Path

_VERSION_BY_MINOR: dict[tuple[int, int], str] = {
    (0, 4): "0.4.26",
    (0, 5): "0.5.17",
    (0, 6): "0.6.12",
    (0, 7): "0.7.6",
    (0, 8): "0.8.20",
}
def infer_solc_version(solidity_path: Path) -> str | None:
    """
    Infer a concrete solc version from `pragma solidity ...`.
    Returns None when no pragma could be parsed.
    """
    try:
        source = solidity_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None

    m = re.search(r"pragma\s+solidity\s+([^;]+);", source, flags=re.IGNORECASE)
    if not m:
        return None

    expr = m.group(1).strip()
    v = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", expr)
    if not v:
        return None

    major = int(v.group(1))
    minor = int(v.group(2))
    patch = int(v.group(3) or 0)

    mapped = _VERSION_BY_MINOR.get((major, minor))
    if mapped:
        return mapped

    return f"{major}.{minor}.{patch}"
