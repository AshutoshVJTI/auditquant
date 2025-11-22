from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


@dataclass
class TrainingSample:
    vulnerable_code: str
    patched_code: str
    vuln_type: str


def load_dataset(root: Path) -> Iterator[TrainingSample]:
    """Yield training samples from SmartBugs + SolidiFI style folders."""
    for vuln_dir in root.glob("*"):
        if not vuln_dir.is_dir():
            continue
        vuln_type = vuln_dir.name
        for sample_dir in vuln_dir.glob("*"):
            vulnerable_path = sample_dir / "vulnerable.sol"
            patched_path = sample_dir / "patched.sol"
            if not vulnerable_path.exists() or not patched_path.exists():
                continue
            yield TrainingSample(
                vulnerable_code=vulnerable_path.read_text(encoding="utf-8"),
                patched_code=patched_path.read_text(encoding="utf-8"),
                vuln_type=vuln_type,
            )
