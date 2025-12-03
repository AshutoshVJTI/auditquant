#!/usr/bin/env python3
"""Download SmartBugs Curated and SolidiFI datasets."""
from __future__ import annotations

import subprocess
from pathlib import Path

SMARTBUGS_REPO = "https://github.com/smartbugs/smartbugs-curated"
SOLIDIFI_REPO = "https://github.com/smartbugs/SolidiFI-benchmark"


def _run(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True)


def _clone_or_update(repo_url: str, dest: Path) -> None:
    if dest.exists():
        if (dest / ".git").exists():
            _run(["git", "-C", str(dest), "pull", "--ff-only"])
            return
        raise RuntimeError(f"Destination exists but is not a git repo: {dest}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    _run(["git", "clone", repo_url, str(dest)])


def main() -> None:
    training_dir = Path(__file__).resolve().parent
    data_dir = training_dir / "data"
    smartbugs_dir = data_dir / "smartbugs-curated"
    solidifi_dir = data_dir / "solidifi"

    print("Downloading SmartBugs Curated dataset...")
    _clone_or_update(SMARTBUGS_REPO, smartbugs_dir)

    print("Downloading SolidiFI benchmark dataset...")
    _clone_or_update(SOLIDIFI_REPO, solidifi_dir)

    print("Done.")


if __name__ == "__main__":
    main()
