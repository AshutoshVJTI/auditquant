#!/usr/bin/env python3
"""
Fetch and parse the two reputed vulnerability databases:

  1. SWC Registry  — 37 entries (SWC-100 … SWC-136), each with description,
     CWE mapping, remediation guidance, vulnerable .sol samples, and fixed
     _fixed.sol samples.
  2. DeFiVulnLabs  — 48 vulnerability types with VulnerableX / FixedX contract
     pairs in Foundry test files.

Output: data/knowledge_base.json
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DIR = SCRIPT_DIR / "data"
REPOS_DIR = SCRIPT_DIR / "repos"

SWC_REPO = "https://github.com/SmartContractSecurity/SWC-registry.git"
DEFI_REPO = "https://github.com/SunWeb3Sec/DeFiVulnLabs.git"


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------

def _clone_or_pull(url: str, dest: Path) -> None:
    if dest.exists():
        print(f"  Repo exists at {dest}, pulling latest …")
        subprocess.run(["git", "-C", str(dest), "pull", "--ff-only"],
                       capture_output=True)
    else:
        print(f"  Cloning {url} → {dest} …")
        subprocess.run(["git", "clone", "--depth", "1", url, str(dest)],
                       check=True)


# ---------------------------------------------------------------------------
# SWC Registry parser
# ---------------------------------------------------------------------------

def _parse_swc_entry(md_path: Path) -> dict[str, Any] | None:
    """Parse a single SWC-*.md file into a knowledge-base entry."""
    text = md_path.read_text(encoding="utf-8", errors="ignore")

    swc_id = md_path.stem  # e.g. "SWC-107"

    # Title
    title_m = re.search(r"^#\s+Title\s*\n+(.+)", text, re.MULTILINE)
    title = title_m.group(1).strip() if title_m else swc_id

    # CWE
    cwe_m = re.search(r"\[CWE-(\d+)", text)
    cwe_id = f"CWE-{cwe_m.group(1)}" if cwe_m else None

    # Description
    desc_m = re.search(
        r"##\s+Description\s*\n+(.*?)(?=\n##|\Z)", text, re.DOTALL
    )
    description = desc_m.group(1).strip() if desc_m else ""

    # Remediation
    rem_m = re.search(
        r"##\s+Remediation\s*\n+(.*?)(?=\n##|\Z)", text, re.DOTALL
    )
    remediation = rem_m.group(1).strip() if rem_m else ""

    # Code samples — extract ```solidity ... ``` blocks
    samples_section = re.search(
        r"##\s+Samples\s*\n+(.*)", text, re.DOTALL
    )
    if not samples_section:
        return None

    samples_text = samples_section.group(1)

    # Each sample is preceded by ### filename.sol
    sample_blocks = re.split(r"###\s+(\S+\.sol)", samples_text)
    # sample_blocks: ['', 'foo.sol', '<code>', 'bar_fixed.sol', '<code>', ...]

    vulnerable_samples: list[dict[str, str]] = []
    fixed_samples: list[dict[str, str]] = []

    i = 1
    while i < len(sample_blocks) - 1:
        filename = sample_blocks[i].strip()
        block = sample_blocks[i + 1]
        code_m = re.search(r"```solidity\s*\n(.*?)```", block, re.DOTALL)
        if code_m:
            code = code_m.group(1).strip()
            entry = {"filename": filename, "code": code}
            if "_fixed" in filename.lower() or "fixed" in filename.lower():
                fixed_samples.append(entry)
            else:
                vulnerable_samples.append(entry)
        i += 2

    if not vulnerable_samples:
        return None

    return {
        "source": "swc-registry",
        "swc_id": swc_id,
        "title": title,
        "cwe_id": cwe_id,
        "description": description,
        "remediation": remediation,
        "vulnerable_samples": vulnerable_samples,
        "fixed_samples": fixed_samples,
    }


def parse_swc_registry(repo_dir: Path) -> list[dict[str, Any]]:
    docs_dir = repo_dir / "entries" / "docs"
    if not docs_dir.exists():
        print(f"  WARNING: {docs_dir} not found")
        return []

    entries: list[dict[str, Any]] = []
    for md_file in sorted(docs_dir.glob("SWC-*.md")):
        entry = _parse_swc_entry(md_file)
        if entry:
            entries.append(entry)
    return entries


# ---------------------------------------------------------------------------
# DeFiVulnLabs parser
# ---------------------------------------------------------------------------

_CONTRACT_RE = re.compile(
    r"contract\s+(\w+).*?\{",
    re.DOTALL,
)


def _extract_contracts(source: str) -> dict[str, str]:
    """Extract top-level contract bodies from a Solidity file."""
    contracts: dict[str, str] = {}

    # Find contract declarations and their bodies using brace counting
    for m in _CONTRACT_RE.finditer(source):
        name = m.group(1)
        start = m.end() - 1  # position of opening brace
        depth = 0
        end = start
        for j in range(start, len(source)):
            if source[j] == "{":
                depth += 1
            elif source[j] == "}":
                depth -= 1
                if depth == 0:
                    end = j + 1
                    break
        contracts[name] = source[m.start():end]

    return contracts


def _classify_contract(name: str) -> str | None:
    low = name.lower()
    if "fix" in low or "secure" in low or "safe" in low:
        return "fixed"
    if "vuln" in low or "attack" in low or "exploit" in low or "bug" in low:
        return "vulnerable"
    return None


def _infer_vuln_type(filename: str) -> str:
    """Guess vulnerability type from the test filename."""
    low = filename.lower().replace(".sol", "").replace("-", "_")
    mapping = {
        "reentrancy": "reentrancy",
        "reentranc": "reentrancy",
        "overflow": "integer-overflow",
        "underflow": "integer-overflow",
        "selfdestruct": "selfdestruct",
        "delegatecall": "unsafe-delegatecall",
        "privatedata": "private-data",
        "visibility": "access-control",
        "txorigin": "tx-origin",
        "randomness": "bad-randomness",
        "dos": "denial-of-service",
        "returnvalue": "unchecked-return",
        "returnfalse": "unchecked-return",
        "backdoor": "hidden-backdoor",
        "bypasscontract": "bypass-iscontract",
        "datalocation": "data-location",
        "dirtybytes": "dirty-bytes",
        "ecrecover": "ecrecover",
        "oracle": "oracle-manipulation",
        "price_manipulation": "price-manipulation",
        "first_deposit": "first-deposit-bug",
        "flashloan": "flash-loan",
        "nft": "nft-vulnerability",
        "hash_collision": "hash-collision",
        "precision": "precision-loss",
        "slippage": "slippage",
        "unsafe_call": "unsafe-call",
        "unchecked": "unchecked-return",
        "signature": "signature-replay",
        "storage_collision": "storage-collision",
        "struct_deletion": "struct-deletion",
        "array_deletion": "array-deletion",
        "gas_price": "gas-price-manipulation",
        "fee_on_transfer": "fee-on-transfer",
        "phantom": "phantom-function",
        "payable_transfer": "payable-transfer",
        "nft_transfer": "nft-transfer",
        "self_transfer": "self-transfer",
        "recovererc20": "recover-erc20",
        "downcast": "unsafe-downcast",
        "divmultiply": "divide-before-multiply",
        "empty_loop": "empty-loop",
        "sanity": "incorrect-sanity-checks",
        "invariant": "invariant-violation",
        "transient": "transient-storage",
    }
    for key, vuln in mapping.items():
        if key in low:
            return vuln
    return low


def parse_defivulnlabs(repo_dir: Path) -> list[dict[str, Any]]:
    test_dir = repo_dir / "src" / "test"
    if not test_dir.exists():
        print(f"  WARNING: {test_dir} not found")
        return []

    entries: list[dict[str, Any]] = []

    for sol_file in sorted(test_dir.glob("*.sol")):
        source = sol_file.read_text(encoding="utf-8", errors="ignore")
        contracts = _extract_contracts(source)
        if not contracts:
            continue

        vulnerable: list[dict[str, str]] = []
        fixed: list[dict[str, str]] = []

        for name, code in contracts.items():
            role = _classify_contract(name)
            if role == "vulnerable":
                vulnerable.append({"filename": sol_file.name, "contract_name": name, "code": code})
            elif role == "fixed":
                fixed.append({"filename": sol_file.name, "contract_name": name, "code": code})

        if vulnerable:
            vuln_type = _infer_vuln_type(sol_file.name)
            entries.append({
                "source": "defivulnlabs",
                "swc_id": None,
                "title": vuln_type.replace("-", " ").title(),
                "cwe_id": None,
                "description": f"Vulnerability example from DeFiVulnLabs: {sol_file.name}",
                "remediation": "",
                "vulnerable_samples": vulnerable,
                "fixed_samples": fixed,
            })

    return entries


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    REPOS_DIR.mkdir(parents=True, exist_ok=True)

    print("=== Fetching SWC Registry ===")
    swc_dir = REPOS_DIR / "SWC-registry"
    _clone_or_pull(SWC_REPO, swc_dir)
    swc_entries = parse_swc_registry(swc_dir)
    print(f"  Parsed {len(swc_entries)} SWC entries with code samples")

    print("\n=== Fetching DeFiVulnLabs ===")
    defi_dir = REPOS_DIR / "DeFiVulnLabs"
    _clone_or_pull(DEFI_REPO, defi_dir)
    defi_entries = parse_defivulnlabs(defi_dir)
    print(f"  Parsed {len(defi_entries)} DeFiVulnLabs entries with vuln/fix pairs")

    knowledge_base = {
        "version": "1.0",
        "sources": ["SWC-registry", "DeFiVulnLabs"],
        "total_entries": len(swc_entries) + len(defi_entries),
        "entries": swc_entries + defi_entries,
    }

    out_path = DATA_DIR / "knowledge_base.json"
    with open(out_path, "w") as f:
        json.dump(knowledge_base, f, indent=2, ensure_ascii=False)

    # Stats
    total_vuln = sum(len(e["vulnerable_samples"]) for e in knowledge_base["entries"])
    total_fix = sum(len(e["fixed_samples"]) for e in knowledge_base["entries"])
    print(f"\n=== Knowledge Base Summary ===")
    print(f"  Total entries:           {knowledge_base['total_entries']}")
    print(f"  Vulnerable code samples: {total_vuln}")
    print(f"  Fixed code samples:      {total_fix}")
    print(f"  Written to:              {out_path}")


if __name__ == "__main__":
    main()
