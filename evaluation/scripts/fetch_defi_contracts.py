#!/usr/bin/env python3
"""
Fetch Real DeFi Contracts

Sources:
1. Code4rena audit repos (have known vulnerabilities + reports)
2. Sherlock audit repos
3. Classic DeFi protocols (Uniswap, Aave, Compound, etc.)

These have:
- Real DeFi logic (AMM, Lending, Vaults, Staking)
- Known vulnerabilities with severity labels
- Ground truth for evaluation
"""
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

EVAL_DIR = Path(__file__).parent.parent
DATASETS_DIR = EVAL_DIR / "datasets"
DEFI_DIR = DATASETS_DIR / "defi"
LABELS_DIR = EVAL_DIR / "labels"

# Real DeFi protocols with known audit history
DEFI_SOURCES = {
    # Code4rena contests (have findings reports)
    "code4rena": [
        {
            "name": "uniswap-v3",
            "repo": "https://github.com/Uniswap/v3-core.git",
            "category": "amm_dex",
            "contracts_path": "contracts",
        },
        {
            "name": "aave-v3",
            "repo": "https://github.com/aave/aave-v3-core.git",
            "category": "lending",
            "contracts_path": "contracts",
        },
        {
            "name": "compound-v2",
            "repo": "https://github.com/compound-finance/compound-protocol.git",
            "category": "lending",
            "contracts_path": "contracts",
        },
        {
            "name": "yearn-vaults",
            "repo": "https://github.com/yearn/yearn-vaults.git",
            "category": "vault_yield",
            "contracts_path": "contracts",
        },
        {
            "name": "convex-staking",
            "repo": "https://github.com/convex-eth/platform.git",
            "category": "staking_rewards",
            "contracts_path": "contracts",
        },
        {
            "name": "curve-stableswap",
            "repo": "https://github.com/curvefi/curve-contract.git",
            "category": "amm_dex",
            "contracts_path": "contracts",
        },
        {
            "name": "sushiswap",
            "repo": "https://github.com/sushiswap/sushiswap.git",
            "category": "amm_dex",
            "contracts_path": "protocols/sushiswap/contracts",
        },
        {
            "name": "balancer-v2",
            "repo": "https://github.com/balancer/balancer-v2-monorepo.git",
            "category": "amm_dex",
            "contracts_path": "pkg/pool-weighted/contracts",
        },
    ],
    # Sherlock audited protocols
    "sherlock": [
        {
            "name": "euler-finance",
            "repo": "https://github.com/euler-xyz/euler-contracts.git",
            "category": "lending",
            "contracts_path": "contracts",
        },
        {
            "name": "notional-v2",
            "repo": "https://github.com/notional-finance/contracts-v2.git",
            "category": "lending",
            "contracts_path": "contracts",
        },
    ],
}

# Known vulnerabilities from public disclosures
KNOWN_VULNS = {
    "uniswap-v3": ["reentrancy", "flash_loan", "price_manipulation"],
    "aave-v3": ["flash_loan", "oracle", "liquidation"],
    "compound-v2": ["oracle", "reentrancy", "governance"],
    "yearn-vaults": ["reentrancy", "share_manipulation", "flash_loan"],
    "convex-staking": ["reward_manipulation", "access_control"],
    "curve-stableswap": ["reentrancy", "price_manipulation"],
    "euler-finance": ["flash_loan", "donation_attack", "liquidation"],
}


def run_cmd(cmd: list[str], cwd: Path | None = None, timeout: int = 120) -> bool:
    """Run command with timeout."""
    try:
        subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, timeout=timeout)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(f"  Command failed: {' '.join(cmd[:3])}...")
        return False


def clone_repo(name: str, repo_url: str, dest: Path) -> bool:
    """Clone a repository with shallow depth."""
    if dest.exists():
        print(f"  {name} already exists, skipping clone")
        return True
    
    print(f"  Cloning {name}...")
    return run_cmd(["git", "clone", "--depth", "1", repo_url, str(dest)])


def find_key_contracts(repo_dir: Path, contracts_path: str, category: str) -> list[Path]:
    """Find key DeFi contracts in a repo."""
    contracts_dir = repo_dir / contracts_path
    if not contracts_dir.exists():
        # Try alternate paths
        for alt in ["src", "contracts", "."]:
            alt_path = repo_dir / alt
            if alt_path.exists():
                contracts_dir = alt_path
                break
    
    if not contracts_dir.exists():
        return []
    
    # Find .sol files
    sol_files = list(contracts_dir.rglob("*.sol"))
    
    # Filter by category-relevant keywords
    category_keywords = {
        "amm_dex": ["pool", "swap", "pair", "liquidity", "router", "factory"],
        "lending": ["lend", "borrow", "pool", "token", "oracle", "liquidat"],
        "vault_yield": ["vault", "strategy", "yield", "deposit", "withdraw"],
        "staking_rewards": ["staking", "reward", "farm", "chef", "gauge"],
    }
    
    keywords = category_keywords.get(category, [])
    
    relevant = []
    for f in sol_files:
        name_lower = f.name.lower()
        # Skip test/mock files
        if any(skip in name_lower for skip in ["test", "mock", "interface", "abstract"]):
            continue
        # Prefer files with category keywords
        if any(kw in name_lower for kw in keywords):
            relevant.append(f)
    
    # If no keyword matches, take largest files (likely main contracts)
    if not relevant:
        sol_files_filtered = [f for f in sol_files if "test" not in f.name.lower()]
        relevant = sorted(sol_files_filtered, key=lambda f: f.stat().st_size, reverse=True)[:5]
    
    return relevant[:10]  # Max 10 per repo


def fetch_defi_contracts():
    """Fetch real DeFi contracts from various sources."""
    print("\n" + "="*60)
    print("Fetching Real DeFi Contracts")
    print("="*60 + "\n")
    
    DEFI_DIR.mkdir(parents=True, exist_ok=True)
    
    selected_contracts: list[dict[str, Any]] = []
    
    for source, repos in DEFI_SOURCES.items():
        print(f"\n📦 Source: {source}")
        
        for repo_info in repos:
            name = repo_info["name"]
            repo_url = repo_info["repo"]
            category = repo_info["category"]
            contracts_path = repo_info["contracts_path"]
            
            repo_dir = DEFI_DIR / name
            
            if clone_repo(name, repo_url, repo_dir):
                contracts = find_key_contracts(repo_dir, contracts_path, category)
                
                print(f"    Found {len(contracts)} relevant contracts in {name}")
                
                for i, contract_path in enumerate(contracts):
                    contract_id = f"defi_{category}_{name}_{i+1:02d}"
                    
                    # Copy to selected directory
                    dest_dir = DATASETS_DIR / "selected"
                    dest_dir.mkdir(exist_ok=True)
                    dest_path = dest_dir / f"{contract_id}_{contract_path.name}"
                    
                    try:
                        shutil.copy2(contract_path, dest_path)
                        
                        source_code = contract_path.read_text(encoding="utf-8", errors="ignore")
                        
                        selected_contracts.append({
                            "id": contract_id,
                            "original_path": str(contract_path),
                            "selected_path": str(dest_path),
                            "dataset": f"{source}/{name}",
                            "filename": contract_path.name,
                            "defi_category": category,
                            "known_vulnerabilities": KNOWN_VULNS.get(name, []),
                            "has_ground_truth": name in KNOWN_VULNS,
                            "source_lines": len(source_code.split("\n")),
                            "source_chars": len(source_code),
                            "is_real_defi": True,
                            "manual_labels": {
                                "confirmed_category": category,
                                "exploitability": None,
                                "loss_percentage": None,
                                "notes": f"From {name} protocol",
                            },
                        })
                    except Exception as e:
                        print(f"      Error copying {contract_path.name}: {e}")
    
    # Update manifest with new contracts
    manifest_path = LABELS_DIR / "dataset_manifest.json"
    
    if manifest_path.exists():
        with open(manifest_path) as f:
            manifest = json.load(f)
    else:
        manifest = {"contracts": [], "version": "1.0"}
    
    # Add new DeFi contracts
    existing_ids = {c["id"] for c in manifest["contracts"]}
    new_contracts = [c for c in selected_contracts if c["id"] not in existing_ids]
    
    manifest["contracts"].extend(new_contracts)
    manifest["defi_contracts_added"] = len(new_contracts)
    
    # Update distribution
    category_counts = {}
    for c in manifest["contracts"]:
        cat = c["defi_category"]
        category_counts[cat] = category_counts.get(cat, 0) + 1
    manifest["actual_distribution"] = category_counts
    
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    
    # Summary
    print("\n" + "="*60)
    print("Summary")
    print("="*60)
    print(f"New DeFi contracts added: {len(new_contracts)}")
    print(f"Total contracts in dataset: {len(manifest['contracts'])}")
    print("\nDistribution:")
    for cat, count in sorted(category_counts.items(), key=lambda x: -x[1]):
        real_count = sum(1 for c in manifest["contracts"] if c["defi_category"] == cat and c.get("is_real_defi"))
        print(f"  {cat}: {count} ({real_count} real DeFi)")
    
    return new_contracts


if __name__ == "__main__":
    fetch_defi_contracts()
