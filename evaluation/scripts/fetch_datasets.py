#!/usr/bin/env python3
"""
Dataset Fetcher for AuditQuant Evaluation

Fetches and organizes contracts from:
1. SmartBugs Curated - Real-world vulnerabilities with labels
2. SolidiFI - Synthetic injected bugs

Target: 100 contracts stratified across DeFi categories
"""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

EVAL_DIR = Path(__file__).parent.parent
DATASETS_DIR = EVAL_DIR / "datasets"
LABELS_DIR = EVAL_DIR / "labels"

# Dataset sources
SMARTBUGS_REPO = "https://github.com/smartbugs/smartbugs-curated.git"
SOLIDIFI_REPO = "https://github.com/DependableSystemsLab/SolidiFI.git"

# Target distribution (100 contracts total)
TARGET_DISTRIBUTION = {
    "amm_dex": 25,
    "lending": 25,
    "vault_yield": 20,
    "staking_rewards": 15,
    "other": 15,
}


def run_cmd(cmd: list[str], cwd: Path | None = None) -> bool:
    """Run a command and return success status."""
    try:
        subprocess.run(cmd, cwd=cwd, check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {' '.join(cmd)}")
        print(f"Error: {e.stderr.decode()}")
        return False


def fetch_smartbugs() -> Path:
    """Clone SmartBugs Curated dataset."""
    dest = DATASETS_DIR / "smartbugs-curated"
    
    if dest.exists():
        print(f"SmartBugs already exists at {dest}")
        return dest
    
    print("Cloning SmartBugs Curated...")
    if run_cmd(["git", "clone", "--depth", "1", SMARTBUGS_REPO, str(dest)]):
        print(f"✓ SmartBugs cloned to {dest}")
    else:
        print("✗ Failed to clone SmartBugs")
    
    return dest


def fetch_solidifi() -> Path:
    """Clone SolidiFI dataset."""
    dest = DATASETS_DIR / "solidifi"
    
    if dest.exists():
        print(f"SolidiFI already exists at {dest}")
        return dest
    
    print("Cloning SolidiFI...")
    if run_cmd(["git", "clone", "--depth", "1", SOLIDIFI_REPO, str(dest)]):
        print(f"✓ SolidiFI cloned to {dest}")
    else:
        print("✗ Failed to clone SolidiFI")
    
    return dest


def find_solidity_files(directory: Path) -> list[Path]:
    """Recursively find all .sol files."""
    return list(directory.rglob("*.sol"))


def classify_contract_simple(source: str) -> str:
    """
    Simple keyword-based classification for initial sorting.
    Full classification uses the DeFi classifier module.
    """
    source_lower = source.lower()
    
    # AMM/DEX patterns
    if any(kw in source_lower for kw in ["swap", "liquidity", "reserve", "uniswap", "pair", "amm"]):
        return "amm_dex"
    
    # Lending patterns
    if any(kw in source_lower for kw in ["borrow", "lend", "collateral", "liquidat", "aave", "compound"]):
        return "lending"
    
    # Vault patterns
    if any(kw in source_lower for kw in ["vault", "yield", "harvest", "strategy", "erc4626"]):
        return "vault_yield"
    
    # Staking patterns
    if any(kw in source_lower for kw in ["stake", "reward", "emission", "masterchef", "farm"]):
        return "staking_rewards"
    
    return "other"


def get_vulnerability_info(file_path: Path, dataset_name: str) -> dict[str, Any]:
    """Extract vulnerability info from dataset metadata."""
    info = {
        "vulnerability_types": [],
        "has_ground_truth": False,
    }
    
    if dataset_name == "smartbugs":
        # SmartBugs organizes by vulnerability type in directory structure
        parts = file_path.parts
        for part in parts:
            if part in ["reentrancy", "access_control", "arithmetic", "denial_of_service",
                       "front_running", "time_manipulation", "unchecked_low_level_calls"]:
                info["vulnerability_types"].append(part)
                info["has_ground_truth"] = True
    
    elif dataset_name == "solidifi":
        # SolidiFI has bug info in filename or adjacent JSON
        filename = file_path.stem
        if "reentrancy" in filename.lower():
            info["vulnerability_types"].append("reentrancy")
        if "overflow" in filename.lower():
            info["vulnerability_types"].append("integer_overflow")
        if "access" in filename.lower():
            info["vulnerability_types"].append("access_control")
        info["has_ground_truth"] = True
    
    return info


def create_contract_entry(
    file_path: Path,
    dataset_name: str,
    category: str,
    index: int,
) -> dict[str, Any]:
    """Create a contract entry for the labeling dataset."""
    source = file_path.read_text(encoding="utf-8", errors="ignore")
    vuln_info = get_vulnerability_info(file_path, dataset_name)
    
    return {
        "id": f"{category}_{index:03d}",
        "original_path": str(file_path),
        "dataset": dataset_name,
        "filename": file_path.name,
        "defi_category": category,
        "defi_category_confidence": None,  # To be filled by classifier
        "known_vulnerabilities": vuln_info["vulnerability_types"],
        "has_ground_truth": vuln_info["has_ground_truth"],
        # Manual labeling fields (to be filled)
        "manual_labels": {
            "confirmed_category": None,
            "exploitability": None,  # "confirmed", "potential", "false_positive"
            "loss_percentage": None,  # 0-100
            "notes": None,
        },
        "source_lines": len(source.split("\n")),
        "source_chars": len(source),
    }


def build_evaluation_dataset():
    """Build the 100-contract evaluation dataset."""
    print("\n" + "="*60)
    print("Building AuditQuant Evaluation Dataset")
    print("="*60 + "\n")
    
    # Create directories
    DATASETS_DIR.mkdir(parents=True, exist_ok=True)
    LABELS_DIR.mkdir(parents=True, exist_ok=True)
    
    # Fetch datasets
    smartbugs_dir = fetch_smartbugs()
    solidifi_dir = fetch_solidifi()
    
    # Find all contracts
    all_contracts: dict[str, list[tuple[Path, str]]] = {cat: [] for cat in TARGET_DISTRIBUTION}
    
    print("\nClassifying contracts...")
    
    # Process SmartBugs
    if smartbugs_dir.exists():
        for sol_file in find_solidity_files(smartbugs_dir):
            try:
                source = sol_file.read_text(encoding="utf-8", errors="ignore")
                category = classify_contract_simple(source)
                all_contracts[category].append((sol_file, "smartbugs"))
            except Exception as e:
                print(f"  Skip {sol_file.name}: {e}")
    
    # Process SolidiFI
    if solidifi_dir.exists():
        for sol_file in find_solidity_files(solidifi_dir):
            try:
                source = sol_file.read_text(encoding="utf-8", errors="ignore")
                category = classify_contract_simple(source)
                all_contracts[category].append((sol_file, "solidifi"))
            except Exception as e:
                print(f"  Skip {sol_file.name}: {e}")
    
    # Report distribution
    print("\nAvailable contracts per category:")
    for cat, contracts in all_contracts.items():
        print(f"  {cat}: {len(contracts)}")
    
    # Select contracts for evaluation
    selected: list[dict[str, Any]] = []
    selected_dir = DATASETS_DIR / "selected"
    selected_dir.mkdir(exist_ok=True)
    
    print("\nSelecting contracts for evaluation dataset...")
    
    for category, target_count in TARGET_DISTRIBUTION.items():
        available = all_contracts[category]
        
        # Take up to target_count, preferring SmartBugs (has better labels)
        smartbugs_contracts = [(p, d) for p, d in available if d == "smartbugs"]
        solidifi_contracts = [(p, d) for p, d in available if d == "solidifi"]
        
        to_select = []
        # Prioritize SmartBugs
        to_select.extend(smartbugs_contracts[:target_count])
        # Fill remaining from SolidiFI
        remaining = target_count - len(to_select)
        if remaining > 0:
            to_select.extend(solidifi_contracts[:remaining])
        
        # If still not enough, take from "other" category
        if len(to_select) < target_count and category != "other":
            other_available = all_contracts["other"]
            remaining = target_count - len(to_select)
            to_select.extend(other_available[:remaining])
        
        # Create entries and copy files
        for idx, (file_path, dataset_name) in enumerate(to_select):
            entry = create_contract_entry(file_path, dataset_name, category, len(selected) + 1)
            
            # Copy to selected directory
            dest_path = selected_dir / f"{entry['id']}_{file_path.name}"
            shutil.copy2(file_path, dest_path)
            entry["selected_path"] = str(dest_path)
            
            selected.append(entry)
        
        print(f"  {category}: selected {len(to_select)}/{target_count}")
    
    # Save manifest
    manifest = {
        "version": "1.0",
        "total_contracts": len(selected),
        "target_distribution": TARGET_DISTRIBUTION,
        "actual_distribution": {
            cat: len([c for c in selected if c["defi_category"] == cat])
            for cat in TARGET_DISTRIBUTION
        },
        "contracts": selected,
    }
    
    manifest_path = LABELS_DIR / "dataset_manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    
    print(f"\n✓ Saved manifest to {manifest_path}")
    
    # Create labeling template
    labeling_template = []
    for contract in selected:
        labeling_template.append({
            "id": contract["id"],
            "filename": contract["filename"],
            "defi_category": contract["defi_category"],
            "known_vulnerabilities": contract["known_vulnerabilities"],
            # Fields to fill manually
            "confirmed_category": "",  # Fill: amm_dex, lending, vault_yield, staking_rewards, other
            "exploitability": "",  # Fill: confirmed, potential, false_positive
            "loss_percentage": None,  # Fill: 0-100
            "notes": "",
        })
    
    template_path = LABELS_DIR / "labeling_template.json"
    with open(template_path, "w") as f:
        json.dump(labeling_template, f, indent=2)
    
    print(f"✓ Saved labeling template to {template_path}")
    
    # Summary
    print("\n" + "="*60)
    print("Dataset Summary")
    print("="*60)
    print(f"Total contracts: {len(selected)}")
    print(f"Selected directory: {selected_dir}")
    print(f"Manifest: {manifest_path}")
    print(f"Labeling template: {template_path}")
    print("\nNext steps:")
    print("1. Review labeling_template.json")
    print("2. Fill in confirmed_category, exploitability, loss_percentage")
    print("3. Run classifier to auto-fill defi_category_confidence")
    print("="*60)


if __name__ == "__main__":
    build_evaluation_dataset()
