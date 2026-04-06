#!/usr/bin/env python3
"""
Builds dataset_v2.json from SmartBugs Curated and prime-smartvuln.
Outputs to evaluation/llm_training/data/dataset_v2.json (70/15/15 split).

Usage:
    python evaluation/scripts/prepare_dataset_v2.py
    python evaluation/scripts/prepare_dataset_v2.py --output path/to/dataset_v2.json
"""
import argparse
import json
import random
from collections import Counter, defaultdict
from pathlib import Path

EVAL_DIR     = Path(__file__).resolve().parents[1]
PROJECT_ROOT = EVAL_DIR.parent
DATASETS_DIR = EVAL_DIR / "datasets"
LABELS_DIR   = EVAL_DIR / "labels"


VULN_LABELS: list[str] = [
    "reentrancy",
    "arithmetic",
    "access_control",
    "unchecked_low_level_calls",
    "denial_of_service",
    "front_running",
    "bad_randomness",
    "flash_loan",
    "price_manipulation",
    "liquidation",
    "reward_manipulation",
    "share_manipulation",
    "governance",
]
LABEL_TO_IDX = {v: i for i, v in enumerate(VULN_LABELS)}

RISK_WEIGHTS: dict[str, float] = {
    "reentrancy":                0.90,
    "flash_loan":                0.88,
    "price_manipulation":        0.85,
    "liquidation":               0.82,
    "share_manipulation":        0.80,
    "access_control":            0.75,
    "reward_manipulation":       0.75,
    "governance":                0.72,
    "arithmetic":                0.70,
    "bad_randomness":            0.65,
    "front_running":             0.62,
    "unchecked_low_level_calls": 0.60,
    "denial_of_service":         0.55,
}

MAX_SOURCE_CHARS = 6000

# SolidiFI folder name → our taxonomy
SOLIDIFI_MAP = {
    "Re-entrancy":           "reentrancy",
    "Overflow-Underflow":    "arithmetic",
    "TOD":                   "front_running",
    "Timestamp-Dependency":  "front_running",
    "Unchecked-Send":        "unchecked_low_level_calls",
    "Unhandled-Exceptions":  "unchecked_low_level_calls",
    "tx.origin":             "access_control",
}

# Not-So-Smart-Contracts folder name → our taxonomy
NOTSO_MAP = {
    "bad_randomness":         "bad_randomness",
    "denial_of_service":      "denial_of_service",
    "forced_ether_reception": "denial_of_service",
    "honeypots":              "access_control",
    "incorrect_interface":    "unchecked_low_level_calls",
    "integer_overflow":       "arithmetic",
    "race_condition":         "front_running",
    "reentrancy":             "reentrancy",
    "unchecked_external_call": "unchecked_low_level_calls",
    "unprotected_function":   "access_control",
    "variable shadowing":     "access_control",
    "wrong_constructor_name": "access_control",
}

# SmartBugs category → our taxonomy
SMARTBUGS_MAP = {
    "access_control":            "access_control",
    "arithmetic":                "arithmetic",
    "bad_randomness":            "bad_randomness",
    "denial_of_service":         "denial_of_service",
    "front_running":             "front_running",
    "other":                     None,
    "reentrancy":                "reentrancy",
    "time_manipulation":         "front_running",
    "unchecked_low_level_calls": "unchecked_low_level_calls",
}

def make_label_vector(vuln_types: list[str]) -> list[int]:
    vec = [0] * len(VULN_LABELS)
    for vt in vuln_types:
        if vt in LABEL_TO_IDX:
            vec[LABEL_TO_IDX[vt]] = 1
    return vec

def make_risk_score(vuln_types: list[str]) -> float:
    if not vuln_types:
        return 0.0
    return max(RISK_WEIGHTS.get(vt, 0.5) for vt in vuln_types)

def read_sol(path: Path) -> str:
    try:
        return path.read_text(errors="replace")[:MAX_SOURCE_CHARS]
    except Exception:
        return ""

def stratified_split(samples: list[dict], train_frac: float, val_frac: float,
                     seed: int) -> list[dict]:
    """Assign train/val/test splits stratified by primary vulnerability type."""
    rng = random.Random(seed)

    # Group by primary vuln type (first in list, or "clean")
    by_primary: dict[str, list[dict]] = defaultdict(list)
    for s in samples:
        primary = s["vuln_types"][0] if s["vuln_types"] else "clean"
        by_primary[primary].append(s)

    assigned = []
    for group in by_primary.values():
        rng.shuffle(group)
        n = len(group)
        n_train = max(1, round(n * train_frac))
        n_val   = max(0, round(n * val_frac))
        for i, s in enumerate(group):
            if i < n_train:
                s["split"] = "train"
            elif i < n_train + n_val:
                s["split"] = "val"
            else:
                s["split"] = "test"
        assigned.extend(group)

    return assigned

def load_web3bugs(contract_labels_path: Path) -> list[dict]:
    """Load the 310 contract-level labeled web3bugs contracts."""
    with open(contract_labels_path) as f:
        labels = json.load(f)

    contracts_root = DATASETS_DIR / "web3bugs" / "contracts"
    samples = []
    missing = 0

    for contract_id, vuln_list in labels.items():
        if not vuln_list:
            continue  # skip contracts with no mapped vuln type
        parts = contract_id.split("_")
        contest = parts[1]
        contract_name = "_".join(parts[2:])

        contest_dir = contracts_root / contest
        if not contest_dir.exists():
            missing += 1
            continue

        matches = list(contest_dir.rglob(f"{contract_name}.sol"))
        if not matches:
            missing += 1
            continue

        source = read_sol(matches[0])
        if not source.strip():
            missing += 1
            continue

        vuln_types = sorted(set(vuln_list))
        samples.append({
            "contract_id":        contract_id,
            "source_code":        source,
            "vuln_types":         vuln_types,
            "label_vector":       make_label_vector(vuln_types),
            "risk_score":         make_risk_score(vuln_types),
            "defi_category":      "defi" if any(v in ("price_manipulation", "flash_loan", "liquidation") for v in vuln_types) else "general",
            "has_ground_truth":   True,
            "label_source":       "web3bugs_contract_level",
            "benchmark_composite": None,
            "split":              "train",  # overwritten by stratified_split
        })

    print(f"  web3bugs: {len(samples)} loaded, {missing} missing files")
    return samples

def load_solidifi() -> list[dict]:
    """Load all 350 SolidiFI buggy contracts."""
    base = DATASETS_DIR / "solidifi" / "buggy_contracts"
    samples = []

    for bug_type_dir in sorted(base.iterdir()):
        if not bug_type_dir.is_dir():
            continue
        mapped = SOLIDIFI_MAP.get(bug_type_dir.name)
        if mapped is None:
            continue

        for sol_file in sorted(bug_type_dir.glob("*.sol")):
            source = read_sol(sol_file)
            if not source.strip():
                continue
            contract_id = f"solidifi_{bug_type_dir.name.lower().replace('-', '_').replace('.', '_')}_{sol_file.stem}"
            vuln_types = [mapped]
            samples.append({
                "contract_id":        contract_id,
                "source_code":        source,
                "vuln_types":         vuln_types,
                "label_vector":       make_label_vector(vuln_types),
                "risk_score":         make_risk_score(vuln_types),
                "defi_category":      "general",
                "has_ground_truth":   True,
                "label_source":       "injection",
                "benchmark_composite": None,
                "split":              "train",
            })

    print(f"  SolidiFI: {len(samples)} loaded")
    return samples

def load_smartbugs() -> list[dict]:
    """Load all 143 SmartBugs curated contracts."""
    vuln_json = DATASETS_DIR / "smartbugs-curated" / "vulnerabilities.json"
    dataset_root = DATASETS_DIR / "smartbugs-curated"

    with open(vuln_json) as f:
        entries = json.load(f)

    samples = []
    skipped = 0

    for entry in entries:
        sol_path = dataset_root / entry["path"]
        if not sol_path.exists():
            skipped += 1
            continue

        source = read_sol(sol_path)
        if not source.strip():
            skipped += 1
            continue

        # Collect all vulnerability categories
        raw_cats = {v["category"] for v in entry.get("vulnerabilities", [])}
        vuln_types = sorted({
            SMARTBUGS_MAP[c]
            for c in raw_cats
            if c in SMARTBUGS_MAP and SMARTBUGS_MAP[c]
        })
        if not vuln_types:
            skipped += 1
            continue

        stem = Path(entry["path"]).stem
        folder = Path(entry["path"]).parent.name
        contract_id = f"smartbugs_{folder}_{stem}"

        samples.append({
            "contract_id":        contract_id,
            "source_code":        source,
            "vuln_types":         vuln_types,
            "label_vector":       make_label_vector(vuln_types),
            "risk_score":         make_risk_score(vuln_types),
            "defi_category":      "general",
            "has_ground_truth":   True,
            "label_source":       "curated",
            "benchmark_composite": None,
            "split":              "train",
        })

    print(f"  SmartBugs curated: {len(samples)} loaded, {skipped} skipped")
    return samples

def load_notso() -> list[dict]:
    """Load Not-So-Smart-Contracts (Trail of Bits)  -  folder name = vuln type."""
    base = DATASETS_DIR / "notso"
    samples = []
    skipped = 0

    for folder in sorted(base.iterdir()):
        if not folder.is_dir():
            continue
        mapped = NOTSO_MAP.get(folder.name)
        if mapped is None:
            continue  # e.g. README dirs

        for sol_file in sorted(folder.rglob("*.sol")):
            source = read_sol(sol_file)
            if not source.strip():
                skipped += 1
                continue
            contract_id = f"notso_{folder.name}_{sol_file.stem}"
            vuln_types = [mapped]
            samples.append({
                "contract_id":        contract_id,
                "source_code":        source,
                "vuln_types":         vuln_types,
                "label_vector":       make_label_vector(vuln_types),
                "risk_score":         make_risk_score(vuln_types),
                "defi_category":      "general",
                "has_ground_truth":   True,
                "label_source":       "not_so_smart",
                "benchmark_composite": None,
                "split":              "train",
            })

    print(f"  Not-So-Smart-Contracts: {len(samples)} loaded, {skipped} skipped")
    return samples

def load_not_used() -> list[dict]:
    """Load not_used_for_training contracts  -  filename encodes vuln type."""
    base = DATASETS_DIR / "not_used_for_training"
    samples = []
    skipped = 0

    for sol_file in sorted(base.glob("*.sol")):
        # filename format: <vuln_type>__<contract_name>.sol
        stem = sol_file.stem
        if "__" not in stem:
            skipped += 1
            continue
        raw_type = stem.split("__")[0]
        mapped = {
            "reentrancy": "reentrancy",
            "arithmetic": "arithmetic",
            "access_control": "access_control",
            "unchecked_low_level_calls": "unchecked_low_level_calls",
            "denial_of_service": "denial_of_service",
            "front_running": "front_running",
            "bad_randomness": "bad_randomness",
            "time_manipulation": "front_running",
        }.get(raw_type)
        if mapped is None:
            skipped += 1
            continue

        source = read_sol(sol_file)
        if not source.strip():
            skipped += 1
            continue

        vuln_types = [mapped]
        samples.append({
            "contract_id":        f"smartbugs_extra_{stem}",
            "source_code":        source,
            "vuln_types":         vuln_types,
            "label_vector":       make_label_vector(vuln_types),
            "risk_score":         make_risk_score(vuln_types),
            "defi_category":      "general",
            "has_ground_truth":   True,
            "label_source":       "curated",
            "benchmark_composite": None,
            "split":              "train",
        })

    print(f"  not_used_for_training: {len(samples)} loaded, {skipped} skipped")
    return samples
NESTED_DATASETS = DATASETS_DIR / "evaluation" / "datasets"

# Slither detector folder → our taxonomy
SLITHER_DETECTOR_MAP = {
    "reentrancy-eth":           "reentrancy",
    "reentrancy-no-eth":        "reentrancy",
    "reentrancy-balance":       "reentrancy",
    "reentrancy-benign":        "reentrancy",
    "reentrancy-events":        "reentrancy",
    "divide-before-multiply":   "arithmetic",
    "incorrect-exp":            "arithmetic",
    "incorrect-shift":          "arithmetic",
    "arbitrary-send-eth":       "access_control",
    "arbitrary-send-erc20":     "access_control",
    "controlled-delegatecall":  "access_control",
    "unprotected-upgrade":      "access_control",
    "events-access":            "access_control",
    "unchecked-lowlevel":       "unchecked_low_level_calls",
    "unchecked-send":           "unchecked_low_level_calls",
    "unchecked-transfer":       "unchecked_low_level_calls",
    "locked-ether":             "denial_of_service",
    "calls-loop":               "denial_of_service",
    "gelato-unprotected-randomness": "bad_randomness",
}

# Ethernaut level filename → vuln type(s)
ETHERNAUT_MAP = {
    "Fallback":      ["access_control"],
    "Coin":          ["access_control"],
    "Telephone":     ["access_control"],
    "Token":         ["arithmetic"],
    "Delegation":    ["access_control"],
    "Force":         ["denial_of_service"],
    "Vault":         ["access_control"],
    "King":          ["denial_of_service"],
    "Reentrance":    ["reentrancy"],
    "Elevator":      ["access_control"],
    "Privacy":       ["access_control"],
    "GatekeeperOne": ["access_control"],
    "GatekeeperTwo": ["access_control"],
    "AlienCodex":    ["arithmetic"],
    "Denial":        ["denial_of_service"],
    "Locked":        ["access_control"],
    "NaughtCoin":    ["access_control"],
    "Recovery":      ["access_control"],
    "Dex":           ["price_manipulation"],
    "DexTwo":        ["price_manipulation"],
    "PuzzleWallet":  ["access_control"],
    "Motorbike":     ["access_control"],
    "DoubleEntryPoint": ["access_control"],
    "GoodSamaritan": ["unchecked_low_level_calls"],
    "CoinFlip":      ["bad_randomness"],
    "Switch":        ["access_control"],
    "HigherOrder":   ["access_control"],
    "Stake":         ["unchecked_low_level_calls"],
}

# Damn Vulnerable DeFi challenge dir → vuln type(s)
DVD_MAP = {
    "unstoppable":    ["flash_loan"],
    "naive-receiver": ["unchecked_low_level_calls"],
    "truster":        ["unchecked_low_level_calls"],
    "side-entrance":  ["reentrancy"],
    "the-rewarder":   ["flash_loan", "arithmetic"],
    "selfie":         ["flash_loan", "governance"],
    "compromised":    ["bad_randomness"],
    "puppet":         ["price_manipulation"],
    "puppet-v2":      ["price_manipulation"],
    "puppet-v3":      ["price_manipulation"],
    "free-rider":     ["reentrancy"],
    "backdoor":       ["access_control"],
    "climber":        ["access_control"],
    "shards":         ["arithmetic"],
    "curvy-puppet":   ["price_manipulation"],
    "abi-smuggling":  ["access_control"],
}

def load_slither_tests() -> list[dict]:
    """Load Slither detector test .sol files  -  folder name encodes vuln type."""
    base = NESTED_DATASETS / "slither-tests" / "tests" / "e2e" / "detectors" / "test_data"
    if not base.exists():
        print("  slither-tests: not found, skipping")
        return []
    samples = []
    skipped = 0

    for detector_dir, vuln_type in SLITHER_DETECTOR_MAP.items():
        dpath = base / detector_dir
        if not dpath.exists():
            continue
        for sol_file in sorted(dpath.rglob("*.sol")):
            source = read_sol(sol_file)
            if not source.strip():
                skipped += 1
                continue
            vuln_types = [vuln_type]
            contract_id = f"slither_{detector_dir}_{sol_file.stem}"
            samples.append({
                "contract_id":        contract_id,
                "source_code":        source,
                "vuln_types":         vuln_types,
                "label_vector":       make_label_vector(vuln_types),
                "risk_score":         make_risk_score(vuln_types),
                "defi_category":      "general",
                "has_ground_truth":   True,
                "label_source":       "slither_tests",
                "benchmark_composite": None,
                "split":              "train",
            })

    print(f"  Slither tests: {len(samples)} loaded, {skipped} skipped")
    return samples

def load_ethernaut() -> list[dict]:
    """Load Ethernaut CTF level contracts with manual vuln-type mapping."""
    levels_dir = NESTED_DATASETS / "ethernaut" / "contracts" / "src" / "levels"
    if not levels_dir.exists():
        print("  ethernaut: not found, skipping")
        return []
    samples = []
    skipped = 0

    for sol_file in sorted(levels_dir.glob("*.sol")):
        # skip Factory contracts
        if "Factory" in sol_file.stem:
            skipped += 1
            continue
        vuln_list = ETHERNAUT_MAP.get(sol_file.stem)
        if not vuln_list:
            skipped += 1
            continue
        source = read_sol(sol_file)
        if not source.strip():
            skipped += 1
            continue
        vuln_types = sorted(set(vuln_list))
        samples.append({
            "contract_id":        f"ethernaut_{sol_file.stem}",
            "source_code":        source,
            "vuln_types":         vuln_types,
            "label_vector":       make_label_vector(vuln_types),
            "risk_score":         make_risk_score(vuln_types),
            "defi_category":      "general",
            "has_ground_truth":   True,
            "label_source":       "ctf",
            "benchmark_composite": None,
            "split":              "train",
        })

    print(f"  Ethernaut: {len(samples)} loaded, {skipped} skipped")
    return samples

def load_dvd() -> list[dict]:
    """Load Damn Vulnerable DeFi src contracts."""
    src_dir = NESTED_DATASETS / "damn-vulnerable-defi" / "src"
    if not src_dir.exists():
        print("  damn-vulnerable-defi: not found, skipping")
        return []
    samples = []
    skipped = 0

    for challenge_dir, vuln_list in DVD_MAP.items():
        cpath = src_dir / challenge_dir
        if not cpath.exists():
            skipped += 1
            continue
        for sol_file in sorted(cpath.rglob("*.sol")):
            source = read_sol(sol_file)
            if not source.strip():
                skipped += 1
                continue
            vuln_types = sorted(set(vuln_list))
            contract_id = f"dvd_{challenge_dir}_{sol_file.stem}"
            samples.append({
                "contract_id":        contract_id,
                "source_code":        source,
                "vuln_types":         vuln_types,
                "label_vector":       make_label_vector(vuln_types),
                "risk_score":         make_risk_score(vuln_types),
                "defi_category":      "defi",
                "has_ground_truth":   True,
                "label_source":       "ctf",
                "benchmark_composite": None,
                "split":              "train",
            })

    print(f"  Damn Vulnerable DeFi: {len(samples)} loaded, {skipped} skipped")
    return samples

def load_web3bugs_clean(labeled_ids: set[str], max_clean: int = 600,
                        seed: int = 42) -> list[dict]:
    """Sample clean web3bugs contracts not in the labeled set as negative examples."""
    contracts_root = DATASETS_DIR / "web3bugs" / "contracts"
    if not contracts_root.exists():
        print("  web3bugs clean: contracts dir not found")
        return []

    rng = random.Random(seed)
    candidates = []
    for sol_file in contracts_root.rglob("*.sol"):
        parts = sol_file.relative_to(contracts_root).parts
        if not parts:
            continue
        contest = parts[0]
        stem = sol_file.stem
        cid = f"web3bugs_{contest}_{stem}"
        if cid in labeled_ids:
            continue  # skip vulnerable contracts
        # Skip obvious non-contracts (interfaces, libraries, mocks, tests)
        lower = stem.lower()
        if any(lower.startswith(p) for p in ("i", "mock", "test", "base", "abstract")):
            if lower[0] == "i" and stem[1:2].isupper():
                continue  # interface (e.g. IPool, IFoo)
        candidates.append((cid, sol_file))

    rng.shuffle(candidates)
    candidates = candidates[:max_clean]

    samples = []
    for cid, sol_file in candidates:
        source = read_sol(sol_file)
        if not source.strip():
            continue
        samples.append({
            "contract_id":        cid,
            "source_code":        source,
            "vuln_types":         [],
            "label_vector":       make_label_vector([]),
            "risk_score":         0.0,
            "defi_category":      "general",
            "has_ground_truth":   True,
            "label_source":       "web3bugs_clean",
            "benchmark_composite": None,
            "split":              "train",
        })

    print(f"  web3bugs clean (negative examples): {len(samples)} loaded from {len(candidates)} candidates")
    return samples

def load_selected_manifest() -> list[dict]:
    """Load selected/ contracts that have known_vulnerabilities in dataset_manifest.json."""
    manifest_path = LABELS_DIR / "dataset_manifest.json"
    selected_dir  = DATASETS_DIR / "selected"

    if not manifest_path.exists():
        print("  selected: manifest not found, skipping")
        return []

    with open(manifest_path) as f:
        manifest = json.load(f)

    samples = []
    skipped = 0

    for entry in manifest.get("contracts", []):
        vuln_list = entry.get("known_vulnerabilities") or []
        if not vuln_list:
            skipped += 1
            continue

        cid  = entry["id"]          # e.g. "amm_dex_001"
        fname = entry["filename"]   # e.g. "smart_billions.sol"
        sol_file = selected_dir / f"{cid}_{fname}"
        if not sol_file.exists():
            skipped += 1
            continue

        source = read_sol(sol_file)
        if not source.strip():
            skipped += 1
            continue

        vuln_types = sorted(set(
            v for v in vuln_list if v in LABEL_TO_IDX
        ))
        if not vuln_types:
            skipped += 1
            continue

        samples.append({
            "contract_id":        f"selected_{cid}_{Path(fname).stem}",
            "source_code":        source,
            "vuln_types":         vuln_types,
            "label_vector":       make_label_vector(vuln_types),
            "risk_score":         make_risk_score(vuln_types),
            "defi_category":      entry.get("defi_category", "general"),
            "has_ground_truth":   True,
            "label_source":       "manifest",
            "benchmark_composite": None,
            "split":              "train",
        })

    print(f"  selected (manifest): {len(samples)} loaded, {skipped} skipped")
    return samples
# Column name → our taxonomy (arithmetic excluded  -  too noisy in this source)
SMARTVULN_COL_MAP = {
    "reentrancy":         "reentrancy",
    "unchecked_low_calls": "unchecked_low_level_calls",
    "access_control":     "access_control",
    "denial_service":     "denial_of_service",
    "time_manipulation":  "front_running",
    "front_running":      "front_running",
}

def load_smartvuln_csv(csv_path: Path, threshold: int = 2,
                       max_per_class: int = 1500, seed: int = 42) -> list[dict]:
    """Load prime-smartvuln CSV.

    Labels are tool-vote counts. threshold=2 means >=2 tools agree → positive.
    Arithmetic column is excluded (57% positive rate  -  too noisy for old Solidity).
    """
    import csv as _csv
    _csv.field_size_limit(2**30)

    if not csv_path.exists():
        print(f"  prime-smartvuln: {csv_path} not found, skipping")
        return []

    rng = random.Random(seed)
    vuln_cols = list(SMARTVULN_COL_MAP.keys())
    all_other_cols = ["Other"]  # used only for clean detection

    with open(csv_path, errors="replace") as f:
        rows = list(_csv.DictReader(f))

    # Partition: vulnerable vs fully clean
    vulnerable_rows = []
    clean_rows = []
    for r in rows:
        vuln_types = [
            SMARTVULN_COL_MAP[col]
            for col in vuln_cols
            if int(r.get(col, 0)) >= threshold
        ]
        if vuln_types:
            vulnerable_rows.append((r, sorted(set(vuln_types))))
        elif all(int(r.get(c, 0)) == 0 for c in vuln_cols + all_other_cols + ["arithmetic"]):
            clean_rows.append(r)

    # Balance per class  -  cap at max_per_class to avoid overwhelming other sources
    class_buckets: dict[str, list] = {}
    for r, vtypes in vulnerable_rows:
        primary = vtypes[0]
        class_buckets.setdefault(primary, []).append((r, vtypes))

    samples = []

    for primary, bucket in class_buckets.items():
        rng.shuffle(bucket)
        for r, vuln_types in bucket[:max_per_class]:
            code = r.get("sourcecode", "")[:MAX_SOURCE_CHARS]
            if not code.strip():
                continue
            addr = r.get("address", "unknown")
            safe_addr = addr.replace("0x", "").lower()[:16]
            contract_id = f"smartvuln_{safe_addr}"
            samples.append({
                "contract_id":        contract_id,
                "source_code":        code,
                "vuln_types":         vuln_types,
                "label_vector":       make_label_vector(vuln_types),
                "risk_score":         make_risk_score(vuln_types),
                "defi_category":      "general",
                "has_ground_truth":   True,
                "label_source":       "smartvuln",
                "benchmark_composite": None,
                "split":              "train",
            })

    # Add capped clean samples (already have web3bugs clean  -  limit these)
    rng.shuffle(clean_rows)
    for r in clean_rows[:500]:
        code = r.get("sourcecode", "")[:MAX_SOURCE_CHARS]
        if not code.strip():
            continue
        addr = r.get("address", "unknown")
        safe_addr = addr.replace("0x", "").lower()[:16]
        samples.append({
            "contract_id":        f"smartvuln_clean_{safe_addr}",
            "source_code":        code,
            "vuln_types":         [],
            "label_vector":       make_label_vector([]),
            "risk_score":         0.0,
            "defi_category":      "general",
            "has_ground_truth":   True,
            "label_source":       "smartvuln",
            "benchmark_composite": None,
            "split":              "train",
        })

    per_class = {k: min(len(v), max_per_class) for k, v in class_buckets.items()}
    print(f"  prime-smartvuln: {len(samples)} loaded | per class: {per_class} | clean: {min(len(clean_rows), 500)}")
    return samples

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--train-frac", type=float, default=0.70)
    parser.add_argument("--val-frac",   type=float, default=0.15)
    parser.add_argument("--seed",       type=int,   default=42)
    parser.add_argument("--smartvuln",  type=Path,
                        default=Path("/tmp/smartvuln/multilabel_BILSTM_BERT.csv"),
                        help="Path to prime-smartvuln CSV (optional)")
    args = parser.parse_args()

    out_path = args.output or (EVAL_DIR / "llm_training" / "data" / "dataset_v2.json")

    print("Building dataset_v2 ...\n")

    all_samples: list[dict] = []

    # 1. SmartBugs curated  -  all 143
    all_samples += load_smartbugs()

    # 2. Prime-SmartVuln (45K real Ethereum contracts, tool-vote labels)
    all_samples += load_smartvuln_csv(args.smartvuln, threshold=2, max_per_class=1500, seed=args.seed)

    # Deduplicate by contract_id
    seen_ids: set[str] = set()
    unique: list[dict] = []
    for s in all_samples:
        if s["contract_id"] not in seen_ids:
            seen_ids.add(s["contract_id"])
            unique.append(s)
    print(f"\nTotal before split: {len(unique)} (deduplicated from {len(all_samples)})")

    # Stratified train/val/test split
    unique = stratified_split(unique, args.train_frac, args.val_frac, args.seed)

    split_counts  = Counter(s["split"] for s in unique)
    source_counts = Counter(s["label_source"] for s in unique)
    train_vulns: Counter = Counter()
    for s in unique:
        if s["split"] == "train":
            for v in s["vuln_types"]:
                train_vulns[v] += 1

    print(f"\nDataset summary:")
    print(f"  Total  : {len(unique)}")
    print(f"  Train  : {split_counts['train']}")
    print(f"  Val    : {split_counts['val']}")
    print(f"  Test   : {split_counts['test']}")
    print(f"\nLabel sources:")
    for src, n in sorted(source_counts.items()):
        print(f"  {src:<30} {n}")
    print(f"\nVulnerability distribution (training set):")
    for label in VULN_LABELS:
        n = train_vulns.get(label, 0)
        bar = "█" * min(n, 50)
        print(f"  {label:<30} {n:3d}  {bar}")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    label_counts = {}
    for s in unique:
        for v in s["vuln_types"]:
            label_counts[v] = label_counts.get(v, 0) + 1

    out_doc = {
        "version":      "v2",
        "vuln_labels":  VULN_LABELS,
        "n_labels":     len(VULN_LABELS),
        "n_total":      len(unique),
        "n_train":      split_counts["train"],
        "n_val":        split_counts["val"],
        "n_test":       split_counts["test"],
        "label_counts": label_counts,
        "sources":      dict(source_counts),
        "samples":      unique,
    }
    out_path.write_text(json.dumps(out_doc, indent=2))

    size_kb = out_path.stat().st_size / 1024
    print(f"\nSaved to: {out_path}  ({size_kb:.0f} KB)")
    print("\nNext step: upload dataset_v2.json to Google Colab and retrain CodeBERT.")
if __name__ == "__main__":
    main()
