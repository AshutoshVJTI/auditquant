"""
Dataset builder for CodeBERT fine-tuning.
Reads SmartBugs Curated contracts and outputs dataset_v2.json with 70/15/15 split.
"""
import json
import re
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

# Label schema

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

N_LABELS: int = len(VULN_LABELS)
LABEL_TO_IDX: dict[str, int] = {v: i for i, v in enumerate(VULN_LABELS)}

# Inline annotation keyword → canonical label
ANNOTATION_MAP: dict[str, str] = {
    "REENTRANCY": "reentrancy",
    "ARITHMETIC": "arithmetic",
    "ACCESS_CONTROL": "access_control",
    "UNCHECKED_LL_CALLS": "unchecked_low_level_calls",
    "UNCHECKED_LOW_LEVEL_CALLS": "unchecked_low_level_calls",
    "DENIAL_OF_SERVICE": "denial_of_service",
    "FRONT_RUNNING": "front_running",
    "TRANSACTION_ORDER_DEPENDENCE": "front_running",
    "BAD_RANDOMNESS": "bad_randomness",
    "TIME_MANIPULATION": "front_running",
    "TIMESTAMP": "front_running",
    "SUICIDAL": "access_control",
    "LEAKING_ETHER": "unchecked_low_level_calls",
    "FLASH_LOAN": "flash_loan",
    "PRICE_MANIPULATION": "price_manipulation",
    "LIQUIDATION": "liquidation",
    "REWARD_MANIPULATION": "reward_manipulation",
    "SHARE_MANIPULATION": "share_manipulation",
    "GOVERNANCE": "governance",
}

# Per-vulnerability base risk weight (0–1, reflects financial severity in DeFi context)
RISK_WEIGHTS: dict[str, float] = {
    "reentrancy":               0.90,
    "flash_loan":               0.88,
    "price_manipulation":       0.85,
    "liquidation":              0.82,
    "share_manipulation":       0.80,
    "access_control":           0.75,
    "reward_manipulation":      0.75,
    "governance":               0.72,
    "arithmetic":               0.70,
    "bad_randomness":           0.65,
    "front_running":            0.62,
    "unchecked_low_level_calls": 0.60,
    "denial_of_service":        0.55,
}

MAX_SOURCE_CHARS = 6000   # ~500–800 BPE tokens; fits CodeBERT's 512-token limit

# Data structures

@dataclass
class Sample:
    contract_id: str
    source_code: str            # truncated to MAX_SOURCE_CHARS
    label_vector: list[int]     # len(VULN_LABELS), multi-hot binary
    risk_score: float           # 0–1 regression target
    vuln_types: list[str]       # canonical vulnerability type names
    defi_category: str
    split: str                  # "train" | "val" | "test"
    has_ground_truth: bool
    label_source: str           # "manifest" | "inline" | "combined" | "none"
    benchmark_composite: float | None = None   # tool-measured composite if available

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
# Label helpers

def _parse_inline_annotations(source: str) -> list[str]:
    found: set[str] = set()
    for m in re.finditer(r"//\s*<yes>\s*<report>\s*(\w+)", source, re.IGNORECASE):
        canonical = ANNOTATION_MAP.get(m.group(1).upper())
        if canonical:
            found.add(canonical)
    return sorted(found)
def _derive_risk_score(vuln_types: list[str]) -> float:
    if not vuln_types:
        return 0.0
    weights = [RISK_WEIGHTS.get(v, 0.5) for v in vuln_types]
    # max captures worst-case; mean captures vulnerability breadth
    return round(max(weights) * 0.6 + (sum(weights) / len(weights)) * 0.4, 4)
def _build_label_vector(vuln_types: list[str]) -> list[int]:
    vec = [0] * N_LABELS
    for vt in vuln_types:
        idx = LABEL_TO_IDX.get(vt)
        if idx is not None:
            vec[idx] = 1
    return vec
# Benchmark risk score lookup

def _load_benchmark_composites(results_dir: Path) -> dict[str, float]:
    """
    Load composite risk scores keyed by contract_id from the most recent
    benchmark_real_recomputed_*.json result file.
    """
    files = sorted(results_dir.glob("benchmark_real_recomputed_*.json"),
                   key=lambda p: p.stat().st_mtime)
    if not files:
        files = sorted(results_dir.glob("benchmark_real_*.json"),
                       key=lambda p: p.stat().st_mtime)
    if not files:
        return {}
    with files[-1].open() as f:
        data = json.load(f)
    composites: dict[str, float] = {}
    for entry in data.get("results", []):
        cid = entry.get("contract_id", "")
        # composite = weighted blend of r_sast + r_dast + r_comp
        r_sast = entry.get("r_sast", 0.0) or 0.0
        r_dast = entry.get("r_dast", 0.0) or 0.0
        r_comp = entry.get("r_comp", 0.0) or 0.0
        composite = 0.5 * r_sast + 0.3 * r_dast + 0.2 * r_comp
        # normalise to 0-1 (scores are already 0-1 from engine.py)
        composites[cid] = round(min(max(composite, 0.0), 1.0), 4)
    return composites
# Stratified split

def _stratified_split(
    samples: list[Sample],
    train_frac: float = 0.70,
    val_frac: float = 0.15,
    seed: int = 42,
    benchmark_fingerprints: set[str] | None = None,
) -> list[Sample]:
    """
    benchmark_fingerprints: set of source[:500] strings for contracts used in the
    external benchmark evaluation set.  Any sample whose fingerprint matches is
    forced into the test split so CodeBERT is never trained on evaluation contracts.
    """
    import random
    rng = random.Random(seed)

    # Separate benchmark contracts before stratification
    forced_test: list[Sample] = []
    remaining: list[Sample] = []
    if benchmark_fingerprints:
        for s in samples:
            fp = s.source_code[:500].strip()
            if fp in benchmark_fingerprints:
                forced_test.append(s)
            else:
                remaining.append(s)
    else:
        remaining = samples

    groups: dict[str, list[Sample]] = defaultdict(list)
    for s in remaining:
        primary = s.vuln_types[0] if s.vuln_types else "none"
        groups[primary].append(s)

    train_list: list[Sample] = []
    val_list:   list[Sample] = []
    test_list:  list[Sample] = []

    for grp in groups.values():
        rng.shuffle(grp)
        n = len(grp)
        if n == 1:
            train_list.extend(grp)
            continue
        n_val  = max(1, round(n * val_frac))
        n_test = max(1, round(n * (1.0 - train_frac - val_frac)))
        # ensure at least one training sample per group
        n_test  = min(n_test,  n - n_val - 1)
        n_train = n - n_val - n_test

        train_list.extend(grp[:n_train])
        val_list.extend(grp[n_train:n_train + n_val])
        test_list.extend(grp[n_train + n_val:])

    for s in train_list:  s.split = "train"
    for s in val_list:    s.split = "val"
    for s in test_list:   s.split = "test"
    for s in forced_test: s.split = "test"

    return train_list + val_list + test_list + forced_test
# SmartBugs directory loader

# SmartBugs category directory name → canonical label
SMARTBUGS_CATEGORY_MAP: dict[str, str] = {
    "reentrancy":               "reentrancy",
    "arithmetic":               "arithmetic",
    "access_control":           "access_control",
    "unchecked_low_level_calls": "unchecked_low_level_calls",
    "denial_of_service":        "denial_of_service",
    "front_running":            "front_running",
    "bad_randomness":           "bad_randomness",
    "time_manipulation":        "front_running",  # timestamp attacks map to front_running
    "other":                    "",               # skip  -  no reliable label
}
def _load_smartbugs_dir(
    smartbugs_dir: Path,
    existing_filenames: set[str],
    benchmark_composites: dict[str, float],
) -> list[Sample]:
    """
    Walk smartbugs-curated/dataset/<category>/*.sol and create Sample objects.
    Skips any filename already covered by existing_filenames (from the manifest).
    The directory name provides the ground-truth vulnerability label; inline
    annotations are also parsed for additional labels.
    """
    dataset_dir = smartbugs_dir / "dataset"
    if not dataset_dir.exists():
        return []

    samples: list[Sample] = []
    for cat_dir in sorted(dataset_dir.iterdir()):
        if not cat_dir.is_dir():
            continue
        canonical = SMARTBUGS_CATEGORY_MAP.get(cat_dir.name, "")
        if not canonical:
            continue  # "other" category  -  no usable label

        for sol_file in sorted(cat_dir.glob("*.sol")):
            if sol_file.name in existing_filenames:
                continue  # already in manifest

            source = sol_file.read_text(encoding="utf-8", errors="replace")
            source_trunc = source[:MAX_SOURCE_CHARS]

            dir_vulns = [canonical]
            inline_vulns = _parse_inline_annotations(source)
            combined = list(dict.fromkeys(dir_vulns + inline_vulns))
            combined = [v for v in combined if v in LABEL_TO_IDX]

            if not combined:
                continue

            cid = f"sb_{cat_dir.name}_{sol_file.stem}"
            label_source = "combined" if inline_vulns else "manifest"

            samples.append(Sample(
                contract_id=cid,
                source_code=source_trunc,
                label_vector=_build_label_vector(combined),
                risk_score=benchmark_composites.get(cid) or _derive_risk_score(combined),
                vuln_types=combined,
                defi_category="other",
                split="train",
                has_ground_truth=True,
                label_source=label_source,
                benchmark_composite=benchmark_composites.get(cid),
            ))

    return samples
# Main builder

def build_dataset(
    manifest_path: Path | None = None,
    selected_dir: Path | None = None,
    smartbugs_dir: Path | None = None,
    results_dir: Path | None = None,
    train_frac: float = 0.70,
    val_frac: float = 0.15,
    seed: int = 42,
    labeled_only: bool = True,
    benchmark_dir: Path | None = None,
) -> list[Sample]:
    """
    Build the full sample list with train/val/test splits assigned.

    Parameters
    ----------
    smartbugs_dir : Path | None
        Path to the smartbugs-curated repo root (contains a ``dataset/`` subdirectory).
        If provided and the directory exists, all 256 SmartBugs contracts are
        loaded in addition to the manifest entries.  New contracts (not already in
        the manifest by filename) are added; the directory name supplies the
        ground-truth vulnerability label.
    benchmark_dir : Path | None
        Directory containing the external benchmark evaluation contracts (*.sol).
        Any training sample whose source code matches a benchmark contract is
        forced into the test split so CodeBERT is never trained on contracts it
        will later be evaluated against.
    labeled_only : bool
        If True (default), only include contracts that have at least one
        vulnerability label from the manifest or inline annotations.
    """
    eval_dir = Path(__file__).resolve().parents[1]
    if manifest_path is None:
        manifest_path = eval_dir / "labels" / "dataset_manifest.json"
    if selected_dir is None:
        selected_dir = eval_dir / "datasets" / "selected"
    if smartbugs_dir is None:
        smartbugs_dir = eval_dir / "datasets" / "smartbugs-curated"
    if results_dir is None:
        results_dir = eval_dir / "results"

    with manifest_path.open() as f:
        manifest = json.load(f)

    benchmark_composites = _load_benchmark_composites(results_dir)

    samples: list[Sample] = []
    manifest_filenames: set[str] = set()

    for entry in manifest["contracts"]:
        cid = entry["id"]
        filename = entry.get("filename", "")
        manifest_filenames.add(filename)

        sol_path = Path(entry.get("selected_path", ""))
        if not sol_path.exists():
            sol_path = selected_dir / f"{cid}_{filename}"
        if not sol_path.exists():
            continue

        source = sol_path.read_text(encoding="utf-8", errors="replace")
        source_trunc = source[:MAX_SOURCE_CHARS]

        # Collect labels
        manifest_vulns: list[str] = [
            v.lower().replace(" ", "_")
            for v in entry.get("known_vulnerabilities", [])
            if v
        ]
        inline_vulns: list[str] = _parse_inline_annotations(source)

        combined: list[str] = list(dict.fromkeys(manifest_vulns + inline_vulns))
        combined = [v for v in combined if v in LABEL_TO_IDX]

        label_source = (
            "combined"  if (manifest_vulns and inline_vulns) else
            "manifest"  if manifest_vulns else
            "inline"    if inline_vulns else
            "none"
        )

        if labeled_only and not combined:
            continue

        risk = benchmark_composites.get(cid) or _derive_risk_score(combined)

        samples.append(Sample(
            contract_id=cid,
            source_code=source_trunc,
            label_vector=_build_label_vector(combined),
            risk_score=risk,
            vuln_types=combined,
            defi_category=entry.get("defi_category", "other"),
            split="train",
            has_ground_truth=bool(entry.get("has_ground_truth")),
            label_source=label_source,
            benchmark_composite=benchmark_composites.get(cid),
        ))

    # Augment with full SmartBugs-curated directory
    if smartbugs_dir.exists():
        sb_samples = _load_smartbugs_dir(smartbugs_dir, manifest_filenames, benchmark_composites)
        samples.extend(sb_samples)

    # Build benchmark fingerprints to prevent train/val contamination
    bench_fps: set[str] | None = None
    if benchmark_dir is None:
        benchmark_dir = eval_dir / "datasets" / "selected"
    if benchmark_dir.exists():
        bench_fps = {
            p.read_text(encoding="utf-8", errors="replace")[:500].strip()
            for p in benchmark_dir.glob("*.sol")
        }

    return _stratified_split(
        samples,
        train_frac=train_frac,
        val_frac=val_frac,
        seed=seed,
        benchmark_fingerprints=bench_fps,
    )
# JSON export

def export_json(samples: list[Sample], output_path: Path | None = None) -> Path:
    """
    Serialise the dataset to a self-contained JSON file suitable for upload
    to Google Colab (no file-path dependencies).
    """
    import datetime
    eval_dir = Path(__file__).resolve().parents[1]
    if output_path is None:
        data_dir = eval_dir / "llm_training" / "data"
        data_dir.mkdir(parents=True, exist_ok=True)
        output_path = data_dir / "dataset.json"

    split_counts = defaultdict(int)
    for s in samples:
        split_counts[s.split] += 1

    label_counts: dict[str, int] = defaultdict(int)
    for s in samples:
        for vt in s.vuln_types:
            label_counts[vt] += 1

    payload = {
        "version": "1.0",
        "created_at": datetime.datetime.utcnow().isoformat() + "Z",
        "vuln_labels": VULN_LABELS,
        "n_labels": N_LABELS,
        "n_total": len(samples),
        "n_train": split_counts["train"],
        "n_val":   split_counts["val"],
        "n_test":  split_counts["test"],
        "label_counts": dict(sorted(label_counts.items(), key=lambda x: -x[1])),
        "samples": [s.to_dict() for s in samples],
    }

    with output_path.open("w") as f:
        json.dump(payload, f, indent=2)

    return output_path
def load_json(path: Path) -> tuple[list[Sample], dict[str, Any]]:
    """Load a dataset exported by export_json(); returns (samples, meta)."""
    with path.open() as f:
        payload = json.load(f)
    samples = [Sample(**s) for s in payload["samples"]]
    meta = {k: v for k, v in payload.items() if k != "samples"}
    return samples, meta
