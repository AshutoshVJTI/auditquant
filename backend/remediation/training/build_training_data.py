#!/usr/bin/env python3
"""
Build fine-tuning data from the knowledge base.

Reads knowledge_base.json and produces:
  - data/train.jsonl  (90 %)
  - data/eval.jsonl   (10 %)
  - data/swc_context.json   (for LLM prompt enrichment)

Each JSONL line: {"input": "fix <vuln_type>: <code>", "target": "<fixed_code>"}
"""
from __future__ import annotations

import json
import random
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DIR = SCRIPT_DIR / "data"
KB_PATH = DATA_DIR / "knowledge_base.json"

SEED = 42
EVAL_RATIO = 0.10


def _normalise_code(code: str) -> str:
    """Remove excessive blank lines while keeping structure."""
    lines = code.strip().splitlines()
    cleaned: list[str] = []
    prev_blank = False
    for line in lines:
        is_blank = line.strip() == ""
        if is_blank and prev_blank:
            continue
        cleaned.append(line)
        prev_blank = is_blank
    return "\n".join(cleaned)


def build_code_pairs(kb: dict) -> list[dict[str, str]]:
    """Create input→target pairs from entries that have both vuln and fix."""
    pairs: list[dict[str, str]] = []
    for entry in kb["entries"]:
        vuln_samples = entry.get("vulnerable_samples", [])
        fix_samples = entry.get("fixed_samples", [])
        if not vuln_samples or not fix_samples:
            continue

        vuln_type = entry.get("title", "unknown")
        swc_id = entry.get("swc_id") or ""

        # Pair up by index; if counts differ, cycle shorter list
        max_len = max(len(vuln_samples), len(fix_samples))
        for i in range(max_len):
            vuln = vuln_samples[i % len(vuln_samples)]
            fix = fix_samples[i % len(fix_samples)]

            vuln_code = _normalise_code(vuln["code"])
            fix_code = _normalise_code(fix["code"])

            if vuln_code == fix_code:
                continue

            prefix = f"fix {vuln_type}"
            if swc_id:
                prefix = f"fix {swc_id} {vuln_type}"

            pairs.append({
                "input": f"{prefix}:\n{vuln_code}",
                "target": fix_code,
            })

    return pairs


def build_swc_context(kb: dict) -> list[dict]:
    """Build a lookup table of SWC context for LLM prompt enrichment."""
    context_entries: list[dict] = []
    for entry in kb["entries"]:
        swc_id = entry.get("swc_id")
        if not swc_id:
            continue
        context_entries.append({
            "swc_id": swc_id,
            "title": entry["title"],
            "cwe_id": entry.get("cwe_id"),
            "description": entry.get("description", ""),
            "remediation": entry.get("remediation", ""),
            "vuln_type": entry["title"].lower().replace(" ", "-"),
        })
    return context_entries


def main() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    with open(KB_PATH) as f:
        kb = json.load(f)

    # --- Code pairs for fine-tuning ---
    pairs = build_code_pairs(kb)
    print(f"Total code pairs: {len(pairs)}")

    random.seed(SEED)
    random.shuffle(pairs)

    split = max(1, int(len(pairs) * EVAL_RATIO))
    eval_pairs = pairs[:split]
    train_pairs = pairs[split:]

    train_path = DATA_DIR / "train.jsonl"
    eval_path = DATA_DIR / "eval.jsonl"

    for path, data in [(train_path, train_pairs), (eval_path, eval_pairs)]:
        with open(path, "w") as f:
            for item in data:
                f.write(json.dumps(item, ensure_ascii=False) + "\n")
        print(f"  Wrote {len(data)} pairs → {path.name}")

    # --- SWC context for LLM enrichment ---
    swc_ctx = build_swc_context(kb)
    ctx_path = DATA_DIR / "swc_context.json"
    with open(ctx_path, "w") as f:
        json.dump(swc_ctx, f, indent=2, ensure_ascii=False)
    print(f"  Wrote {len(swc_ctx)} SWC context entries → {ctx_path.name}")


if __name__ == "__main__":
    main()
