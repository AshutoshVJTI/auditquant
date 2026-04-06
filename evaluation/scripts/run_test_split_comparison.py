#!/usr/bin/env python3
"""
Runs AuditQuant, CodeBERT, GPT-4o, Claude, and Gemini on the 929-contract
held-out test split from dataset_v2.json and computes P/R/F1.

Usage:
    python evaluation/scripts/run_test_split_comparison.py
    python evaluation/scripts/run_test_split_comparison.py --skip-llm
    python evaluation/scripts/run_test_split_comparison.py --skip-tools
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

EVAL_DIR     = Path(__file__).resolve().parents[1]
PROJECT_ROOT = EVAL_DIR.parent
RESULTS_DIR  = EVAL_DIR / "results"
DATASET_PATH = EVAL_DIR / "llm_training" / "data" / "dataset_v2.json"
LLM_EVAL_PATH = RESULTS_DIR / "llm_eval.json"

sys.path.insert(0, str(PROJECT_ROOT / "backend"))

try:
    from dotenv import load_dotenv
    load_dotenv(PROJECT_ROOT / ".env")
except ImportError:
    pass  # keys already in environment

VULN_TYPES = [
    "reentrancy",
    "arithmetic",
    "access_control",
    "unchecked_low_level_calls",
    "denial_of_service",
    "front_running",
    "bad_randomness",
    "price_manipulation",
]

TOOL_TYPE_MAP: dict[str, str] = {
    "reentrancy": "reentrancy", "reentrancy-eth": "reentrancy",
    "reentrancy-no-eth": "reentrancy", "reentrancy-benign": "reentrancy",
    "reentrancy-events": "reentrancy", "external-call": "reentrancy",
    "dao": "reentrancy", "state-access-after-external-call": "reentrancy",
    "multiple-calls-in-a-single-transaction": "reentrancy",
    "pess-balancer-readonly-reentrancy": "reentrancy",
    "pess-curve-readonly-reentrancy": "reentrancy",
    "pess-inconsistent-nonreentrant": "reentrancy",
    "arithmetic": "arithmetic", "integer-overflow": "arithmetic",
    "integer-underflow": "arithmetic", "overflow": "arithmetic",
    "underflow": "arithmetic", "divide-before-multiply": "arithmetic",
    "tautology": "arithmetic", "incorrect-equality": "arithmetic",
    "assert-violation": "arithmetic", "integer-arithmetic-bugs": "arithmetic",
    "exception-state": "arithmetic", "pess-dubious-typecast": "arithmetic",
    "pess-potential-arithmetic-overflow": "arithmetic",
    "sol-integer-overflow-add": "arithmetic", "sol-integer-overflow-sub": "arithmetic",
    "sol-integer-overflow-mul": "arithmetic", "sol-integer-add-assign": "arithmetic",
    "sol-integer-sub-assign": "arithmetic", "sol-integer-mul-assign": "arithmetic",
    "sol-unchecked-block": "arithmetic",
    "access-control": "access_control", "arbitrary-send": "access_control",
    "arbitrary-send-eth": "access_control", "suicidal": "access_control",
    "tx-origin": "access_control", "unprotected-upgrade": "access_control",
    "incorrect-modifier": "access_control", "missing-zero-check": "access_control",
    "unprotected-ether-withdrawal": "access_control",
    "delegatecall-to-user-supplied-address": "access_control",
    "write-to-arbitrary-storage": "access_control",
    "external-call-to-user-supplied-address": "access_control",
    "weak-prng": "access_control", "pess-unprotected-initialize": "access_control",
    "pess-unprotected-setter": "access_control", "pess-only-eoa-check": "access_control",
    "pess-call-forward-to-protected": "access_control", "pess-ecrecover": "access_control",
    "pess-strange-setter": "access_control", "sol-tx-origin-auth": "access_control",
    "sol-delegatecall": "access_control", "sol-selfdestruct": "access_control",
    "sol-suicide": "access_control", "sol-assembly": "access_control",
    "unchecked-lowlevel": "unchecked_low_level_calls",
    "unchecked-send": "unchecked_low_level_calls",
    "unchecked-transfer": "unchecked_low_level_calls",
    "unused-return": "unchecked_low_level_calls",
    "unchecked-call": "unchecked_low_level_calls",
    "unchecked-low-level-calls": "unchecked_low_level_calls",
    "pess-double-entry-token-alert": "unchecked_low_level_calls",
    "sol-unchecked-send": "unchecked_low_level_calls",
    "sol-unchecked-transfer": "unchecked_low_level_calls",
    "denial-of-service": "denial_of_service", "dos": "denial_of_service",
    "calls-loop": "denial_of_service", "controlled-array-length": "denial_of_service",
    "cache-array-length": "denial_of_service",
    "front-running": "front_running", "timestamp": "front_running",
    "block-timestamp": "front_running", "time-manipulation": "front_running",
    "transaction-order-dependency": "front_running",
    "transaction-order-dependence": "front_running", "tod": "front_running",
    "dependence-on-predictable-environment-variable": "front_running",
    "pess-tx-gasprice": "front_running", "sol-blockhash-randomness": "front_running",
    "sol-block-timestamp": "front_running",
    "bad-randomness": "bad_randomness", "weak-randomness": "bad_randomness",
    "bad-prng": "bad_randomness",
    "price-manipulation": "price_manipulation", "oracle-manipulation": "price_manipulation",
    "oracle": "price_manipulation", "price-oracle": "price_manipulation",
    "pess-price-manipulation": "price_manipulation", "pess-uni-v2": "price_manipulation",
}

def _norm_tool(t: str) -> str | None:
    key = t.lower().strip().replace("_", "-")
    return TOOL_TYPE_MAP.get(key) or TOOL_TYPE_MAP.get(key.replace("-", "_"))

def run_slither_local(source_code: str, timeout: int = 60) -> set[str]:
    """Write source to temp file, run slither, return normalised vuln types."""
    with tempfile.NamedTemporaryFile(suffix=".sol", mode="w", delete=False) as f:
        f.write(source_code)
        tmp = f.name
    try:
        result = subprocess.run(
            ["slither", tmp, "--json", "-", "--solc-disable-warnings",
             "--disable-color", "--exclude-informational", "--exclude-low"],
            capture_output=True, timeout=timeout,
        )
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            # Try to extract JSON from mixed output
            text = result.stdout.decode(errors="replace")
            m = re.search(r'\{[\s\S]*\}', text)
            if not m:
                return set()
            try:
                data = json.loads(m.group())
            except json.JSONDecodeError:
                return set()

        detectors = data.get("results", {}).get("detectors", [])
        vulns: set[str] = set()
        for d in detectors:
            check = d.get("check", "")
            norm = _norm_tool(check)
            if norm:
                vulns.add(norm)
        return vulns
    except subprocess.TimeoutExpired:
        return set()
    except Exception:
        return set()
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass

LLM_SYSTEM = (
    "You are an expert smart contract security auditor specialising in Solidity vulnerability detection."
)

LLM_TEMPLATE = """\
Analyse this Solidity smart contract for security vulnerabilities.

Return a JSON object with EXACTLY this structure (no markdown, no extra text):
{{
  "vulnerabilities": [
    {{"type": "<category>", "severity": "<critical|high|medium|low>", "description": "<brief>"}}
  ]
}}

Use ONLY these vulnerability categories (exact strings):
{vuln_list}

If no vulnerabilities, return {{"vulnerabilities": []}}.

Contract:
```solidity
{code}
```"""

def _build_prompt(source: str) -> str:
    code = source[:12000]
    if len(source) > 12000:
        code += "\n// ... (truncated)"
    return LLM_TEMPLATE.format(
        vuln_list="\n".join(f"  - {v}" for v in VULN_TYPES),
        code=code,
    )

def _parse_llm(raw: str) -> list[str]:
    raw = re.sub(r"```(?:json)?\s*", "", raw).strip()
    raw = re.sub(r"```\s*$", "", raw).strip()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        m = re.search(r'\{[\s\S]*\}', raw)
        if not m:
            return []
        try:
            data = json.loads(m.group())
        except json.JSONDecodeError:
            return []
    result = []
    for v in data.get("vulnerabilities", []):
        t = v.get("type", "").lower().strip().replace("-", "_").replace(" ", "_")
        if t in VULN_TYPES and t not in result:
            result.append(t)
    return result

def call_gpt(source: str, key: str) -> list[str]:
    from openai import OpenAI
    model = os.environ.get("OPENAI_MODEL", "gpt-4o")
    client = OpenAI(api_key=key)
    raw = client.chat.completions.create(
        model=model,
        messages=[{"role": "system", "content": LLM_SYSTEM},
                  {"role": "user",   "content": _build_prompt(source)}],
        temperature=0.0, max_tokens=1024,
        response_format={"type": "json_object"},
    ).choices[0].message.content or ""
    return _parse_llm(raw)

def call_claude(source: str, key: str) -> list[str]:
    import anthropic
    model = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-6")
    client = anthropic.Anthropic(api_key=key)
    msg = client.messages.create(
        model=model, max_tokens=1024,
        system=LLM_SYSTEM,
        messages=[{"role": "user", "content": _build_prompt(source)}],
    )
    raw = msg.content[0].text if msg.content else ""
    return _parse_llm(raw)

def call_gemini(source: str, key: str) -> list[str]:
    from google import genai
    from google.genai import types as gt
    model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
    client = genai.Client(api_key=key)
    r = client.models.generate_content(
        model=model,
        contents=_build_prompt(source),
        config=gt.GenerateContentConfig(
            system_instruction=LLM_SYSTEM, temperature=0.0, max_output_tokens=1024,
            response_mime_type="application/json",
            thinking_config=gt.ThinkingConfig(thinking_budget=0),
        ),
    )
    return _parse_llm(r.text if hasattr(r, "text") else "")

def _tpfpfn(pred: set, gt: set) -> tuple[int, int, int]:
    return len(pred & gt), len(pred - gt), len(gt - pred)

def aggregate_metrics(rows: list[dict], system: str) -> dict:
    tp = fp = fn = 0
    per_type: dict[str, dict] = {v: {"tp": 0, "fp": 0, "fn": 0} for v in VULN_TYPES}
    for row in rows:
        gt   = set(row["ground_truth"])
        pred = set(row.get(system, {}).get("detected", []))
        t, f, n = _tpfpfn(pred, gt)
        tp += t; fp += f; fn += n
        for v in VULN_TYPES:
            if v in pred and v in gt:
                per_type[v]["tp"] += 1
            elif v in pred:
                per_type[v]["fp"] += 1
            elif v in gt:
                per_type[v]["fn"] += 1

    p  = tp / (tp + fp) if tp + fp else 0
    r  = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * p * r / (p + r) if p + r else 0

    pvt = {}
    for v, c in per_type.items():
        pp = c["tp"] / (c["tp"] + c["fp"]) if c["tp"] + c["fp"] else 0
        pr = c["tp"] / (c["tp"] + c["fn"]) if c["tp"] + c["fn"] else 0
        pf = 2 * pp * pr / (pp + pr) if pp + pr else 0
        pvt[v] = {
            "precision": round(pp, 4), "recall": round(pr, 4), "f1": round(pf, 4),
            "support": c["tp"] + c["fn"], "tp": c["tp"], "fp": c["fp"], "fn": c["fn"],
        }

    return {
        "metrics": {"tp": tp, "fp": fp, "fn": fn,
                    "precision": round(p, 4), "recall": round(r, 4), "f1": round(f1, 4)},
        "per_vuln_type": pvt,
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit",       type=int, default=None, help="Process only N contracts")
    parser.add_argument("--skip-llm",    action="store_true", help="Skip all LLM API calls")
    parser.add_argument("--skip-tools",  action="store_true", help="Skip Slither (use cache only)")
    parser.add_argument("--skip-gpt",    action="store_true")
    parser.add_argument("--skip-claude", action="store_true")
    parser.add_argument("--skip-gemini", action="store_true")
    parser.add_argument("--output",      type=Path, default=None)
    args = parser.parse_args()

    print("Loading dataset...")
    with open(DATASET_PATH) as f:
        ds = json.load(f)
    test_samples = [s for s in ds["samples"] if s.get("split") == "test"]
    if args.limit:
        test_samples = test_samples[:args.limit]
    print(f"  Test contracts: {len(test_samples)}")

    print("Loading CodeBERT predictions from llm_eval.json...")
    with open(LLM_EVAL_PATH) as f:
        llm_eval = json.load(f)
    cb_by_id: dict[str, list[str]] = {}
    for row in llm_eval.get("per_sample", []):
        cb_by_id[row["contract_id"]] = row.get("pred_labels", [])
    print(f"  CodeBERT predictions loaded for {len(cb_by_id)} contracts")

    tool_cache_path = RESULTS_DIR / "test_split_tool_cache.json"
    llm_cache_path  = RESULTS_DIR / "test_split_llm_cache.json"

    tool_cache: dict[str, list[str]] = {}
    llm_cache:  dict[str, list[str]] = {}

    if tool_cache_path.exists():
        tool_cache = json.loads(tool_cache_path.read_text())
        print(f"  Tool cache: {len(tool_cache)} entries")
    if llm_cache_path.exists():
        llm_cache = json.loads(llm_cache_path.read_text())
        print(f"  LLM cache:  {len(llm_cache)} entries")

    openai_key    = os.environ.get("OPENAI_API_KEY")
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
    google_key    = os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")

    llm_systems = []
    if not args.skip_llm:
        if openai_key  and not args.skip_gpt:    llm_systems.append(("gpt4o",  call_gpt,    openai_key))
        if anthropic_key and not args.skip_claude: llm_systems.append(("claude", call_claude, anthropic_key))
        if google_key  and not args.skip_gemini: llm_systems.append(("gemini", call_gemini, google_key))

    all_systems = ["auditquant_tools", "auditquant_codebert"] + [s[0] for s in llm_systems]
    print(f"\nSystems: {all_systems}")

    per_contract: list[dict] = []
    tool_errors: dict = defaultdict(int)
    llm_errors:  dict = defaultdict(int)

    for idx, sample in enumerate(test_samples, 1):
        cid    = sample["contract_id"]
        source = sample["source_code"]
        gt     = set(sample.get("vuln_types", []))

        row: dict = {"contract_id": cid, "ground_truth": sorted(gt)}

        # Tools (Slither)
        if cid in tool_cache:
            tool_preds = set(tool_cache[cid])
        elif args.skip_tools:
            tool_preds = set()
        else:
            tool_preds = run_slither_local(source)
            tool_cache[cid] = sorted(tool_preds)
            if idx % 20 == 0:
                tool_cache_path.write_text(json.dumps(tool_cache, indent=2))

        t, f, n = _tpfpfn(tool_preds, gt)
        row["auditquant_tools"] = {"detected": sorted(tool_preds), "tp": t, "fp": f, "fn": n}

        # AuditQuant + CodeBERT (tools union CodeBERT)
        cb_preds = set(cb_by_id.get(cid, []))
        combined = tool_preds | cb_preds
        t, f, n = _tpfpfn(combined, gt)
        row["auditquant_codebert"] = {"detected": sorted(combined), "tp": t, "fp": f, "fn": n}

        # LLMs
        for sname, caller, key in llm_systems:
            cache_key = f"{sname}::{cid}"
            if cache_key in llm_cache:
                detected = llm_cache[cache_key]
            else:
                try:
                    detected = caller(source, key)
                    llm_cache[cache_key] = detected
                    if idx % 10 == 0:
                        llm_cache_path.write_text(json.dumps(llm_cache, indent=2))
                except Exception as e:
                    print(f"  [{sname}] {cid} error: {e}")
                    detected = []
                    llm_errors[sname] += 1
            t, f, n = _tpfpfn(set(detected), gt)
            row[sname] = {"detected": detected, "tp": t, "fp": f, "fn": n}

        per_contract.append(row)

        if idx % 50 == 0:
            print(f"  [{idx}/{len(test_samples)}] {cid}")

    # Final cache flush
    tool_cache_path.write_text(json.dumps(tool_cache, indent=2))
    llm_cache_path.write_text(json.dumps(llm_cache, indent=2))

    system_metrics = {s: aggregate_metrics(per_contract, s) for s in all_systems}

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = args.output or RESULTS_DIR / f"test_split_comparison_{ts}.json"
    out = {
        "run_id": f"test_split_comparison_{ts}",
        "timestamp": datetime.now().isoformat(),
        "n_contracts": len(per_contract),
        "split": "test",
        "note": "864 test contracts, never used to train or calibrate CodeBERT",
        "systems_evaluated": all_systems,
        "system_metrics": system_metrics,
        "per_contract": per_contract,
    }
    out_path.write_text(json.dumps(out, indent=2))

    labels = {
        "auditquant_tools":    "AuditQuant (Tools Only)",
        "auditquant_codebert": "AuditQuant + CodeBERT",
        "gpt4o":               "GPT-4o",
        "claude":              "Claude Sonnet 4.6",
        "gemini":              "Gemini 2.5 Flash",
    }
    print(f"\n{'System':<30} {'P':>8} {'R':>8} {'F1':>8} {'TP':>6} {'FP':>6} {'FN':>6}")
    print("-" * 75)
    for s in all_systems:
        m = system_metrics[s]["metrics"]
        print(f"{labels.get(s, s):<30} {m['precision']:>8.3f} {m['recall']:>8.3f} "
              f"{m['f1']:>8.3f} {m['tp']:>6} {m['fp']:>6} {m['fn']:>6}")

    print(f"\nSaved: {out_path}")
    print("\nRun generate_comparison_graphs.py pointing to this file to generate graphs.")
if __name__ == "__main__":
    sys.exit(main())
