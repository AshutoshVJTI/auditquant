#!/usr/bin/env python3
"""
AuditQuant Real-Data Benchmark
Runs Slither, Mythril, Oyente (Docker), LLM summarization (OpenAI),
anti-hallucination verification, and risk scoring on actual contracts.

Results are saved incrementally so partial runs are recoverable.

Usage:
    python run_real_benchmark.py                     # all 100 contracts
    python run_real_benchmark.py --limit 20          # first 20
    python run_real_benchmark.py --resume <run_id>   # resume partial run
    python run_real_benchmark.py --skip-oyente       # skip Oyente (it fails on modern Solidity)
    python run_real_benchmark.py --skip-mythril      # skip Mythril (very slow)
"""

import argparse
import asyncio
import json
import os
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

# ── path setup ──────────────────────────────────────────────────────────────
EVAL_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = EVAL_DIR.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))

# Load .env before importing backend modules
from dotenv import load_dotenv
load_dotenv(PROJECT_ROOT / ".env")

LABELS_DIR = EVAL_DIR / "labels"
RESULTS_DIR = EVAL_DIR / "results"
DATASETS_DIR = EVAL_DIR / "datasets" / "selected"
COMPOSE_PATH = str(PROJECT_ROOT / "docker" / "docker-compose.yml")


# ── data classes ────────────────────────────────────────────────────────────

@dataclass
class ToolFinding:
    type: str
    severity: str
    confidence: float
    title: str = ""
    description: str = ""
    location: str | None = None
    swc_id: str | None = None
    has_exploit_proof: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ContractResult:
    contract_id: str
    filename: str
    status: str = "pending"
    start_time: float = 0.0
    end_time: float = 0.0
    total_seconds: float = 0.0

    tool_results: dict[str, dict] = field(default_factory=dict)
    total_findings: int = 0
    cross_validated: int = 0

    defi_category: str = ""
    classifier_confidence: float = 0.0

    r_sast: float = 0.0
    r_dast: float = 0.0
    r_comp: float = 0.0

    llm_claims: int = 0
    verified_claims: int = 0
    rejected_claims: int = 0
    hallucination_rate: float = 0.0
    llm_summary: str = ""

    ground_truth_vulns: list[str] = field(default_factory=list)
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0

    business_risk_score: float = 0.0

    error: str = ""


# ── tool runners (direct Docker) ───────────────────────────────────────────

async def run_slither_native(sol_path: Path, timeout: int = 120) -> dict:
    """Run Slither natively (uses solc-select for multi-version support)."""
    start = time.time()
    try:
        cmd = ["slither", str(sol_path.resolve()), "--json", "-"]
        proc = await asyncio.create_subprocess_exec(
            *cmd, cwd=str(PROJECT_ROOT),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        elapsed = (time.time() - start) * 1000

        payload = None
        try:
            payload = json.loads(stdout.decode())
        except json.JSONDecodeError:
            pass

        if payload and "results" in payload:
            detectors = payload.get("results", {}).get("detectors", [])
            findings = []
            for d in detectors:
                impact = d.get("impact", "Unknown")
                if impact.lower() == "informational":
                    continue
                loc = None
                elems = d.get("elements", [])
                if elems:
                    sm = elems[0].get("source_mapping", {})
                    fn = sm.get("filename_relative") or sm.get("filename")
                    if fn:
                        loc = f"{fn}:{sm.get('start', '?')}"
                findings.append(ToolFinding(
                    type=d.get("check", "unknown"),
                    severity=impact,
                    confidence={"High": 0.9, "Medium": 0.7, "Low": 0.5}.get(
                        d.get("confidence", "Medium"), 0.6
                    ),
                    title=d.get("check", "unknown"),
                    description=(d.get("description", ""))[:200],
                    location=loc,
                ).to_dict())
            return {"findings": findings, "time_ms": elapsed, "success": True, "error": None}
        else:
            err = stderr.decode()[:300]
            return {"findings": [], "time_ms": elapsed, "success": False, "error": err}
    except asyncio.TimeoutError:
        return {"findings": [], "time_ms": (time.time() - start) * 1000, "success": False, "error": "timeout"}
    except Exception as e:
        return {"findings": [], "time_ms": (time.time() - start) * 1000, "success": False, "error": str(e)[:200]}


async def run_mythril_docker(sol_path: Path, timeout: int = 90) -> dict:
    """Run Mythril via Docker, return {findings, time_ms, success, error}."""
    start = time.time()
    try:
        rel = sol_path.resolve().relative_to(PROJECT_ROOT)
        cmd = [
            "docker", "compose", "-f", COMPOSE_PATH,
            "run", "--rm", "mythril",
            "analyze", f"/work/{rel.as_posix()}", "-o", "json",
            "--execution-timeout", "60",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd, cwd=str(PROJECT_ROOT),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        elapsed = (time.time() - start) * 1000

        payload = None
        try:
            payload = json.loads(stdout.decode())
        except json.JSONDecodeError:
            pass

        if payload:
            issues = payload.get("issues") or []
            findings = []
            for iss in issues:
                sev = iss.get("severity", "Unknown")
                tx_seq = iss.get("tx_sequence") or iss.get("transactions") or []
                has_proof = isinstance(tx_seq, list) and len(tx_seq) > 0
                findings.append(ToolFinding(
                    type=iss.get("title", "unknown").lower().replace(" ", "-"),
                    severity=sev,
                    confidence=0.85 if has_proof else 0.6,
                    title=iss.get("title", "unknown"),
                    description=(iss.get("description", ""))[:200],
                    location=iss.get("sourceMap") or f"line:{iss.get('lineno', '?')}",
                    swc_id=iss.get("swc-id"),
                    has_exploit_proof=has_proof,
                ).to_dict())
            return {"findings": findings, "time_ms": elapsed, "success": True, "error": None}
        else:
            err = stderr.decode()[:300]
            return {"findings": [], "time_ms": elapsed, "success": False, "error": err}
    except asyncio.TimeoutError:
        return {"findings": [], "time_ms": (time.time() - start) * 1000, "success": False, "error": "timeout"}
    except Exception as e:
        return {"findings": [], "time_ms": (time.time() - start) * 1000, "success": False, "error": str(e)[:200]}


async def run_oyente_docker(sol_path: Path, timeout: int = 60) -> dict:
    """Run Oyente via Docker, return {findings, time_ms, success, error}."""
    start = time.time()
    try:
        rel = sol_path.resolve().relative_to(PROJECT_ROOT)
        cmd = [
            "docker", "compose", "-f", COMPOSE_PATH,
            "run", "--rm", "oyente",
            "-s", f"/work/{rel.as_posix()}", "-ce",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd, cwd=str(PROJECT_ROOT),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        elapsed = (time.time() - start) * 1000

        import re
        output = stdout.decode() + stderr.decode()
        vuln_pattern = re.compile(
            r'(Callstack Depth Attack|Re-Entrancy|Time.?[Dd]ependency|'
            r'Integer Overflow|Integer Underflow|Assertion Failure|'
            r'Money.?[Cc]oncurrency|Parity).+?:\s*(True|False)',
            re.IGNORECASE
        )

        findings = []
        for m in vuln_pattern.finditer(output):
            vuln_name = m.group(1)
            is_vuln = m.group(2).lower() == "true"
            if is_vuln:
                vtype = vuln_name.lower().replace(" ", "-").replace("_", "-")
                findings.append(ToolFinding(
                    type=vtype,
                    severity="High" if "reentr" in vtype.lower() or "overflow" in vtype.lower() else "Medium",
                    confidence=0.7,
                    title=f"Oyente: {vuln_name}",
                    description=f"Bytecode analysis detected {vuln_name}",
                    has_exploit_proof=False,
                ).to_dict())

        return {"findings": findings, "time_ms": elapsed, "success": True, "error": None}
    except asyncio.TimeoutError:
        return {"findings": [], "time_ms": (time.time() - start) * 1000, "success": False, "error": "timeout"}
    except Exception as e:
        return {"findings": [], "time_ms": (time.time() - start) * 1000, "success": False, "error": str(e)[:200]}


# ── LLM summarization + verification ───────────────────────────────────────

async def run_llm_verification(
    all_findings: list[dict],
    source_code: str,
    defi_category: str,
    api_key: str,
    model: str = "gpt-4o-mini",
) -> dict:
    """
    Send tool findings to LLM for summarization, then verify claims.
    Returns {summary, claims_count, verified, rejected, hallucination_rate}.
    """
    if not all_findings:
        return {
            "summary": "No findings to summarize.",
            "claims_count": 0, "verified": 0, "rejected": 0,
            "hallucination_rate": 0.0,
        }

    from openai import OpenAI
    client = OpenAI(api_key=api_key)

    findings_text = "\n".join(
        f"- [{f.get('title', 'unknown')}] severity={f.get('severity', '?')}, "
        f"confidence={f.get('confidence', '?')}, location={f.get('location', '?')}"
        for f in all_findings[:15]
    )

    prompt = f"""You are a smart contract security auditor. Analyze these tool findings
for a {defi_category} DeFi contract.

Tool Findings:
{findings_text}

For each REAL vulnerability (ignore likely false positives), provide:

VULNERABILITY: <type>
LOCATION: <file:line or function>
EXPLOITABLE: <yes/no — only yes if tool provided proof>
LOSS_PERCENTAGE: <0-100>
DESCRIPTION: <concise description>

Rules:
- Only report vulnerabilities actually found by tools
- Do not invent new vulnerabilities
- EXPLOITABLE=yes requires dynamic proof (Mythril exploit trace)

Summary:"""

    try:
        import re

        response = await asyncio.to_thread(
            client.chat.completions.create,
            model=model,
            messages=[
                {"role": "system", "content": "You are a precise smart contract security auditor."},
                {"role": "user", "content": prompt},
            ],
            timeout=45,
        )
        summary = (response.choices[0].message.content or "").strip()

        vuln_matches = re.findall(r"VULNERABILITY:\s*(.+)", summary, re.IGNORECASE)
        claims_count = len(vuln_matches)

        # Verify claims against tool evidence
        tool_types = set()
        for f in all_findings:
            tool_types.add(f.get("type", "").lower().replace("_", "-"))
            tool_types.add(f.get("title", "").lower().replace("_", "-").replace(" ", "-"))

        verified = 0
        rejected = 0
        for claim in vuln_matches:
            claim_norm = claim.strip().lower().replace("_", "-").replace(" ", "-")
            if any(claim_norm in tt or tt in claim_norm for tt in tool_types if tt):
                verified += 1
            else:
                rejected += 1

        hallucination_rate = rejected / max(1, claims_count)

        return {
            "summary": summary,
            "claims_count": claims_count,
            "verified": verified,
            "rejected": rejected,
            "hallucination_rate": hallucination_rate,
        }
    except Exception as e:
        return {
            "summary": f"LLM error: {e}",
            "claims_count": 0, "verified": 0, "rejected": 0,
            "hallucination_rate": 0.0,
        }


# ── ChatGPT-only baseline ──────────────────────────────────────────────────

async def run_chatgpt_only(
    source_code: str,
    known_vulns: set[str],
    api_key: str,
    model: str = "gpt-4o-mini",
) -> dict:
    """ChatGPT-only audit (no tools). Returns {tp, fp, fn, time}."""
    import re
    start = time.time()
    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key)
        prompt = (
            "You are a smart contract security auditor. Analyze the following "
            "Solidity source code and list every vulnerability you find.\n\n"
            "For each vulnerability output EXACTLY one line:\n"
            "VULNERABILITY: <type>\n\n"
            "Use normalised types: reentrancy, access-control, integer-overflow, "
            "unchecked-return, timestamp-dependency, front-running, denial-of-service, oracle.\n\n"
            f"Source code:\n```solidity\n{source_code[:6000]}\n```"
        )
        response = await asyncio.to_thread(
            client.chat.completions.create,
            model=model,
            messages=[
                {"role": "system", "content": "You are a precise smart contract security auditor."},
                {"role": "user", "content": prompt},
            ],
            timeout=45,
        )
        text = (response.choices[0].message.content or "").strip()
        detected = set()
        for m in re.finditer(r"VULNERABILITY:\s*([^\n]+)", text, re.IGNORECASE):
            detected.add(m.group(1).strip().lower().replace(" ", "-").replace("_", "-"))

        tp = len(known_vulns & detected)
        fp = len(detected - known_vulns)
        fn = len(known_vulns - detected)
    except Exception as e:
        print(f"      [chatgpt-only] error: {e}")
        tp, fp, fn = 0, 0, len(known_vulns)

    return {"tp": tp, "fp": fp, "fn": fn, "time": time.time() - start}


# ── single contract analysis ───────────────────────────────────────────────

async def analyze_contract(
    contract: dict,
    api_key: str,
    model: str,
    skip_mythril: bool = False,
    skip_oyente: bool = False,
) -> ContractResult:
    """Full pipeline: tools → LLM → verification → risk scoring."""
    result = ContractResult(
        contract_id=contract["id"],
        filename=contract["filename"],
    )
    result.start_time = time.time()
    sol_path = Path(contract["selected_path"])

    if not sol_path.exists():
        result.status = "failed"
        result.error = f"File not found: {sol_path}"
        result.end_time = time.time()
        result.total_seconds = result.end_time - result.start_time
        return result

    try:
        source_code = sol_path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        result.status = "failed"
        result.error = f"Read error: {e}"
        result.end_time = time.time()
        result.total_seconds = result.end_time - result.start_time
        return result

    # DeFi classification (from manifest or pattern-based)
    result.defi_category = contract.get("defi_category", "other")
    cls_result = contract.get("classifier_result", {})
    result.classifier_confidence = cls_result.get("confidence", 0.0)
    if cls_result.get("category"):
        result.defi_category = cls_result["category"]

    # Run tools in parallel
    tasks = {"slither": run_slither_native(sol_path)}
    if not skip_mythril:
        tasks["mythril"] = run_mythril_docker(sol_path, timeout=90)
    if not skip_oyente:
        tasks["oyente"] = run_oyente_docker(sol_path, timeout=60)

    tool_names = list(tasks.keys())
    tool_coros = list(tasks.values())
    tool_outputs = await asyncio.gather(*tool_coros, return_exceptions=True)

    all_findings: list[dict] = []
    for name, output in zip(tool_names, tool_outputs):
        if isinstance(output, Exception):
            result.tool_results[name] = {
                "findings": [], "time_ms": 0, "success": False, "error": str(output)[:200]
            }
        else:
            result.tool_results[name] = output
            all_findings.extend(output.get("findings", []))

    result.total_findings = len(all_findings)

    # Cross-validation: findings reported by 2+ tools
    type_tools: dict[str, set[str]] = {}
    for name, output in zip(tool_names, tool_outputs):
        if isinstance(output, Exception):
            continue
        for f in output.get("findings", []):
            ftype = f.get("type", "").lower()
            type_tools.setdefault(ftype, set()).add(name)
    result.cross_validated = sum(1 for tools in type_tools.values() if len(tools) >= 2)

    # Risk scores
    static_count = len(result.tool_results.get("slither", {}).get("findings", []))
    dynamic_count = sum(
        len(result.tool_results.get(t, {}).get("findings", []))
        for t in ["mythril", "oyente"]
    )
    result.r_sast = min(100.0, static_count * 15.0)
    result.r_dast = min(100.0, dynamic_count * 20.0)

    # Complexity estimate from source lines
    lines = len(source_code.splitlines())
    result.r_comp = min(100.0, 100.0 / (1 + 2.71828 ** (-(lines - 200) / 100)))

    # LLM summarization + verification
    if api_key and all_findings:
        llm_result = await run_llm_verification(
            all_findings, source_code, result.defi_category, api_key, model,
        )
        result.llm_summary = llm_result["summary"]
        result.llm_claims = llm_result["claims_count"]
        result.verified_claims = llm_result["verified"]
        result.rejected_claims = llm_result["rejected"]
        result.hallucination_rate = llm_result["hallucination_rate"]

    # Business risk score (simplified rubric)
    max_sev_score = max(
        ({"high": 5, "medium": 3, "low": 1}.get(f.get("severity", "").lower(), 1)
         for f in all_findings),
        default=0,
    )
    cat_exposure = {"amm_dex": 5, "lending": 5, "vault_yield": 4, "staking_rewards": 3.5}.get(
        result.defi_category, 2
    )
    evidence = min(5.0, result.cross_validated * 2 + 1) if all_findings else 0
    result.business_risk_score = min(100.0, (
        (max_sev_score / 5) * 0.3 +
        (min(5, result.r_dast / 20) / 5) * 0.35 +
        (cat_exposure / 5) * 0.2 +
        (evidence / 5) * 0.15
    ) * 100)

    # Ground truth comparison
    known = set(contract.get("known_vulnerabilities", []))
    result.ground_truth_vulns = list(known)
    detected_types = set(f.get("type", "").lower().replace("_", "-") for f in all_findings)
    result.true_positives = len(known & detected_types)
    result.false_positives = len(detected_types - known) if known else 0
    result.false_negatives = len(known - detected_types)

    result.status = "completed"
    result.end_time = time.time()
    result.total_seconds = result.end_time - result.start_time
    return result


# ── standalone tool analysis (for comparative eval) ─────────────────────────

async def analyze_standalone(contract: dict, tool: str) -> dict:
    """Run a single tool in isolation on one contract."""
    sol_path = Path(contract["selected_path"])
    if not sol_path.exists():
        return {"tp": 0, "fp": 0, "fn": 0, "time": 0}

    start = time.time()
    runners = {
        "slither": run_slither_native,
        "mythril": lambda p: run_mythril_docker(p, timeout=90),
        "oyente": lambda p: run_oyente_docker(p, timeout=60),
    }
    runner = runners.get(tool)
    if not runner:
        return {"tp": 0, "fp": 0, "fn": 0, "time": 0}

    try:
        output = await runner(sol_path)
    except Exception:
        output = {"findings": []}

    known = set(contract.get("known_vulnerabilities", []))
    detected = set(f.get("type", "").lower().replace("_", "-") for f in output.get("findings", []))

    return {
        "tp": len(known & detected),
        "fp": len(detected - known) if known else 0,
        "fn": len(known - detected),
        "time": time.time() - start,
    }


# ── metrics ─────────────────────────────────────────────────────────────────

def compute_metrics(results: list[ContractResult]) -> dict:
    completed = [r for r in results if r.status == "completed"]
    n = len(completed)
    if n == 0:
        return {
            "total_contracts": len(results), "successful": 0, "failed": len(results),
            "total_time_seconds": 0, "avg_time_per_contract": 0,
            "tool_metrics": {}, "total_findings": 0, "total_cross_validated": 0,
            "total_llm_claims": 0, "total_verified": 0, "total_rejected": 0,
            "overall_hallucination_rate": 0, "true_positives": 0,
            "false_positives": 0, "false_negatives": 0,
            "precision": 0, "recall": 0, "f1_score": 0,
        }

    total_time = sum(r.total_seconds for r in completed)
    tp = sum(r.true_positives for r in completed)
    fp = sum(r.false_positives for r in completed)
    fn = sum(r.false_negatives for r in completed)
    p = tp / max(1, tp + fp)
    r = tp / max(1, tp + fn)
    f1 = 2 * p * r / max(0.001, p + r)

    total_claims = sum(r.llm_claims for r in completed)
    total_verified = sum(r.verified_claims for r in completed)
    total_rejected = sum(r.rejected_claims for r in completed)

    tool_metrics = {}
    for tool in ["slither", "mythril", "oyente"]:
        tool_findings = sum(
            len(r.tool_results.get(tool, {}).get("findings", []))
            for r in completed
        )
        tool_time = sum(
            r.tool_results.get(tool, {}).get("time_ms", 0)
            for r in completed
        )
        tool_success = sum(
            1 for r in completed
            if r.tool_results.get(tool, {}).get("success", False)
        )
        tool_errors = sum(
            1 for r in completed
            if tool in r.tool_results and not r.tool_results[tool].get("success", False)
        )
        tool_metrics[tool] = {
            "total_findings": tool_findings,
            "avg_time_ms": tool_time / max(1, n),
            "success_rate": tool_success / max(1, n),
            "error_count": tool_errors,
        }

    return {
        "total_contracts": len(results),
        "successful": n,
        "failed": len(results) - n,
        "total_time_seconds": total_time,
        "avg_time_per_contract": total_time / max(1, n),
        "tool_metrics": tool_metrics,
        "total_findings": sum(r.total_findings for r in completed),
        "total_cross_validated": sum(r.cross_validated for r in completed),
        "total_llm_claims": total_claims,
        "total_verified": total_verified,
        "total_rejected": total_rejected,
        "overall_hallucination_rate": total_rejected / max(1, total_claims),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": p,
        "recall": r,
        "f1_score": f1,
    }


def safe_prf(tp, fp, fn):
    p = tp / max(1, tp + fp)
    r = tp / max(1, tp + fn)
    f1 = 2 * p * r / max(0.001, p + r)
    return p, r, f1


# ── main ────────────────────────────────────────────────────────────────────

async def run_benchmark(args):
    with open(LABELS_DIR / "dataset_manifest.json") as f:
        manifest = json.load(f)
    contracts = manifest["contracts"]
    if args.limit:
        contracts = contracts[:args.limit]

    api_key = os.getenv("OPENAI_API_KEY", "")
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    run_id = args.resume or datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    output_path = RESULTS_DIR / f"benchmark_real_{run_id}.json"
    comp_output_path = RESULTS_DIR / f"comparative_real_{run_id}.json"

    # Resume support
    existing_results: dict[str, ContractResult] = {}
    if args.resume and output_path.exists():
        with open(output_path) as f:
            prev = json.load(f)
        for r in prev.get("results", []):
            cr = ContractResult(**{k: v for k, v in r.items() if k in ContractResult.__dataclass_fields__})
            existing_results[cr.contract_id] = cr
        print(f"Resuming run {run_id}: {len(existing_results)} contracts already done")

    tools_label = "Slither"
    if not args.skip_mythril:
        tools_label += " + Mythril"
    if not args.skip_oyente:
        tools_label += " + Oyente"

    print(f"\n{'='*65}")
    print(f"  AuditQuant Real-Data Benchmark")
    print(f"{'='*65}")
    print(f"  Contracts   : {len(contracts)}")
    print(f"  Tools       : {tools_label}")
    print(f"  LLM         : {model} ({'enabled' if api_key else 'disabled'})")
    print(f"  Run ID      : {run_id}")
    print(f"{'='*65}\n")

    results: list[ContractResult] = []
    # Also collect comparative data
    comp_rows: list[dict] = []

    for i, contract in enumerate(contracts, 1):
        cid = contract["id"]

        # Skip already completed
        if cid in existing_results:
            results.append(existing_results[cid])
            print(f"  [{i:3d}/{len(contracts)}] {cid} — skipped (already done)")
            continue

        print(f"  [{i:3d}/{len(contracts)}] {cid}...", end="", flush=True)

        # 1. Full hybrid pipeline
        result = await analyze_contract(
            contract, api_key, model,
            skip_mythril=args.skip_mythril,
            skip_oyente=args.skip_oyente,
        )
        results.append(result)

        status_icon = "OK" if result.status == "completed" else "FAIL"
        tool_summary = ", ".join(
            f"{t}={'ok' if d.get('success') else 'err'}"
            for t, d in result.tool_results.items()
        )
        print(f" {status_icon} | {result.total_seconds:.1f}s | "
              f"{result.total_findings} findings | {tool_summary}"
              f"{' | llm=' + str(result.llm_claims) + ' claims' if result.llm_claims else ''}")

        # 2. Comparative: standalone tools + ChatGPT-only
        if args.comparative:
            known = set(contract.get("known_vulnerabilities", []))
            sol_path = Path(contract["selected_path"])
            source_code = ""
            if sol_path.exists():
                source_code = sol_path.read_text(encoding="utf-8", errors="ignore")

            row = {
                "contract_id": cid,
                "filename": contract["filename"],
                "ground_truth_count": len(known),
                "hybrid_tp": result.true_positives,
                "hybrid_fp": result.false_positives,
                "hybrid_fn": result.false_negatives,
                "hybrid_time": result.total_seconds,
                "standalone": {},
            }

            for tool in ["slither", "mythril", "oyente"]:
                if (tool == "mythril" and args.skip_mythril) or (tool == "oyente" and args.skip_oyente):
                    row["standalone"][tool] = {"tp": 0, "fp": 0, "fn": 0, "time": 0}
                    continue
                st = await analyze_standalone(contract, tool)
                row["standalone"][tool] = st

            if api_key and source_code:
                gpt = await run_chatgpt_only(source_code, known, api_key, model)
            else:
                gpt = {"tp": 0, "fp": 0, "fn": len(known), "time": 0}
            row["chatgpt_tp"] = gpt["tp"]
            row["chatgpt_fp"] = gpt["fp"]
            row["chatgpt_fn"] = gpt["fn"]
            row["chatgpt_time"] = gpt["time"]
            comp_rows.append(row)

        # Incremental save every 5 contracts
        if i % 5 == 0 or i == len(contracts):
            _save_results(results, run_id, output_path)
            if args.comparative and comp_rows:
                _save_comparative(comp_rows, run_id, comp_output_path)

    # Final save
    metrics = compute_metrics(results)
    _save_results(results, run_id, output_path, metrics)

    # Comparative metrics
    if args.comparative and comp_rows:
        comp_metrics = _compute_comp_metrics(comp_rows)
        _save_comparative(comp_rows, run_id, comp_output_path, comp_metrics)

    _print_summary(metrics, results)
    print(f"\nResults saved to: {output_path}")
    if args.comparative:
        print(f"Comparative saved to: {comp_output_path}")

    return output_path, comp_output_path if args.comparative else None


def _save_results(results, run_id, path, metrics=None):
    if metrics is None:
        metrics = compute_metrics(results)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    output = {
        "run_id": run_id,
        "timestamp": datetime.utcnow().isoformat(),
        "mode": "real",
        "metrics": metrics,
        "results": [asdict(r) for r in results],
    }
    with open(path, "w") as f:
        json.dump(output, f, indent=2)


def _save_comparative(rows, run_id, path, metrics=None):
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    if metrics is None:
        metrics = _compute_comp_metrics(rows)
    output = {
        "run_id": run_id,
        "timestamp": datetime.utcnow().isoformat(),
        "mode": "comparative",
        "metrics": metrics,
        "per_contract": rows,
    }
    with open(path, "w") as f:
        json.dump(output, f, indent=2)


def _compute_comp_metrics(rows):
    n = len(rows)
    h_tp = sum(r["hybrid_tp"] for r in rows)
    h_fp = sum(r["hybrid_fp"] for r in rows)
    h_fn = sum(r["hybrid_fn"] for r in rows)
    hp, hr, hf1 = safe_prf(h_tp, h_fp, h_fn)

    standalone_metrics = {}
    for tool in ["slither", "mythril", "oyente"]:
        t_tp = sum(r["standalone"].get(tool, {}).get("tp", 0) for r in rows)
        t_fp = sum(r["standalone"].get(tool, {}).get("fp", 0) for r in rows)
        t_fn = sum(r["standalone"].get(tool, {}).get("fn", 0) for r in rows)
        tp, tr, tf1 = safe_prf(t_tp, t_fp, t_fn)
        standalone_metrics[tool] = {
            "precision": round(tp, 4), "recall": round(tr, 4), "f1": round(tf1, 4),
            "fp_rate": round(t_fp / max(1, t_tp + t_fp), 4),
            "avg_time": round(sum(r["standalone"].get(tool, {}).get("time", 0) for r in rows) / max(1, n), 4),
        }

    g_tp = sum(r.get("chatgpt_tp", 0) for r in rows)
    g_fp = sum(r.get("chatgpt_fp", 0) for r in rows)
    g_fn = sum(r.get("chatgpt_fn", 0) for r in rows)
    gp, gr, gf1 = safe_prf(g_tp, g_fp, g_fn)

    return {
        "total_contracts": n,
        "hybrid_precision": round(hp, 4), "hybrid_recall": round(hr, 4),
        "hybrid_f1": round(hf1, 4),
        "hybrid_fp_rate": round(h_fp / max(1, h_tp + h_fp), 4),
        "hybrid_avg_time": round(sum(r["hybrid_time"] for r in rows) / max(1, n), 4),
        "standalone_metrics": standalone_metrics,
        "chatgpt_precision": round(gp, 4), "chatgpt_recall": round(gr, 4),
        "chatgpt_f1": round(gf1, 4),
        "chatgpt_fp_rate": round(g_fp / max(1, g_tp + g_fp), 4),
        "chatgpt_avg_time": round(sum(r.get("chatgpt_time", 0) for r in rows) / max(1, n), 4),
    }


def _print_summary(metrics, results):
    m = metrics
    print(f"\n{'='*65}")
    print("  BENCHMARK SUMMARY")
    print(f"{'='*65}")
    print(f"  Contracts     : {m['successful']}/{m['total_contracts']} completed")
    print(f"  Total time    : {m['total_time_seconds']:.1f}s")
    print(f"  Avg/contract  : {m['avg_time_per_contract']:.1f}s")
    print(f"\n  Detection:")
    print(f"    Total findings   : {m['total_findings']}")
    print(f"    Cross-validated  : {m['total_cross_validated']}")
    print(f"    Precision        : {m['precision']:.1%}")
    print(f"    Recall           : {m['recall']:.1%}")
    print(f"    F1               : {m['f1_score']:.1%}")
    print(f"\n  LLM Verification:")
    print(f"    Total claims     : {m['total_llm_claims']}")
    print(f"    Verified         : {m['total_verified']}")
    print(f"    Rejected         : {m['total_rejected']}")
    print(f"    Hallucination %  : {m['overall_hallucination_rate']:.1%}")
    print(f"\n  Per-Tool:")
    for tool, td in m.get("tool_metrics", {}).items():
        print(f"    {tool:10s}: {td['total_findings']:3d} findings, "
              f"{td['success_rate']:.0%} success, avg {td['avg_time_ms']:.0f}ms"
              + (f", {td['error_count']} errors" if td.get('error_count') else ""))
    print(f"{'='*65}\n")


def main():
    parser = argparse.ArgumentParser(description="AuditQuant real-data benchmark")
    parser.add_argument("--limit", type=int, help="Max contracts to analyze")
    parser.add_argument("--resume", type=str, help="Resume a previous run by run_id")
    parser.add_argument("--skip-mythril", action="store_true", help="Skip Mythril (very slow)")
    parser.add_argument("--skip-oyente", action="store_true", help="Skip Oyente (fails on modern Solidity)")
    parser.add_argument("--comparative", action="store_true",
                        help="Also run standalone tool + ChatGPT-only comparisons")
    args = parser.parse_args()
    asyncio.run(run_benchmark(args))


if __name__ == "__main__":
    main()
