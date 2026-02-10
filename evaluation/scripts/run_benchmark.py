#!/usr/bin/env python3
"""
AuditQuant Evaluation Benchmark Pipeline

Runs the full multi-tool analysis on all contracts and collects metrics for:
1. False Positive Rate per tool
2. Precision/Recall/F1 per vulnerability type
3. LLM Hallucination Rate
4. Loss % Correlation (predicted vs ground truth)
5. Time to Actionable Report
6. Comparative evaluation: hybrid vs standalone tools vs ChatGPT-only (RQ4)

Usage:
    python run_benchmark.py [--limit N] [--tools slither,mythril,...]
    python run_benchmark.py --mode compare [--limit N]   # runs comparative eval
"""
import argparse
import asyncio
import json
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

# Add backend to path
EVAL_DIR = Path(__file__).parent.parent
PROJECT_ROOT = EVAL_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

LABELS_DIR = EVAL_DIR / "labels"
RESULTS_DIR = EVAL_DIR / "results"
DATASETS_DIR = EVAL_DIR / "datasets" / "selected"


@dataclass
class ContractResult:
    """Result of analyzing a single contract."""
    contract_id: str
    filename: str
    status: str = "pending"
    
    # Timing
    start_time: float = 0.0
    end_time: float = 0.0
    total_seconds: float = 0.0
    
    # Per-tool results
    tool_results: dict[str, dict] = field(default_factory=dict)
    
    # Aggregated findings
    total_findings: int = 0
    cross_validated: int = 0
    
    # Classification
    defi_category: str = ""
    classifier_confidence: float = 0.0
    
    # Risk scores
    r_sast: float = 0.0
    r_dast: float = 0.0
    r_comp: float = 0.0
    
    # LLM validation
    llm_claims: int = 0
    verified_claims: int = 0
    rejected_claims: int = 0
    hallucination_rate: float = 0.0
    
    # Ground truth comparison (if labels available)
    ground_truth_vulns: list[str] = field(default_factory=list)
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    
    error: str = ""


@dataclass
class BenchmarkMetrics:
    """Aggregated benchmark metrics."""
    total_contracts: int = 0
    successful: int = 0
    failed: int = 0
    
    # Timing
    total_time_seconds: float = 0.0
    avg_time_per_contract: float = 0.0
    
    # Per-tool metrics
    tool_metrics: dict[str, dict] = field(default_factory=dict)
    
    # Aggregated detection
    total_findings: int = 0
    total_cross_validated: int = 0
    
    # LLM metrics
    total_llm_claims: int = 0
    total_verified: int = 0
    total_rejected: int = 0
    overall_hallucination_rate: float = 0.0
    
    # Classification accuracy
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0


# ---------------------------------------------------------------------------
# Comparative evaluation data structures (RQ4)
# ---------------------------------------------------------------------------

@dataclass
class StandaloneToolResult:
    """Metrics for a single-tool-only run on one contract."""
    tool: str
    contract_id: str
    findings_count: int = 0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    time_seconds: float = 0.0


@dataclass
class ComparativeRow:
    """Per-contract comparison across approaches."""
    contract_id: str
    filename: str
    ground_truth_count: int = 0

    # Hybrid (AuditQuant full pipeline)
    hybrid_tp: int = 0
    hybrid_fp: int = 0
    hybrid_fn: int = 0
    hybrid_time: float = 0.0

    # Per-standalone tool
    standalone: dict[str, dict[str, Any]] = field(default_factory=dict)

    # ChatGPT-only baseline
    chatgpt_tp: int = 0
    chatgpt_fp: int = 0
    chatgpt_fn: int = 0
    chatgpt_time: float = 0.0


@dataclass
class ComparativeMetrics:
    """Aggregated side-by-side metrics for the comparative evaluation."""
    total_contracts: int = 0

    # Hybrid
    hybrid_precision: float = 0.0
    hybrid_recall: float = 0.0
    hybrid_f1: float = 0.0
    hybrid_fp_rate: float = 0.0
    hybrid_avg_time: float = 0.0

    # Per-standalone tool
    standalone_metrics: dict[str, dict[str, float]] = field(default_factory=dict)

    # ChatGPT-only
    chatgpt_precision: float = 0.0
    chatgpt_recall: float = 0.0
    chatgpt_f1: float = 0.0
    chatgpt_fp_rate: float = 0.0
    chatgpt_avg_time: float = 0.0


def load_manifest() -> dict:
    """Load the dataset manifest."""
    manifest_path = LABELS_DIR / "dataset_manifest.json"
    with open(manifest_path) as f:
        return json.load(f)


def load_ground_truth() -> dict[str, dict]:
    """Load ground truth labels if available."""
    labels_path = LABELS_DIR / "ground_truth.json"
    if labels_path.exists():
        with open(labels_path) as f:
            data = json.load(f)
            return {item["id"]: item for item in data}
    return {}


async def analyze_contract_mock(contract: dict) -> ContractResult:
    """
    Mock analysis for testing without Docker.
    Replace with real analysis once Docker is set up.
    """
    import random
    
    result = ContractResult(
        contract_id=contract["id"],
        filename=contract["filename"],
    )
    
    result.start_time = time.time()
    
    # Simulate analysis time
    await asyncio.sleep(0.1)
    
    # Mock tool results
    known_vulns = contract.get("known_vulnerabilities", [])
    classifier_result = contract.get("classifier_result", {})
    
    result.defi_category = classifier_result.get("category", "other")
    result.classifier_confidence = classifier_result.get("confidence", 0.0)
    
    # Simulate tool findings based on known vulnerabilities
    tools = ["slither", "mythril", "oyente"]
    
    for tool in tools:
        # Each tool has different detection rates
        detection_rate = {
            "slither": 0.9,
            "mythril": 0.6,
            "oyente": 0.5,
        }[tool]
        
        findings = []
        for vuln in known_vulns:
            if random.random() < detection_rate:
                findings.append({
                    "type": vuln,
                    "severity": random.choice(["high", "medium", "low"]),
                    "confidence": random.uniform(0.5, 1.0),
                })
        
        # Add some false positives
        if random.random() < 0.2:
            findings.append({
                "type": "potential_issue",
                "severity": "low",
                "confidence": random.uniform(0.3, 0.6),
            })
        
        result.tool_results[tool] = {
            "findings": findings,
            "time_ms": random.randint(100, 2000),
            "success": True,
        }
        result.total_findings += len(findings)
    
    # Simulate cross-validation
    result.cross_validated = max(0, len(known_vulns) - 1)
    
    # Simulate risk scores
    result.r_sast = random.uniform(20, 80)
    result.r_dast = random.uniform(10, 70)
    result.r_comp = random.uniform(15, 60)
    
    # Simulate LLM validation
    result.llm_claims = result.total_findings
    result.verified_claims = int(result.total_findings * 0.7)
    result.rejected_claims = result.total_findings - result.verified_claims
    result.hallucination_rate = result.rejected_claims / max(1, result.llm_claims)
    
    # Ground truth comparison
    result.ground_truth_vulns = known_vulns
    detected_types = set()
    for tool_data in result.tool_results.values():
        for finding in tool_data.get("findings", []):
            detected_types.add(finding["type"])
    
    result.true_positives = len(set(known_vulns) & detected_types)
    result.false_positives = len(detected_types - set(known_vulns))
    result.false_negatives = len(set(known_vulns) - detected_types)
    
    result.end_time = time.time()
    result.total_seconds = result.end_time - result.start_time
    result.status = "completed"
    
    return result


async def analyze_contract_real(contract: dict) -> ContractResult:
    """
    Real analysis using the multi-tool orchestrator.
    Requires Docker containers to be running.
    """
    from app.services.multi_tool_orchestrator import MultiToolOrchestrator
    from app.services.defi_classifier import classify_contract, get_business_context
    from app.services.anti_hallucination import AntiHallucinationVerifier
    
    result = ContractResult(
        contract_id=contract["id"],
        filename=contract["filename"],
    )
    
    result.start_time = time.time()
    
    try:
        file_path = Path(contract["selected_path"])
        source_code = file_path.read_text(encoding="utf-8", errors="ignore")
        
        # Classification
        classification = classify_contract(source_code)
        result.defi_category = classification.primary_category.value
        result.classifier_confidence = classification.confidence
        
        # Multi-tool analysis
        orchestrator = MultiToolOrchestrator()
        tool_result = await orchestrator.analyze(file_path, contract["id"])
        
        # Collect per-tool results
        from app.services.normalized_finding import ToolSource
        for tool_source, tool_res in tool_result.tool_results.items():
            result.tool_results[tool_source.value] = {
                "findings": [f.to_dict() for f in tool_res.findings],
                "count": len(tool_res.findings),
                "success": tool_res.error is None,
            }
        
        result.total_findings = len(tool_result.all_findings)
        result.cross_validated = len(tool_result.cross_validated)
        
        # Ground truth comparison
        known_vulns = set(contract.get("known_vulnerabilities", []))
        detected_types = set(f.vulnerability_type for f in tool_result.all_findings)
        
        result.ground_truth_vulns = list(known_vulns)
        result.true_positives = len(known_vulns & detected_types)
        result.false_positives = len(detected_types - known_vulns)
        result.false_negatives = len(known_vulns - detected_types)
        
        result.status = "completed"
        
    except Exception as e:
        result.status = "failed"
        result.error = str(e)
    
    result.end_time = time.time()
    result.total_seconds = result.end_time - result.start_time
    
    return result


def compute_metrics(results: list[ContractResult]) -> BenchmarkMetrics:
    """Compute aggregated benchmark metrics."""
    metrics = BenchmarkMetrics()
    
    metrics.total_contracts = len(results)
    metrics.successful = sum(1 for r in results if r.status == "completed")
    metrics.failed = sum(1 for r in results if r.status == "failed")
    
    # Timing
    metrics.total_time_seconds = sum(r.total_seconds for r in results)
    metrics.avg_time_per_contract = metrics.total_time_seconds / max(1, metrics.total_contracts)
    
    # Per-tool metrics
    tools = ["slither", "mythril", "oyente"]
    for tool in tools:
        tool_findings = 0
        tool_time = 0
        tool_success = 0
        
        for r in results:
            if tool in r.tool_results:
                tool_data = r.tool_results[tool]
                tool_findings += len(tool_data.get("findings", []))
                tool_time += tool_data.get("time_ms", 0)
                if tool_data.get("success"):
                    tool_success += 1
        
        metrics.tool_metrics[tool] = {
            "total_findings": tool_findings,
            "avg_time_ms": tool_time / max(1, metrics.successful),
            "success_rate": tool_success / max(1, metrics.total_contracts),
        }
    
    # Aggregated findings
    metrics.total_findings = sum(r.total_findings for r in results)
    metrics.total_cross_validated = sum(r.cross_validated for r in results)
    
    # LLM metrics
    metrics.total_llm_claims = sum(r.llm_claims for r in results)
    metrics.total_verified = sum(r.verified_claims for r in results)
    metrics.total_rejected = sum(r.rejected_claims for r in results)
    metrics.overall_hallucination_rate = (
        metrics.total_rejected / max(1, metrics.total_llm_claims)
    )
    
    # Precision/Recall/F1
    metrics.true_positives = sum(r.true_positives for r in results)
    metrics.false_positives = sum(r.false_positives for r in results)
    metrics.false_negatives = sum(r.false_negatives for r in results)
    
    if metrics.true_positives + metrics.false_positives > 0:
        metrics.precision = metrics.true_positives / (metrics.true_positives + metrics.false_positives)
    
    if metrics.true_positives + metrics.false_negatives > 0:
        metrics.recall = metrics.true_positives / (metrics.true_positives + metrics.false_negatives)
    
    if metrics.precision + metrics.recall > 0:
        metrics.f1_score = 2 * (metrics.precision * metrics.recall) / (metrics.precision + metrics.recall)
    
    return metrics


async def run_benchmark(
    limit: int | None = None,
    use_mock: bool = True,
    tools: list[str] | None = None,
) -> tuple[list[ContractResult], BenchmarkMetrics]:
    """Run the full benchmark."""
    manifest = load_manifest()
    contracts = manifest["contracts"]
    
    if limit:
        contracts = contracts[:limit]
    
    print(f"\n{'='*60}")
    print(f"AuditQuant Benchmark")
    print(f"{'='*60}")
    print(f"Contracts: {len(contracts)}")
    print(f"Mode: {'Mock' if use_mock else 'Real'}")
    print(f"{'='*60}\n")
    
    results: list[ContractResult] = []
    
    for i, contract in enumerate(contracts, 1):
        print(f"[{i}/{len(contracts)}] Analyzing {contract['id']}...", end=" ", flush=True)
        
        if use_mock:
            result = await analyze_contract_mock(contract)
        else:
            result = await analyze_contract_real(contract)
        
        results.append(result)
        
        status_icon = "✓" if result.status == "completed" else "✗"
        print(f"{status_icon} ({result.total_seconds:.1f}s, {result.total_findings} findings)")
    
    # Compute metrics
    metrics = compute_metrics(results)
    
    return results, metrics


def save_results(
    results: list[ContractResult],
    metrics: BenchmarkMetrics,
    run_id: str,
) -> Path:
    """Save benchmark results to disk."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    
    output = {
        "run_id": run_id,
        "timestamp": datetime.utcnow().isoformat(),
        "metrics": asdict(metrics),
        "results": [asdict(r) for r in results],
    }
    
    output_path = RESULTS_DIR / f"benchmark_{run_id}.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    
    return output_path


def print_summary(metrics: BenchmarkMetrics):
    """Print benchmark summary."""
    print(f"\n{'='*60}")
    print("BENCHMARK SUMMARY")
    print(f"{'='*60}")
    
    print(f"\n📊 Overall:")
    print(f"   Contracts analyzed: {metrics.successful}/{metrics.total_contracts}")
    print(f"   Total time: {metrics.total_time_seconds:.1f}s")
    print(f"   Avg per contract: {metrics.avg_time_per_contract:.1f}s")
    
    print(f"\n🔍 Detection:")
    print(f"   Total findings: {metrics.total_findings}")
    print(f"   Cross-validated: {metrics.total_cross_validated}")
    print(f"   Precision: {metrics.precision:.1%}")
    print(f"   Recall: {metrics.recall:.1%}")
    print(f"   F1 Score: {metrics.f1_score:.1%}")
    
    print(f"\n🤖 LLM Validation:")
    print(f"   Total claims: {metrics.total_llm_claims}")
    print(f"   Verified: {metrics.total_verified}")
    print(f"   Rejected: {metrics.total_rejected}")
    print(f"   Hallucination rate: {metrics.overall_hallucination_rate:.1%}")
    
    print(f"\n🛠️  Per-Tool Findings:")
    for tool, data in metrics.tool_metrics.items():
        print(f"   {tool}: {data['total_findings']} findings, {data['success_rate']:.0%} success")
    
    print(f"\n{'='*60}\n")


# ---------------------------------------------------------------------------
# Standalone tool analysis (for comparative evaluation)
# ---------------------------------------------------------------------------

async def analyze_contract_standalone_mock(
    contract: dict,
    tool: str,
) -> StandaloneToolResult:
    """
    Mock: run a single tool in isolation on one contract.

    Detection-rate and false-positive probabilities mirror realistic
    tool characteristics so the comparison is meaningful in mock mode.
    """
    import random

    result = StandaloneToolResult(tool=tool, contract_id=contract["id"])
    start = time.time()
    await asyncio.sleep(0.05)

    known_vulns = set(contract.get("known_vulnerabilities", []))

    detection_rates: dict[str, float] = {
        "slither": 0.85,
        "mythril": 0.55,
        "oyente": 0.45,
    }
    fp_rates: dict[str, float] = {
        "slither": 0.35,
        "mythril": 0.20,
        "oyente": 0.25,
    }

    det_rate = detection_rates.get(tool, 0.5)
    fp_rate_val = fp_rates.get(tool, 0.25)

    detected: set[str] = set()
    for vuln in known_vulns:
        if random.random() < det_rate:
            detected.add(vuln)

    fp_count = 0
    if random.random() < fp_rate_val:
        fp_count = random.randint(1, 3)

    result.findings_count = len(detected) + fp_count
    result.true_positives = len(detected)
    result.false_positives = fp_count
    result.false_negatives = len(known_vulns - detected)
    result.time_seconds = time.time() - start
    return result


async def analyze_contract_standalone_real(
    contract: dict,
    tool: str,
) -> StandaloneToolResult:
    """
    Real: run a single tool in isolation on one contract.

    Requires Docker containers to be running.
    """
    from app.services.slither_runner import run_slither
    from app.services.mythril_runner import run_mythril
    from app.services.oyente_runner import run_oyente
    from app.services.slither_adapter import slither_to_normalized
    from app.services.mythril_adapter import mythril_to_normalized
    from app.config import settings

    result = StandaloneToolResult(tool=tool, contract_id=contract["id"])
    start = time.time()

    try:
        file_path = Path(contract["selected_path"])
        compose_path = settings.docker_compose_path or settings.slither_compose_path
        known_vulns = set(contract.get("known_vulnerabilities", []))

        if tool == "slither":
            raw = await run_slither(compose_path, file_path)
            findings = slither_to_normalized(raw)
        elif tool == "mythril":
            raw = await run_mythril(compose_path, file_path)
            findings = mythril_to_normalized(raw)
        elif tool == "oyente":
            findings = await run_oyente(compose_path, file_path, timeout=180)
        else:
            findings = []

        detected_types = set(f.vulnerability_type for f in findings)
        result.findings_count = len(findings)
        result.true_positives = len(known_vulns & detected_types)
        result.false_positives = len(detected_types - known_vulns)
        result.false_negatives = len(known_vulns - detected_types)
    except Exception as e:
        print(f"[standalone/{tool}] error: {e}")

    result.time_seconds = time.time() - start
    return result


async def analyze_contract_chatgpt_mock(contract: dict) -> dict[str, Any]:
    """
    Mock: simulate ChatGPT-only audit (no deterministic tools).

    ChatGPT has high recall on well-known vulnerability patterns but
    produces significantly more false positives and is not reproducible.
    """
    import random

    start = time.time()
    await asyncio.sleep(0.08)

    known_vulns = set(contract.get("known_vulnerabilities", []))

    detected: set[str] = set()
    for vuln in known_vulns:
        if random.random() < 0.75:
            detected.add(vuln)

    fp_count = random.randint(1, 5)

    return {
        "tp": len(detected),
        "fp": fp_count,
        "fn": len(known_vulns - detected),
        "time": time.time() - start,
    }


async def analyze_contract_chatgpt_real(contract: dict) -> dict[str, Any]:
    """
    Real: run ChatGPT-only audit (no deterministic tools).

    Sends the raw source code to the LLM and asks it to identify
    vulnerabilities without any tool evidence.  Compares its claims
    against known ground-truth labels.
    """
    from openai import OpenAI
    from app.config import settings

    start = time.time()
    known_vulns = set(contract.get("known_vulnerabilities", []))

    try:
        file_path = Path(contract["selected_path"])
        source_code = file_path.read_text(encoding="utf-8", errors="ignore")

        client = OpenAI(api_key=settings.openai_api_key)
        prompt = (
            "You are a smart contract security auditor.  Analyze the following "
            "Solidity source code and list every vulnerability you find.\n\n"
            "For each vulnerability output EXACTLY one line in the format:\n"
            "VULNERABILITY: <normalised-type>\n\n"
            "Use only these normalised types where applicable: reentrancy, "
            "access-control, integer-overflow, unchecked-return, "
            "timestamp-dependency, front-running, denial-of-service, oracle.\n\n"
            f"Source code:\n```solidity\n{source_code[:8000]}\n```"
        )
        response = client.chat.completions.create(
            model=settings.openai_model,
            messages=[
                {"role": "system", "content": "You are a precise smart contract security auditor."},
                {"role": "user", "content": prompt},
            ],
            timeout=60,
        )
        text = (response.choices[0].message.content or "").strip()

        import re
        detected: set[str] = set()
        for m in re.finditer(r"VULNERABILITY:\s*([^\n]+)", text, re.IGNORECASE):
            detected.add(m.group(1).strip().lower().replace(" ", "-"))

        tp = len(known_vulns & detected)
        fp = len(detected - known_vulns)
        fn = len(known_vulns - detected)
    except Exception as e:
        print(f"[chatgpt-only] error: {e}")
        tp, fp, fn = 0, 0, len(known_vulns)

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "time": time.time() - start,
    }


async def run_comparative_benchmark(
    limit: int | None = None,
    use_mock: bool = True,
) -> tuple[list[ComparativeRow], ComparativeMetrics]:
    """
    Run the full comparative evaluation (RQ4).

    For every contract the benchmark runs:
      1. The hybrid AuditQuant pipeline (all tools + cross-validation + LLM)
      2. Each tool in standalone mode
      3. A ChatGPT-only baseline

    All three approaches are compared on precision, recall, F1,
    false-positive rate, and time-to-audit.
    """
    manifest = load_manifest()
    contracts = manifest["contracts"]
    if limit:
        contracts = contracts[:limit]

    tools = ["slither", "mythril", "oyente"]

    print(f"\n{'='*60}")
    print("AuditQuant Comparative Benchmark (RQ4)")
    print(f"{'='*60}")
    print(f"Contracts: {len(contracts)}")
    print(f"Approaches: hybrid, standalone ({', '.join(tools)}), chatgpt-only")
    print(f"Mode: {'Mock' if use_mock else 'Real'}")
    print(f"{'='*60}\n")

    rows: list[ComparativeRow] = []

    for i, contract in enumerate(contracts, 1):
        print(f"[{i}/{len(contracts)}] {contract['id']}...", end=" ", flush=True)

        row = ComparativeRow(
            contract_id=contract["id"],
            filename=contract["filename"],
            ground_truth_count=len(contract.get("known_vulnerabilities", [])),
        )

        # 1. Hybrid (full AuditQuant pipeline)
        if use_mock:
            hybrid = await analyze_contract_mock(contract)
        else:
            hybrid = await analyze_contract_real(contract)
        row.hybrid_tp = hybrid.true_positives
        row.hybrid_fp = hybrid.false_positives
        row.hybrid_fn = hybrid.false_negatives
        row.hybrid_time = hybrid.total_seconds

        # 2. Standalone tools
        for tool in tools:
            if use_mock:
                st = await analyze_contract_standalone_mock(contract, tool)
            else:
                st = await analyze_contract_standalone_real(contract, tool)
            row.standalone[tool] = {
                "tp": st.true_positives,
                "fp": st.false_positives,
                "fn": st.false_negatives,
                "time": st.time_seconds,
            }

        # 3. ChatGPT-only baseline
        if use_mock:
            gpt = await analyze_contract_chatgpt_mock(contract)
        else:
            gpt = await analyze_contract_chatgpt_real(contract)
        row.chatgpt_tp = gpt["tp"]
        row.chatgpt_fp = gpt["fp"]
        row.chatgpt_fn = gpt["fn"]
        row.chatgpt_time = gpt["time"]

        rows.append(row)
        print("done")

    # Aggregate
    metrics = _compute_comparative_metrics(rows, tools)
    return rows, metrics


def _safe_prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    """Return (precision, recall, f1) with safe division."""
    p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
    return p, r, f1


def _compute_comparative_metrics(
    rows: list[ComparativeRow],
    tools: list[str],
) -> ComparativeMetrics:
    m = ComparativeMetrics(total_contracts=len(rows))

    # Hybrid
    h_tp = sum(r.hybrid_tp for r in rows)
    h_fp = sum(r.hybrid_fp for r in rows)
    h_fn = sum(r.hybrid_fn for r in rows)
    m.hybrid_precision, m.hybrid_recall, m.hybrid_f1 = _safe_prf(h_tp, h_fp, h_fn)
    m.hybrid_fp_rate = h_fp / max(1, h_tp + h_fp)
    m.hybrid_avg_time = sum(r.hybrid_time for r in rows) / max(1, len(rows))

    # Per standalone tool
    for tool in tools:
        t_tp = sum(r.standalone.get(tool, {}).get("tp", 0) for r in rows)
        t_fp = sum(r.standalone.get(tool, {}).get("fp", 0) for r in rows)
        t_fn = sum(r.standalone.get(tool, {}).get("fn", 0) for r in rows)
        p, r, f1 = _safe_prf(t_tp, t_fp, t_fn)
        m.standalone_metrics[tool] = {
            "precision": round(p, 4),
            "recall": round(r, 4),
            "f1": round(f1, 4),
            "fp_rate": round(t_fp / max(1, t_tp + t_fp), 4),
            "avg_time": round(
                sum(r.standalone.get(tool, {}).get("time", 0) for r in rows) / max(1, len(rows)), 4
            ),
        }

    # ChatGPT
    g_tp = sum(r.chatgpt_tp for r in rows)
    g_fp = sum(r.chatgpt_fp for r in rows)
    g_fn = sum(r.chatgpt_fn for r in rows)
    m.chatgpt_precision, m.chatgpt_recall, m.chatgpt_f1 = _safe_prf(g_tp, g_fp, g_fn)
    m.chatgpt_fp_rate = g_fp / max(1, g_tp + g_fp)
    m.chatgpt_avg_time = sum(r.chatgpt_time for r in rows) / max(1, len(rows))

    return m


def print_comparative_summary(m: ComparativeMetrics):
    """Pretty-print the comparative evaluation results."""
    print(f"\n{'='*72}")
    print("COMPARATIVE EVALUATION SUMMARY  (RQ4)")
    print(f"{'='*72}")
    print(f"Contracts evaluated: {m.total_contracts}\n")

    header = f"{'Approach':<20} {'Precision':>10} {'Recall':>10} {'F1':>10} {'FP Rate':>10} {'Avg Time':>10}"
    print(header)
    print("-" * len(header))

    print(f"{'AuditQuant (hybrid)':<20} {m.hybrid_precision:>10.1%} {m.hybrid_recall:>10.1%} "
          f"{m.hybrid_f1:>10.1%} {m.hybrid_fp_rate:>10.1%} {m.hybrid_avg_time:>9.2f}s")

    for tool, sm in m.standalone_metrics.items():
        print(f"{tool:<20} {sm['precision']:>10.1%} {sm['recall']:>10.1%} "
              f"{sm['f1']:>10.1%} {sm['fp_rate']:>10.1%} {sm['avg_time']:>9.2f}s")

    print(f"{'ChatGPT-only':<20} {m.chatgpt_precision:>10.1%} {m.chatgpt_recall:>10.1%} "
          f"{m.chatgpt_f1:>10.1%} {m.chatgpt_fp_rate:>10.1%} {m.chatgpt_avg_time:>9.2f}s")

    print(f"\n{'='*72}\n")


def save_comparative_results(
    rows: list[ComparativeRow],
    metrics: ComparativeMetrics,
    run_id: str,
) -> Path:
    """Save comparative benchmark results to JSON."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    output = {
        "run_id": run_id,
        "timestamp": datetime.utcnow().isoformat(),
        "mode": "comparative",
        "metrics": asdict(metrics),
        "per_contract": [asdict(r) for r in rows],
    }
    output_path = RESULTS_DIR / f"comparative_{run_id}.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    return output_path


# ---------------------------------------------------------------------------
# Performance graph generation
# ---------------------------------------------------------------------------

def generate_performance_graphs(
    metrics: BenchmarkMetrics,
    run_id: str,
    comparative_metrics: ComparativeMetrics | None = None,
) -> list[Path]:
    """
    Generate performance graphs for the evaluation results.

    Produces up to five charts aligned with the report's key metrics:
      1. Tool Coverage — findings per tool
      2. Hallucination Suppression — before/after claim verification
      3. False Positive Rate — per approach (comparative)
      4. Business Risk Accuracy — consensus rates
      5. Time to Audit — per approach
    """
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed — skipping graph generation")
        return []

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    graphs_dir = RESULTS_DIR / "graphs"
    graphs_dir.mkdir(exist_ok=True)
    generated: list[Path] = []

    plt.rcParams.update({
        "figure.facecolor": "#0f172a",
        "axes.facecolor": "#1e293b",
        "axes.edgecolor": "#334155",
        "axes.labelcolor": "#e2e8f0",
        "text.color": "#e2e8f0",
        "xtick.color": "#94a3b8",
        "ytick.color": "#94a3b8",
        "grid.color": "#334155",
        "grid.alpha": 0.5,
    })

    # ── 1. Tool Coverage ──────────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(8, 5))
    tools = list(metrics.tool_metrics.keys())
    counts = [metrics.tool_metrics[t]["total_findings"] for t in tools]
    colours = ["#38bdf8", "#818cf8", "#34d399"][:len(tools)]
    ax.bar(tools, counts, color=colours, edgecolor="none", width=0.5)
    ax.set_title("Tool Coverage — Findings per Tool", fontsize=14, pad=12)
    ax.set_ylabel("Total Findings")
    ax.grid(axis="y")
    path = graphs_dir / f"tool_coverage_{run_id}.png"
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    generated.append(path)

    # ── 2. Hallucination Suppression ──────────────────────────────────
    fig, ax = plt.subplots(figsize=(8, 5))
    labels = ["Before Verification\n(Raw LLM Claims)", "After Verification\n(Verified Claims)"]
    values = [metrics.total_llm_claims, metrics.total_verified]
    bars = ax.bar(labels, values, color=["#f87171", "#34d399"], edgecolor="none", width=0.45)
    ax.set_title("Hallucination Suppression (RQ2)", fontsize=14, pad=12)
    ax.set_ylabel("Number of Claims")
    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5,
                str(val), ha="center", va="bottom", fontsize=11)
    ax.grid(axis="y")
    path = graphs_dir / f"hallucination_suppression_{run_id}.png"
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    generated.append(path)

    # ── 3 – 5: Comparative graphs (only when comparative metrics exist) ─
    if comparative_metrics is not None:
        cm = comparative_metrics
        approaches = ["AuditQuant\n(Hybrid)"]
        fp_rates = [cm.hybrid_fp_rate]
        f1_scores = [cm.hybrid_f1]
        avg_times = [cm.hybrid_avg_time]
        approach_colours = ["#38bdf8"]

        for tool_name, sm in cm.standalone_metrics.items():
            approaches.append(tool_name.capitalize())
            fp_rates.append(sm["fp_rate"])
            f1_scores.append(sm["f1"])
            avg_times.append(sm["avg_time"])
            approach_colours.append("#818cf8")

        approaches.append("ChatGPT\nOnly")
        fp_rates.append(cm.chatgpt_fp_rate)
        f1_scores.append(cm.chatgpt_f1)
        avg_times.append(cm.chatgpt_avg_time)
        approach_colours.append("#f87171")

        # 3. False Positive Rate
        fig, ax = plt.subplots(figsize=(10, 5))
        ax.bar(approaches, [r * 100 for r in fp_rates], color=approach_colours, edgecolor="none", width=0.5)
        ax.set_title("False Positive Rate by Approach (RQ4)", fontsize=14, pad=12)
        ax.set_ylabel("False Positive Rate (%)")
        ax.grid(axis="y")
        path = graphs_dir / f"false_positive_rate_{run_id}.png"
        fig.tight_layout()
        fig.savefig(path, dpi=150)
        plt.close(fig)
        generated.append(path)

        # 4. F1 Score / Business Risk Accuracy
        fig, ax = plt.subplots(figsize=(10, 5))
        ax.bar(approaches, [s * 100 for s in f1_scores], color=approach_colours, edgecolor="none", width=0.5)
        ax.set_title("Detection Accuracy — F1 Score (RQ4)", fontsize=14, pad=12)
        ax.set_ylabel("F1 Score (%)")
        ax.set_ylim(0, 105)
        ax.grid(axis="y")
        path = graphs_dir / f"f1_score_{run_id}.png"
        fig.tight_layout()
        fig.savefig(path, dpi=150)
        plt.close(fig)
        generated.append(path)

        # 5. Time to Audit
        fig, ax = plt.subplots(figsize=(10, 5))
        ax.bar(approaches, avg_times, color=approach_colours, edgecolor="none", width=0.5)
        ax.set_title("Average Time to Audit per Contract (RQ4)", fontsize=14, pad=12)
        ax.set_ylabel("Time (seconds)")
        ax.grid(axis="y")
        path = graphs_dir / f"time_to_audit_{run_id}.png"
        fig.tight_layout()
        fig.savefig(path, dpi=150)
        plt.close(fig)
        generated.append(path)

    print(f"\nGenerated {len(generated)} performance graph(s) in {graphs_dir}/")
    return generated


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Run AuditQuant benchmark")
    parser.add_argument("--limit", type=int, help="Limit number of contracts")
    parser.add_argument("--real", action="store_true", help="Use real analysis (requires Docker)")
    parser.add_argument("--tools", type=str, help="Comma-separated list of tools")
    parser.add_argument(
        "--mode",
        choices=["standard", "compare"],
        default="standard",
        help="'standard' runs hybrid only; 'compare' runs hybrid vs standalone vs ChatGPT (RQ4)",
    )
    args = parser.parse_args()

    run_id = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    if args.mode == "compare":
        rows, comp_metrics = asyncio.run(run_comparative_benchmark(
            limit=args.limit,
            use_mock=not args.real,
        ))
        output_path = save_comparative_results(rows, comp_metrics, run_id)
        print_comparative_summary(comp_metrics)

        # Also run the standard benchmark to get per-tool metrics for graphs
        results, metrics = asyncio.run(run_benchmark(
            limit=args.limit,
            use_mock=not args.real,
        ))
        save_results(results, metrics, run_id)
        generate_performance_graphs(metrics, run_id, comparative_metrics=comp_metrics)
        print(f"Comparative results saved to: {output_path}")
    else:
        tools = args.tools.split(",") if args.tools else None

        results, metrics = asyncio.run(run_benchmark(
            limit=args.limit,
            use_mock=not args.real,
            tools=tools,
        ))

        output_path = save_results(results, metrics, run_id)
        print_summary(metrics)
        generate_performance_graphs(metrics, run_id)
        print(f"Results saved to: {output_path}")


if __name__ == "__main__":
    main()
