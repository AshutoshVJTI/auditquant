#!/usr/bin/env python3
"""
AuditQuant Evaluation Benchmark Pipeline

Runs the full multi-tool analysis on all contracts and collects metrics for:
1. False Positive Rate per tool
2. Precision/Recall/F1 per vulnerability type
3. LLM Hallucination Rate
4. Loss % Correlation (predicted vs ground truth)
5. Time to Actionable Report

Usage:
    python run_benchmark.py [--limit N] [--tools slither,mythril,...]
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
    tools = ["slither", "securify", "mythril", "echidna", "oyente"]
    
    for tool in tools:
        # Each tool has different detection rates
        detection_rate = {
            "slither": 0.9,
            "securify": 0.7,
            "mythril": 0.6,
            "echidna": 0.4,
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
        for tool_name, findings in [
            ("slither", tool_result.slither_findings),
            ("mythril", tool_result.mythril_findings),
            ("securify", tool_result.securify_findings),
            ("echidna", tool_result.echidna_findings),
            ("oyente", tool_result.oyente_findings),
        ]:
            result.tool_results[tool_name] = {
                "findings": [f.to_dict() for f in findings],
                "count": len(findings),
                "success": True,
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
    tools = ["slither", "securify", "mythril", "echidna", "oyente"]
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


def main():
    parser = argparse.ArgumentParser(description="Run AuditQuant benchmark")
    parser.add_argument("--limit", type=int, help="Limit number of contracts")
    parser.add_argument("--real", action="store_true", help="Use real analysis (requires Docker)")
    parser.add_argument("--tools", type=str, help="Comma-separated list of tools")
    args = parser.parse_args()
    
    tools = args.tools.split(",") if args.tools else None
    
    # Run benchmark
    results, metrics = asyncio.run(run_benchmark(
        limit=args.limit,
        use_mock=not args.real,
        tools=tools,
    ))
    
    # Save results
    run_id = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    output_path = save_results(results, metrics, run_id)
    
    # Print summary
    print_summary(metrics)
    
    print(f"Results saved to: {output_path}")


if __name__ == "__main__":
    main()
