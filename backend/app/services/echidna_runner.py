"""
Echidna Runner

Property-based fuzzer for smart contracts.
https://github.com/crytic/echidna
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from app.services.normalized_finding import (
    AnalysisType,
    ExploitTrace,
    Location,
    NormalizedFinding,
    Severity,
    ToolSource,
    normalize_vuln_type,
)


# Map Echidna test types to vulnerability categories
ECHIDNA_VULN_MAP = {
    "assertion": "assertion-failure",
    "property": "invariant-violation",
    "optimization": "gas-optimization",
    "overflow": "integer-overflow",
    "reentrancy": "reentrancy",
}

# SWC mappings for common Echidna findings
ECHIDNA_SWC_MAP = {
    "assertion-failure": "SWC-110",
    "invariant-violation": "SWC-110",
    "integer-overflow": "SWC-101",
    "reentrancy": "SWC-107",
}


def parse_echidna_output(payload: dict | list, contract_file: str) -> list[NormalizedFinding]:
    """
    Parse Echidna JSON output into normalized findings.
    
    Echidna output structure (corpus format):
    {
        "tests": [
            {
                "name": "test_propertyName",
                "status": "passed" | "failed" | "shrunk",
                "events": [...],
                "transactions": [
                    {
                        "contract": "ContractName",
                        "function": "functionName",
                        "arguments": [...],
                        "value": "0",
                        "gas": 12345
                    }
                ],
                "seed": 12345,
                "coverage": {...}
            }
        ],
        "fuzzing_mode": "property" | "assertion" | "optimization"
    }
    """
    findings: list[NormalizedFinding] = []
    finding_id = 0
    
    # Handle both dict and list formats
    if isinstance(payload, list):
        tests = payload
        fuzzing_mode = "property"
    else:
        tests = payload.get("tests", payload.get("results", []))
        fuzzing_mode = payload.get("fuzzing_mode", "property")
    
    for test in tests:
        if not isinstance(test, dict):
            continue
            
        status = test.get("status", test.get("result", "")).lower()
        
        # Only report failed/shrunk tests (these are vulnerabilities)
        if status not in ("failed", "shrunk", "falsified"):
            continue
        
        finding_id += 1
        test_name = test.get("name", test.get("property", f"test_{finding_id}"))
        
        # Extract exploit trace (transaction sequence that triggers the bug)
        exploit_trace = _extract_echidna_trace(test)
        
        # Determine vulnerability type from test name or mode
        vuln_type = _infer_vuln_type(test_name, fuzzing_mode)
        
        # Extract location info
        location = _extract_echidna_location(test, contract_file)
        
        findings.append(
            NormalizedFinding(
                id=f"ECH-{finding_id}",
                tool=ToolSource.ECHIDNA,
                analysis_type=AnalysisType.FUZZING,
                vulnerability_type=normalize_vuln_type(vuln_type),
                title=f"Fuzzing Failed: {test_name}",
                description=_build_echidna_description(test, test_name),
                severity=Severity.HIGH,  # Echidna only reports if it found a real bug
                severity_score=90.0,
                confidence=0.99,  # Fuzzer provides concrete proof
                location=location,
                exploit_trace=exploit_trace,
                swc_id=ECHIDNA_SWC_MAP.get(vuln_type),
                is_reachable=True,  # Echidna proves reachability
                has_exploit_proof=exploit_trace.has_proof,
                raw=test,
            )
        )
    
    return findings


def _extract_echidna_trace(test: dict) -> ExploitTrace:
    """Extract the transaction sequence that triggers the vulnerability."""
    transactions = test.get("transactions", test.get("sequence", []))
    events = test.get("events", [])
    
    steps = []
    input_sequence = []
    
    for tx in transactions:
        if isinstance(tx, dict):
            step = {
                "contract": tx.get("contract", tx.get("destination", "")),
                "function": tx.get("function", tx.get("call", "")),
                "arguments": tx.get("arguments", tx.get("args", [])),
                "value": tx.get("value", "0"),
                "gas": tx.get("gas", tx.get("gasLimit", 0)),
            }
            steps.append(step)
            
            # Build human-readable input sequence
            func = step["function"]
            args = step["arguments"]
            if func:
                input_sequence.append(f"{func}({', '.join(map(str, args))})")
    
    return ExploitTrace(
        steps=steps,
        input_sequence=input_sequence,
        transaction_data=transactions if isinstance(transactions, list) else [],
    )


def _extract_echidna_location(test: dict, filename: str) -> Location:
    """Extract location from Echidna test data."""
    location = Location(filename=filename)
    
    # Try to get contract/function from first transaction
    transactions = test.get("transactions", test.get("sequence", []))
    if transactions and isinstance(transactions[0], dict):
        tx = transactions[0]
        location.contract_name = tx.get("contract", tx.get("destination"))
        location.function_name = tx.get("function", tx.get("call"))
    
    return location


def _infer_vuln_type(test_name: str, fuzzing_mode: str) -> str:
    """Infer vulnerability type from test name and fuzzing mode."""
    name_lower = test_name.lower()
    
    # Check for common patterns in test names
    if "reentr" in name_lower:
        return "reentrancy"
    if "overflow" in name_lower or "underflow" in name_lower:
        return "integer-overflow"
    if "access" in name_lower or "auth" in name_lower or "owner" in name_lower:
        return "access-control"
    if "balance" in name_lower or "drain" in name_lower:
        return "arbitrary-send"
    
    # Fall back to fuzzing mode
    return ECHIDNA_VULN_MAP.get(fuzzing_mode, "invariant-violation")


def _build_echidna_description(test: dict, test_name: str) -> str:
    """Build a descriptive message for the finding."""
    transactions = test.get("transactions", test.get("sequence", []))
    tx_count = len(transactions)
    
    desc = f"Echidna fuzzer falsified property '{test_name}' "
    
    if tx_count > 0:
        desc += f"with a sequence of {tx_count} transaction(s). "
        
        # Show first and last transaction
        if transactions and isinstance(transactions[0], dict):
            first_tx = transactions[0]
            func = first_tx.get("function", first_tx.get("call", "unknown"))
            desc += f"Attack starts with call to {func}. "
    
    if test.get("seed"):
        desc += f"[seed: {test['seed']}]"
    
    return desc


async def run_echidna(
    compose_path: str, 
    solidity_path: Path,
    config_path: Path | None = None,
    test_limit: int = 50000,
    timeout: int = 300,
) -> list[NormalizedFinding]:
    """
    Run Echidna fuzzer in Docker and return normalized findings.
    
    Args:
        compose_path: Path to docker-compose.yml
        solidity_path: Path to Solidity file to analyze
        config_path: Optional path to Echidna config YAML
        test_limit: Maximum number of test sequences (default: 50000)
        timeout: Timeout in seconds (default: 300)
    """
    project_root = Path(__file__).resolve().parents[3]
    compose_file = Path(compose_path)
    if not compose_file.is_absolute():
        compose_file = project_root / compose_file

    relative_target = solidity_path.resolve().relative_to(project_root)

    command = [
        "docker",
        "compose",
        "-f",
        str(compose_file),
        "run",
        "--rm",
        "echidna",
        f"/work/{relative_target.as_posix()}",
        "--format",
        "json",
        "--test-limit",
        str(test_limit),
        "--timeout",
        str(timeout),
    ]
    
    # Add config if provided
    if config_path and config_path.exists():
        relative_config = config_path.resolve().relative_to(project_root)
        command.extend(["--config", f"/work/{relative_config.as_posix()}"])
    
    process = await asyncio.create_subprocess_exec(
        *command,
        cwd=str(project_root),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    
    # Echidna returns non-zero if it found bugs (which is what we want!)
    # Only fail on actual errors
    if process.returncode != 0 and process.returncode != 1:
        stderr_text = stderr.decode().strip()
        if "error" in stderr_text.lower() and "compilation" in stderr_text.lower():
            raise RuntimeError(f"Echidna compilation failed: {stderr_text}")

    try:
        # Echidna outputs one JSON object per line
        output = stdout.decode().strip()
        if not output:
            return []
        
        # Try parsing as single JSON first
        try:
            payload = json.loads(output)
        except json.JSONDecodeError:
            # Try parsing as newline-delimited JSON
            lines = output.split("\n")
            payload = []
            for line in lines:
                line = line.strip()
                if line and line.startswith("{"):
                    try:
                        payload.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    except Exception:
        return []
    
    return parse_echidna_output(payload, solidity_path.name)
