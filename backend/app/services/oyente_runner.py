"""
Oyente Runner

Symbolic execution tool for smart contract analysis (baseline comparator).
https://github.com/enzymefinance/oyente

Note: Oyente is an older tool, used primarily as a baseline for comparison
with modern tools. It supports a limited set of vulnerability patterns.
"""
from __future__ import annotations

import asyncio
import json
import re
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


# Oyente vulnerability type mappings
OYENTE_VULN_MAP = {
    "callstack": "denial-of-service",
    "money_concurrency": "front-running",  # TOD
    "time_dependency": "timestamp-dependency",
    "reentrancy": "reentrancy",
    "assertion_failure": "assertion-failure",
    "integer_overflow": "integer-overflow",
    "integer_underflow": "integer-overflow",
    "parity_multisig_bug_2": "access-control",
}

# SWC mappings
OYENTE_SWC_MAP = {
    "callstack": "SWC-113",
    "money_concurrency": "SWC-114",
    "time_dependency": "SWC-116",
    "reentrancy": "SWC-107",
    "assertion_failure": "SWC-110",
    "integer_overflow": "SWC-101",
    "integer_underflow": "SWC-101",
    "parity_multisig_bug_2": "SWC-124",
}


def parse_oyente_output(output: str, contract_file: str) -> list[NormalizedFinding]:
    """
    Parse Oyente output into normalized findings.
    
    Oyente outputs text-based results. We parse both JSON (if available)
    and the text output format.
    
    Text format example:
    ============ Results ===========
    INFO:root:contract <ContractName>:
    INFO:symExec:   Callstack Depth Attack Vulnerability: True
    INFO:symExec:   Re-Entrancy Vulnerability: False
    """
    findings: list[NormalizedFinding] = []
    finding_id = 0
    
    # Try JSON parsing first
    try:
        json_match = re.search(r'\{[\s\S]*\}', output)
        if json_match:
            payload = json.loads(json_match.group())
            return _parse_oyente_json(payload, contract_file)
    except json.JSONDecodeError:
        pass
    
    # Fall back to text parsing
    current_contract = None
    
    # Pattern to match vulnerability lines
    vuln_pattern = re.compile(
        r'(Callstack Depth Attack|Re-Entrancy|Time.?[Dd]ependency|'
        r'Integer Overflow|Integer Underflow|Assertion Failure|'
        r'Money.?[Cc]oncurrency|Parity).+?:\s*(True|False)',
        re.IGNORECASE
    )
    
    contract_pattern = re.compile(r'contract\s+(\w+):', re.IGNORECASE)
    
    for line in output.split('\n'):
        # Check for contract name
        contract_match = contract_pattern.search(line)
        if contract_match:
            current_contract = contract_match.group(1)
            continue
        
        # Check for vulnerability
        vuln_match = vuln_pattern.search(line)
        if vuln_match:
            vuln_name = vuln_match.group(1).lower().replace(" ", "_").replace("-", "_")
            is_vulnerable = vuln_match.group(2).lower() == "true"
            
            if is_vulnerable:
                finding_id += 1
                vuln_type = _normalize_oyente_vuln(vuln_name)
                
                findings.append(
                    NormalizedFinding(
                        id=f"OYE-{finding_id}",
                        tool=ToolSource.OYENTE,
                        analysis_type=AnalysisType.SYMBOLIC,
                        vulnerability_type=normalize_vuln_type(vuln_type),
                        title=f"Oyente: {_format_vuln_name(vuln_name)}",
                        description=f"Oyente symbolic execution detected {_format_vuln_name(vuln_name)} vulnerability",
                        severity=_get_oyente_severity(vuln_type),
                        severity_score=_get_oyente_severity_score(vuln_type),
                        confidence=0.7,  # Oyente has moderate confidence
                        location=Location(
                            filename=contract_file,
                            contract_name=current_contract,
                        ),
                        swc_id=OYENTE_SWC_MAP.get(vuln_type),
                        is_reachable=True,  # Symbolic execution proves reachability
                        has_exploit_proof=False,  # Oyente doesn't provide traces
                        raw={"line": line, "vuln_name": vuln_name},
                    )
                )
    
    return findings


def _parse_oyente_json(payload: dict, contract_file: str) -> list[NormalizedFinding]:
    """Parse Oyente JSON output format."""
    findings: list[NormalizedFinding] = []
    finding_id = 0
    
    for contract_name, vulns in payload.items():
        if not isinstance(vulns, dict):
            continue
            
        for vuln_name, is_vulnerable in vulns.items():
            if not is_vulnerable:
                continue
                
            finding_id += 1
            vuln_type = _normalize_oyente_vuln(vuln_name)
            
            findings.append(
                NormalizedFinding(
                    id=f"OYE-{finding_id}",
                    tool=ToolSource.OYENTE,
                    analysis_type=AnalysisType.SYMBOLIC,
                    vulnerability_type=normalize_vuln_type(vuln_type),
                    title=f"Oyente: {_format_vuln_name(vuln_name)}",
                    description=f"Oyente detected {_format_vuln_name(vuln_name)} in {contract_name}",
                    severity=_get_oyente_severity(vuln_type),
                    severity_score=_get_oyente_severity_score(vuln_type),
                    confidence=0.7,
                    location=Location(
                        filename=contract_file,
                        contract_name=contract_name,
                    ),
                    swc_id=OYENTE_SWC_MAP.get(vuln_type),
                    is_reachable=True,
                    has_exploit_proof=False,
                    raw={"contract": contract_name, "vuln": vuln_name},
                )
            )
    
    return findings


def _normalize_oyente_vuln(vuln_name: str) -> str:
    """Normalize Oyente vulnerability names."""
    key = vuln_name.lower().replace(" ", "_").replace("-", "_")
    
    # Handle common variations
    if "callstack" in key:
        return "callstack"
    if "reentr" in key:
        return "reentrancy"
    if "time" in key and "depend" in key:
        return "time_dependency"
    if "overflow" in key:
        return "integer_overflow"
    if "underflow" in key:
        return "integer_underflow"
    if "money" in key or "concurrency" in key:
        return "money_concurrency"
    if "assertion" in key:
        return "assertion_failure"
    if "parity" in key:
        return "parity_multisig_bug_2"
    
    return OYENTE_VULN_MAP.get(key, key)


def _format_vuln_name(vuln_name: str) -> str:
    """Format vulnerability name for display."""
    return vuln_name.replace("_", " ").title()


def _get_oyente_severity(vuln_type: str) -> Severity:
    """Get severity level for Oyente vulnerability type."""
    high_severity = {"reentrancy", "integer_overflow", "integer_underflow", "parity_multisig_bug_2"}
    medium_severity = {"money_concurrency", "time_dependency"}
    
    if vuln_type in high_severity:
        return Severity.HIGH
    if vuln_type in medium_severity:
        return Severity.MEDIUM
    return Severity.LOW


def _get_oyente_severity_score(vuln_type: str) -> float:
    """Get severity score for Oyente vulnerability type."""
    scores = {
        "reentrancy": 90.0,
        "integer_overflow": 80.0,
        "integer_underflow": 80.0,
        "parity_multisig_bug_2": 85.0,
        "money_concurrency": 60.0,
        "time_dependency": 50.0,
        "callstack": 40.0,
        "assertion_failure": 30.0,
    }
    return scores.get(vuln_type, 30.0)


async def run_oyente(
    compose_path: str, 
    solidity_path: Path,
    timeout: int = 180,
) -> list[NormalizedFinding]:
    """
    Run Oyente in Docker and return normalized findings.
    
    Args:
        compose_path: Path to docker-compose.yml
        solidity_path: Path to Solidity file to analyze
        timeout: Timeout in seconds (default: 180)
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
        "oyente",
        "-s",
        f"/work/{relative_target.as_posix()}",
        "-ce",  # Enable all checks
    ]
    
    process = await asyncio.create_subprocess_exec(
        *command,
        cwd=str(project_root),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    
    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout
        )
    except asyncio.TimeoutError:
        process.kill()
        await process.communicate()
        raise RuntimeError(f"Oyente timed out after {timeout} seconds")
    
    # Oyente returns 0 on success, non-zero on errors
    if process.returncode != 0:
        stderr_text = stderr.decode().strip()
        # Check if it's a real error vs just findings
        if "error" in stderr_text.lower() and "solc" in stderr_text.lower():
            raise RuntimeError(f"Oyente compilation failed: {stderr_text}")

    output = stdout.decode() + stderr.decode()  # Oyente mixes stdout/stderr
    return parse_oyente_output(output, solidity_path.name)
