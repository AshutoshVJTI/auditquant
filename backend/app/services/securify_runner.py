"""
Securify2 Runner

Static analysis tool using semantic patterns for vulnerability detection.
https://github.com/eth-sri/securify2
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from app.services.normalized_finding import (
    AnalysisType,
    ExploitTrace,
    Location,
    NormalizedFinding,
    Severity,
    ToolSource,
    normalize_vuln_type,
)


# Securify severity mapping
SECURIFY_SEVERITY_MAP = {
    "violation": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "safe": Severity.INFO,
    "conflict": Severity.MEDIUM,
}

# Securify pattern to SWC mapping
SECURIFY_SWC_MAP = {
    "DAO": "SWC-107",
    "DAOConstantGas": "SWC-107",
    "TODReceiver": "SWC-114",
    "TODAmount": "SWC-114",
    "TODTransfer": "SWC-114",
    "UnrestrictedWrite": "SWC-124",
    "UnrestrictedEtherFlow": "SWC-105",
    "MissingInputValidation": "SWC-115",
    "UnhandledException": "SWC-104",
    "LockedEther": "SWC-132",
    "ReentrancyNoETH": "SWC-107",
    "ReentrancyBenign": "SWC-107",
}


def parse_securify_output(payload: dict, contract_file: str) -> list[NormalizedFinding]:
    """
    Parse Securify2 JSON output into normalized findings.
    
    Securify output structure:
    {
        "ContractName": {
            "results": {
                "PatternName": {
                    "violations": [...],
                    "warnings": [...],
                    "safe": [...],
                    "conflicts": [...]
                }
            }
        }
    }
    """
    findings: list[NormalizedFinding] = []
    finding_id = 0
    
    for contract_name, contract_data in payload.items():
        if not isinstance(contract_data, dict):
            continue
            
        results = contract_data.get("results", {})
        
        for pattern_name, pattern_results in results.items():
            if not isinstance(pattern_results, dict):
                continue
            
            # Process violations (definite issues)
            for violation in pattern_results.get("violations", []):
                finding_id += 1
                location = _parse_securify_location(violation, contract_name, contract_file)
                
                findings.append(
                    NormalizedFinding(
                        id=f"SEC-{finding_id}",
                        tool=ToolSource.SECURIFY,
                        analysis_type=AnalysisType.STATIC,
                        vulnerability_type=normalize_vuln_type(pattern_name),
                        title=f"{pattern_name} Violation",
                        description=f"Securify detected a definite {pattern_name} vulnerability in {contract_name}",
                        severity=Severity.HIGH,
                        severity_score=90.0,
                        confidence=0.95,
                        location=location,
                        swc_id=SECURIFY_SWC_MAP.get(pattern_name),
                        is_reachable=False,
                        has_exploit_proof=False,
                        raw={"pattern": pattern_name, "type": "violation", "data": violation},
                    )
                )
            
            # Process warnings (potential issues)
            for warning in pattern_results.get("warnings", []):
                finding_id += 1
                location = _parse_securify_location(warning, contract_name, contract_file)
                
                findings.append(
                    NormalizedFinding(
                        id=f"SEC-{finding_id}",
                        tool=ToolSource.SECURIFY,
                        analysis_type=AnalysisType.STATIC,
                        vulnerability_type=normalize_vuln_type(pattern_name),
                        title=f"{pattern_name} Warning",
                        description=f"Securify detected a potential {pattern_name} issue in {contract_name}",
                        severity=Severity.MEDIUM,
                        severity_score=60.0,
                        confidence=0.7,
                        location=location,
                        swc_id=SECURIFY_SWC_MAP.get(pattern_name),
                        is_reachable=False,
                        has_exploit_proof=False,
                        raw={"pattern": pattern_name, "type": "warning", "data": warning},
                    )
                )
            
            # Process conflicts (tool uncertainty)
            for conflict in pattern_results.get("conflicts", []):
                finding_id += 1
                location = _parse_securify_location(conflict, contract_name, contract_file)
                
                findings.append(
                    NormalizedFinding(
                        id=f"SEC-{finding_id}",
                        tool=ToolSource.SECURIFY,
                        analysis_type=AnalysisType.STATIC,
                        vulnerability_type=normalize_vuln_type(pattern_name),
                        title=f"{pattern_name} Conflict",
                        description=f"Securify found conflicting evidence for {pattern_name} in {contract_name}",
                        severity=Severity.LOW,
                        severity_score=30.0,
                        confidence=0.4,
                        location=location,
                        swc_id=SECURIFY_SWC_MAP.get(pattern_name),
                        is_reachable=False,
                        has_exploit_proof=False,
                        raw={"pattern": pattern_name, "type": "conflict", "data": conflict},
                    )
                )
    
    return findings


def _parse_securify_location(data: dict | str | int, contract_name: str, filename: str) -> Location:
    """Extract location from Securify finding data."""
    location = Location(
        filename=filename,
        contract_name=contract_name,
    )
    
    if isinstance(data, dict):
        if "line" in data:
            location.line_start = data["line"]
        if "function" in data:
            location.function_name = data["function"]
    elif isinstance(data, int):
        # Sometimes Securify just returns line numbers
        location.line_start = data
    
    return location


async def run_securify(compose_path: str, solidity_path: Path) -> list[NormalizedFinding]:
    """Run Securify2 in Docker and return normalized findings."""
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
        "securify",
        "-fs",
        f"/work/{relative_target.as_posix()}",
        "-o",
        "json",
    ]
    
    process = await asyncio.create_subprocess_exec(
        *command,
        cwd=str(project_root),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    
    # Securify returns 0 even with findings, non-zero only on errors
    if process.returncode != 0 and b"error" in stderr.lower():
        raise RuntimeError(
            f"Securify failed with exit code {process.returncode}: {stderr.decode().strip()}"
        )

    try:
        payload = json.loads(stdout.decode())
    except json.JSONDecodeError:
        # Securify sometimes outputs non-JSON warnings before the JSON
        output = stdout.decode()
        json_start = output.find("{")
        if json_start != -1:
            payload = json.loads(output[json_start:])
        else:
            return []
    
    return parse_securify_output(payload, solidity_path.name)
