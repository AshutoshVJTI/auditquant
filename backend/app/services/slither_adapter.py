"""
Slither Adapter

Converts Slither output to normalized findings.
"""
from __future__ import annotations

from app.services.normalized_finding import (
    AnalysisType,
    Location,
    NormalizedFinding,
    Severity,
    ToolSource,
    normalize_vuln_type,
)
from app.services.slither_runner import SlitherFinding


# Slither severity mapping
SLITHER_SEVERITY_MAP = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFO,
    "Optimization": Severity.INFO,
}

# Slither check to SWC mapping
SLITHER_SWC_MAP = {
    "reentrancy-eth": "SWC-107",
    "reentrancy-no-eth": "SWC-107",
    "reentrancy-benign": "SWC-107",
    "reentrancy-events": "SWC-107",
    "unprotected-upgrade": "SWC-105",
    "arbitrary-send": "SWC-105",
    "suicidal": "SWC-106",
    "controlled-delegatecall": "SWC-112",
    "tx-origin": "SWC-115",
    "timestamp": "SWC-116",
    "weak-prng": "SWC-120",
    "unchecked-lowlevel": "SWC-104",
    "unchecked-send": "SWC-104",
    "locked-ether": "SWC-132",
}

# Confidence to float mapping
CONFIDENCE_MAP = {
    "High": 0.95,
    "Medium": 0.75,
    "Low": 0.5,
}


def slither_to_normalized(findings: list[SlitherFinding]) -> list[NormalizedFinding]:
    """Convert Slither findings to normalized format."""
    normalized: list[NormalizedFinding] = []
    
    for idx, finding in enumerate(findings, start=1):
        location = _parse_slither_location(finding.location)
        severity = SLITHER_SEVERITY_MAP.get(finding.impact, Severity.MEDIUM)
        confidence = CONFIDENCE_MAP.get(finding.confidence, 0.5)
        
        normalized.append(
            NormalizedFinding(
                id=f"SLI-{idx}",
                tool=ToolSource.SLITHER,
                analysis_type=AnalysisType.STATIC,
                vulnerability_type=normalize_vuln_type(finding.title),
                title=finding.title,
                description=finding.description,
                severity=severity,
                severity_score=0.0,  # Will be auto-calculated
                confidence=confidence,
                location=location,
                swc_id=SLITHER_SWC_MAP.get(finding.title.lower()),
                is_reachable=False,  # Static analysis can't prove reachability
                has_exploit_proof=False,
                raw=finding.raw,
            )
        )
    
    return normalized


def _parse_slither_location(location_str: str | None) -> Location | None:
    """Parse Slither location string to Location object."""
    if not location_str:
        return None
    
    location = Location()
    
    # Format: filename:start:length
    parts = location_str.split(":")
    if len(parts) >= 1:
        location.filename = parts[0]
    if len(parts) >= 2:
        try:
            location.line_start = int(parts[1])
        except ValueError:
            pass
    
    return location
