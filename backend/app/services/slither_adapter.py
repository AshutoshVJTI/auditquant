# Slither → NormalizedFinding conversion

from app.services.normalized_finding import (
    AnalysisType,
    Location,
    NormalizedFinding,
    Severity,
    ToolSource,
    normalize_vuln_type,
)
from app.services.confidence_loader import slither_tier
from app.services.slither_runner import SlitherFinding


SLITHER_SEVERITY_MAP = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFO,
    "Optimization": Severity.INFO,
}

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

def slither_to_normalized(findings: list[SlitherFinding]) -> list[NormalizedFinding]:
    normalized: list[NormalizedFinding] = []

    for idx, finding in enumerate(findings, start=1):
        location = _parse_slither_location(finding)
        severity = SLITHER_SEVERITY_MAP.get(finding.impact, Severity.MEDIUM)
        confidence = slither_tier(finding.confidence)
        
        normalized.append(
            NormalizedFinding(
                id=f"SLI-{idx}",
                tool=ToolSource.SLITHER,
                analysis_type=AnalysisType.STATIC,
                vulnerability_type=normalize_vuln_type(finding.title),
                title=finding.title,
                description=finding.description,
                severity=severity,
                severity_score=0.0,  # gets set in __post_init__
                confidence=confidence,
                location=location,
                swc_id=SLITHER_SWC_MAP.get(finding.title.lower()),
                is_reachable=False,
                has_exploit_proof=False,
                raw=finding.raw,
            )
        )
    
    return normalized


def _parse_slither_location(finding: SlitherFinding) -> Location | None:
    # source_mapping.start is a byte offset; use source_mapping.lines for real line numbers
    raw = finding.raw
    if isinstance(raw, dict):
        elements = raw.get("elements") or []
        if elements:
            source = elements[0].get("source_mapping") or {}
            lines = source.get("lines")
            fn = source.get("filename_relative") or source.get("filename")
            if isinstance(lines, list) and lines:
                numeric = [x for x in lines if isinstance(x, int)]
                if numeric:
                    loc = Location(filename=fn if fn else None, line_start=min(numeric))
                    return loc
    location_str = finding.location
    if not location_str:
        return None
    location = Location()
    parts = location_str.split(":")
    if len(parts) >= 1:
        location.filename = parts[0]
    if len(parts) >= 2:
        try:
            offset = int(parts[1])
            # Heuristic: Slither start offsets are usually large; line numbers stay small.
            if offset < 5000:
                location.line_start = offset
        except ValueError:
            pass
    return location if location.filename or location.line_start is not None else None
