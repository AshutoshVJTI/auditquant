# Converts raw Mythril findings into NormalizedFinding objects.

from app.services.normalized_finding import (
    AnalysisType,
    ExploitTrace,
    Location,
    NormalizedFinding,
    Severity,
    ToolSource,
    normalize_vuln_type,
)
from app.services.mythril_runner import MythrilFinding


MYTHRIL_SEVERITY_MAP = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
}


def mythril_to_normalized(findings: list[MythrilFinding]) -> list[NormalizedFinding]:
    normalized: list[NormalizedFinding] = []
    
    for idx, finding in enumerate(findings, start=1):
        location = _parse_mythril_location(finding.location)
        severity = MYTHRIL_SEVERITY_MAP.get(finding.severity, Severity.MEDIUM)
        
        exploit_trace = None
        if finding.exploit_trace:
            exploit_trace = ExploitTrace(
                steps=finding.exploit_trace,
                transaction_data=finding.exploit_trace,
            )
        
        normalized.append(
            NormalizedFinding(
                id=f"MYT-{idx}",
                tool=ToolSource.MYTHRIL,
                analysis_type=AnalysisType.SYMBOLIC,
                vulnerability_type=normalize_vuln_type(finding.title),
                title=finding.title,
                description=finding.description,
                severity=severity,
                severity_score=finding.base_severity,
                confidence=0.95 if finding.reachable else 0.7,
                location=location,
                exploit_trace=exploit_trace,
                swc_id=finding.swc_id,
                is_reachable=finding.reachable,
                has_exploit_proof=finding.reachable and len(finding.exploit_trace) > 0,
                raw=finding.raw,
            )
        )
    
    return normalized


def _parse_mythril_location(location_str: str | None) -> Location | None:
    if not location_str:
        return None
    
    location = Location()
    if location_str.startswith("line:"):
        try:
            location.line_start = int(location_str.split(":")[1])
        except (ValueError, IndexError):
            pass
    else:
        parts = location_str.split(":")
        if len(parts) >= 2:
            try:
                location.line_start = int(parts[1])
            except ValueError:
                pass
    
    return location
