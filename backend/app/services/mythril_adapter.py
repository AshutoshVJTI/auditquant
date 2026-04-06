# Mythril → NormalizedFinding conversion

from app.services.normalized_finding import (
    AnalysisType,
    ExploitTrace,
    Location,
    NormalizedFinding,
    Severity,
    ToolSource,
    normalize_vuln_type,
)
from app.services.confidence_loader import mythril_confidence
from app.services.mythril_runner import MythrilFinding


MYTHRIL_SEVERITY_MAP = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
}


def mythril_to_normalized(findings: list[MythrilFinding]) -> list[NormalizedFinding]:
    normalized: list[NormalizedFinding] = []
    
    for idx, finding in enumerate(findings, start=1):
        severity = MYTHRIL_SEVERITY_MAP.get(finding.severity, Severity.MEDIUM)
        
        exploit_trace = None
        if finding.exploit_trace:
            exploit_trace = ExploitTrace(
                steps=finding.exploit_trace,
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
                confidence=mythril_confidence(finding.reachable),
                location=_parse_mythril_location(finding.location, finding.raw),
                exploit_trace=exploit_trace,
                swc_id=finding.swc_id,
                is_reachable=finding.reachable,
                has_exploit_proof=finding.reachable and len(finding.exploit_trace) > 0,
                raw=finding.raw,
            )
        )
    
    return normalized


def _parse_mythril_location(location_str: str | None, raw: dict | None = None) -> Location | None:
    location = Location()
    if isinstance(raw, dict):
        fn = raw.get("filename")
        if fn:
            location.filename = str(fn)
        for key in ("lineno", "line", "line_number"):
            if raw.get(key) is not None:
                try:
                    location.line_start = int(raw[key])
                except (TypeError, ValueError):
                    pass
                break
    if location.line_start is None and location_str:
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
    if not location.filename and not location_str:
        return None
    return location if location.filename or location.line_start is not None else None
