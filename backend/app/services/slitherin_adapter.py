# Slitherin → NormalizedFinding conversion
# Slitherin provides DeFi-specific detectors not in base Slither:
# readonly-reentrancy, ERC4626 inflation, price oracle, permit DoS, etc.

from app.services.normalized_finding import (
    AnalysisType,
    Location,
    NormalizedFinding,
    Severity,
    ToolSource,
    normalize_vuln_type,
)
from app.services.confidence_loader import slitherin_tier
from app.services.slitherin_runner import SlitherInFinding


SEVERITY_MAP = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFO,
    "Optimization": Severity.INFO,
}

SWC_MAP = {
    "readonly-reentrancy": "SWC-107",
    "reentrancy-read-before-write": "SWC-107",
    "pess-readonly-reentrancy": "SWC-107",
    "unprotected-initialize": "SWC-105",
    "pess-unprotected-initialize": "SWC-105",
    "arbitrary-call": "SWC-107",
    "pess-arbitrary-call": "SWC-107",
    "permit-dos": "SWC-134",
    "erc4626-inflation-attack": "SWC-101",
    "controlled-delegatecall": "SWC-112",
    "unsafe-delegatecall": "SWC-112",
}


def slitherin_to_normalized(findings: list[SlitherInFinding]) -> list[NormalizedFinding]:
    normalized: list[NormalizedFinding] = []
    for idx, finding in enumerate(findings, start=1):
        location = _parse_location(finding.location)
        severity = SEVERITY_MAP.get(finding.impact, Severity.MEDIUM)
        confidence = slitherin_tier(finding.confidence)
        normalized.append(
            NormalizedFinding(
                id=f"SLR-{idx}",
                tool=ToolSource.SLITHERIN,
                analysis_type=AnalysisType.STATIC,
                vulnerability_type=normalize_vuln_type(finding.title),
                title=finding.title,
                description=finding.description,
                severity=severity,
                severity_score=0.0,
                confidence=confidence,
                location=location,
                swc_id=SWC_MAP.get(finding.title.lower()),
                is_reachable=False,
                has_exploit_proof=False,
                raw=finding.raw,
            )
        )
    return normalized


def _parse_location(location_str: str | None) -> Location | None:
    if not location_str:
        return None
    location = Location()
    parts = location_str.split(":")
    if parts:
        location.filename = parts[0]
    if len(parts) >= 2:
        try:
            location.line_start = int(parts[1])
        except ValueError:
            pass
    return location
