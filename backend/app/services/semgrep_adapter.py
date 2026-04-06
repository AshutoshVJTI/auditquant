# Semgrep → NormalizedFinding conversion

from app.services.normalized_finding import (
    AnalysisType,
    Location,
    NormalizedFinding,
    Severity,
    ToolSource,
    normalize_vuln_type,
)
from app.services.confidence_loader import semgrep_tier
from app.services.semgrep_runner import SemgrepFinding


SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}

CONFIDENCE_MAP = {
    "HIGH": 0.85,
    "MEDIUM": 0.65,
    "LOW": 0.45,
}

# Maps keywords in Semgrep check_id to canonical vuln types and SWC IDs
_RULE_PATTERNS: list[tuple[str, str, str | None]] = [
    ("reentrancy",          "reentrancy",        "SWC-107"),
    ("tx-origin",           "access-control",    "SWC-115"),
    ("arbitrary-send",      "access-control",    "SWC-105"),
    ("delegatecall",        "access-control",    "SWC-112"),
    ("unchecked-return",    "unchecked-return",  "SWC-104"),
    ("unchecked-send",      "unchecked-return",  "SWC-104"),
    ("unchecked-transfer",  "unchecked-return",  "SWC-104"),
    ("selfdestruct",        "access-control",    "SWC-106"),
    ("timestamp",           "timestamp-dependency", "SWC-116"),
    ("integer-overflow",    "integer-overflow",  "SWC-101"),
    ("divide-before-multiply", "integer-overflow", "SWC-101"),
    ("locked-ether",        "denial-of-service", "SWC-132"),
    ("dos",                 "denial-of-service", "SWC-113"),
    ("front-running",       "front-running",     None),
    ("oracle",              "oracle",            None),
    ("permit",              "denial-of-service", None),
]


def _map_rule_id(check_id: str) -> tuple[str, str | None]:
    lower = check_id.lower()
    for keyword, vuln_type, swc in _RULE_PATTERNS:
        if keyword in lower:
            return vuln_type, swc
    # fall back to last segment of the check_id
    last = check_id.split(".")[-1].split("/")[-1]
    return normalize_vuln_type(last), None


def semgrep_to_normalized(findings: list[SemgrepFinding]) -> list[NormalizedFinding]:
    normalized: list[NormalizedFinding] = []
    for idx, finding in enumerate(findings, start=1):
        severity = SEVERITY_MAP.get(finding.severity.upper(), Severity.MEDIUM)
        raw_confidence = str(finding.metadata.get("confidence", "MEDIUM")).upper()
        confidence = semgrep_tier(raw_confidence)
        vuln_type, swc_id = _map_rule_id(finding.check_id)

        # CWE from metadata if present
        cwe_list = finding.metadata.get("cwe", [])
        cwe_id = cwe_list[0] if cwe_list else None

        location = Location(
            filename=finding.path,
            line_start=finding.line_start or None,
            line_end=finding.line_end or None,
            column_start=finding.col_start or None,
            column_end=finding.col_end or None,
        )

        normalized.append(
            NormalizedFinding(
                id=f"SGP-{idx}",
                tool=ToolSource.SEMGREP,
                analysis_type=AnalysisType.PATTERN,
                vulnerability_type=vuln_type,
                title=finding.check_id.split(".")[-1],
                description=finding.message,
                severity=severity,
                severity_score=0.0,
                confidence=confidence,
                location=location,
                swc_id=swc_id,
                cwe_id=cwe_id,
                is_reachable=False,
                has_exploit_proof=False,
                raw=finding.raw,
            )
        )
    return normalized
