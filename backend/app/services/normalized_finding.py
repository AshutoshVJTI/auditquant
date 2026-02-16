# Shared data structures for findings that all tool adapters convert into.

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ToolSource(str, Enum):
    SLITHER = "slither"
    MYTHRIL = "mythril"
    OYENTE = "oyente"


class AnalysisType(str, Enum):
    STATIC = "static"
    SYMBOLIC = "symbolic"
    BYTECODE = "bytecode"


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"


SEVERITY_SCORES = {
    Severity.CRITICAL: 100.0,
    Severity.HIGH: 90.0,
    Severity.MEDIUM: 60.0,
    Severity.LOW: 30.0,
    Severity.INFO: 10.0,
}


@dataclass
class Location:
    filename: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    column_start: int | None = None
    column_end: int | None = None
    function_name: str | None = None
    contract_name: str | None = None

    def __str__(self) -> str:
        parts = []
        if self.filename:
            parts.append(self.filename)
        if self.line_start:
            parts.append(f"L{self.line_start}")
            if self.line_end and self.line_end != self.line_start:
                parts[-1] += f"-{self.line_end}"
        if self.function_name:
            parts.append(f"fn:{self.function_name}")
        return ":".join(parts) if parts else "unknown"


@dataclass
class ExploitTrace:
    steps: list[dict[str, Any]] = field(default_factory=list)
    input_sequence: list[str] = field(default_factory=list)
    transaction_data: list[dict[str, Any]] = field(default_factory=list)
    
    @property
    def has_proof(self) -> bool:
        return len(self.steps) > 0 or len(self.input_sequence) > 0


@dataclass
class NormalizedFinding:
    """Unified finding that all tool adapters produce."""
    id: str
    tool: ToolSource
    analysis_type: AnalysisType

    vulnerability_type: str  # e.g. "reentrancy", "access-control"
    title: str
    description: str

    severity: Severity
    severity_score: float
    confidence: float  # 0.0-1.0

    location: Location | None = None
    exploit_trace: ExploitTrace | None = None
    swc_id: str | None = None
    cwe_id: str | None = None
    is_reachable: bool = False
    has_exploit_proof: bool = False
    raw: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.severity_score == 0.0:
            self.severity_score = SEVERITY_SCORES.get(self.severity, 0.0)
        
        if self.exploit_trace and self.exploit_trace.has_proof:
            self.has_exploit_proof = True
            self.is_reachable = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tool": self.tool.value,
            "analysis_type": self.analysis_type.value,
            "vulnerability_type": self.vulnerability_type,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "severity_score": self.severity_score,
            "confidence": self.confidence,
            "location": str(self.location) if self.location else None,
            "swc_id": self.swc_id,
            "cwe_id": self.cwe_id,
            "is_reachable": self.is_reachable,
            "has_exploit_proof": self.has_exploit_proof,
        }


# maps tool-specific vuln names to canonical types
VULN_TYPE_ALIASES = {
    "reentrancy": "reentrancy",
    "reentrancy-eth": "reentrancy",
    "reentrancy-no-eth": "reentrancy",
    "reentrancy-benign": "reentrancy",
    "reentrancy-events": "reentrancy",
    "external-call": "reentrancy",
    "dao": "reentrancy",
    "access-control": "access-control",
    "unprotected-function": "access-control",
    "tx-origin": "access-control",
    "suicidal": "access-control",
    "arbitrary-send": "access-control",
    "integer-overflow": "integer-overflow",
    "integer-underflow": "integer-overflow",
    "overflow": "integer-overflow",
    "underflow": "integer-overflow",
    "unchecked-return": "unchecked-return",
    "unchecked-call": "unchecked-return",
    "unchecked-lowlevel": "unchecked-return",
    "unchecked-send": "unchecked-return",
    "timestamp": "timestamp-dependency",
    "block-timestamp": "timestamp-dependency",
    "weak-prng": "timestamp-dependency",
    "dos": "denial-of-service",
    "denial-of-service": "denial-of-service",
    "gas-limit": "denial-of-service",
    "front-running": "front-running",
    "transaction-order-dependency": "front-running",
    "tod": "front-running",
}


def normalize_vuln_type(raw_type: str) -> str:
    key = raw_type.lower().strip().replace(" ", "-").replace("_", "-")
    return VULN_TYPE_ALIASES.get(key, key)
