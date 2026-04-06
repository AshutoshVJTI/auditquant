# Common finding format that all tool adapters produce.
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
class ToolSource(str, Enum):
    SLITHER = "slither"
    SLITHERIN = "slitherin"
    SEMGREP = "semgrep"
    MYTHRIL = "mythril"
    OYENTE = "oyente"  # kept for historical benchmark data
class AnalysisType(str, Enum):
    STATIC = "static"
    PATTERN = "pattern"
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

    @property
    def has_proof(self) -> bool:
        return len(self.steps) > 0
@dataclass
class NormalizedFinding:
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
# map tool-specific names to our canonical types
VULN_TYPE_ALIASES = {
    "reentrancy": "reentrancy",
    "reentrancy-eth": "reentrancy",
    "reentrancy-no-eth": "reentrancy",
    "reentrancy-benign": "reentrancy",
    "reentrancy-events": "reentrancy",
    "external-call": "reentrancy",
    "external-call-to-user-supplied-address": "reentrancy",
    "external-call-to-user-supplied-addresses": "reentrancy",
    "unchecked-return-value-from-external-call": "unchecked-return",
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
    # Slitherin DeFi-specific
    "readonly-reentrancy": "reentrancy",
    "erc4626-inflation-attack": "share-manipulation",
    "price-manipulation-vulnerable-functions": "oracle",
    "unprotected-initialize": "access-control",
    "permit-dos": "denial-of-service",
    "arbitrary-call": "access-control",
    # Semgrep
    "arbitrary-send-eth": "access-control",
    "tx-origin-auth": "access-control",
    "unchecked-return-value": "unchecked-return",
    "unsafe-delegatecall": "access-control",
    "unchecked-low-level-calls": "unchecked-return",
    "arithmetic": "integer-overflow",
    "flash-loan": "access-control",
    "price-manipulation": "oracle",
    "liquidation": "oracle",
    "reward-manipulation": "share-manipulation",
    "governance": "access-control",
}
def normalize_vuln_type(raw_type: str) -> str:
    key = raw_type.lower().strip().replace(" ", "-").replace("_", "-")
    return VULN_TYPE_ALIASES.get(key, key)
