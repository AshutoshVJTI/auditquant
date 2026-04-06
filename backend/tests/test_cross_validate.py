"""Cross-validation groups findings by normalized location + vuln type."""

from app.services.multi_tool_orchestrator import MultiToolOrchestrator
from app.services.normalized_finding import (
    AnalysisType,
    Location,
    NormalizedFinding,
    Severity,
    ToolSource,
)


def _nf(
    fid: str,
    tool: ToolSource,
    vuln_type: str,
    line: int,
    filename: str,
    analysis: AnalysisType,
) -> NormalizedFinding:
    return NormalizedFinding(
        id=fid,
        tool=tool,
        analysis_type=analysis,
        vulnerability_type=vuln_type,
        title="t",
        description="",
        severity=Severity.HIGH,
        severity_score=90.0,
        confidence=0.5,
        location=Location(filename=filename, line_start=line),
    )


def test_high_confidence_same_type_different_path_prefix():
    orch = MultiToolOrchestrator(compose_path="docker/docker-compose.yml")
    slither = _nf(
        "SLI-1",
        ToolSource.SLITHER,
        "reentrancy",
        94,
        "/work/backend/.analysis/reentrancy.sol",
        AnalysisType.STATIC,
    )
    mythril = _nf(
        "MYT-1",
        ToolSource.MYTHRIL,
        "reentrancy",
        94,
        "reentrancy.sol",
        AnalysisType.SYMBOLIC,
    )
    tools = {ToolSource.SLITHER, ToolSource.MYTHRIL}
    high, medium, lone = orch._cross_validate([slither, mythril], tools)
    assert len(high) == 2
    assert not medium
    assert not lone


def test_medium_confidence_same_line_different_types():
    orch = MultiToolOrchestrator(compose_path="docker/docker-compose.yml")
    slither = _nf(
        "SLI-1",
        ToolSource.SLITHER,
        "reentrancy",
        94,
        "c.sol",
        AnalysisType.STATIC,
    )
    mythril = _nf(
        "MYT-1",
        ToolSource.MYTHRIL,
        "unchecked-return",
        94,
        "c.sol",
        AnalysisType.SYMBOLIC,
    )
    tools = {ToolSource.SLITHER, ToolSource.MYTHRIL}
    high, medium, lone = orch._cross_validate([slither, mythril], tools)
    assert not high
    assert len(medium) == 2
    assert not lone


def test_lone_signal_single_tool():
    orch = MultiToolOrchestrator(compose_path="docker/docker-compose.yml")
    only = _nf(
        "SLI-1",
        ToolSource.SLITHER,
        "reentrancy",
        1,
        "c.sol",
        AnalysisType.STATIC,
    )
    high, medium, lone = orch._cross_validate([only], {ToolSource.SLITHER})
    assert not high
    assert not medium
    assert len(lone) == 1
