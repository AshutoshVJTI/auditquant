import asyncio
import logging
import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

from app.config import settings
from app.services.normalized_finding import (
    AnalysisType,
    NormalizedFinding,
    ToolSource,
)
from app.services.slither_runner import run_slither
from app.services.slitherin_runner import run_slitherin
from app.services.semgrep_runner import run_semgrep
from app.services.mythril_runner import run_mythril
from app.services.slither_adapter import slither_to_normalized
from app.services.slitherin_adapter import slitherin_to_normalized
from app.services.semgrep_adapter import semgrep_to_normalized
from app.services.mythril_adapter import mythril_to_normalized


@dataclass
class ToolResult:
    tool: ToolSource
    findings: list[NormalizedFinding] = field(default_factory=list)
    error: str | None = None
    execution_time_ms: float = 0.0


@dataclass
class MultiToolResult:
    analysis_id: str
    filename: str
    tool_results: dict[ToolSource, ToolResult] = field(default_factory=dict)
    all_findings: list[NormalizedFinding] = field(default_factory=list)
    cross_validated: list[NormalizedFinding] = field(default_factory=list)
    high_confidence: list[NormalizedFinding] = field(default_factory=list)
    medium_confidence: list[NormalizedFinding] = field(default_factory=list)
    lone_signals: list[NormalizedFinding] = field(default_factory=list)
    total_execution_time_ms: float = 0.0

    @property
    def tools_succeeded(self) -> list[ToolSource]:
        return [t for t, r in self.tool_results.items() if r.error is None]

    @property
    def tools_failed(self) -> list[ToolSource]:
        return [t for t, r in self.tool_results.items() if r.error is not None]


class MultiToolOrchestrator:

    def __init__(
        self,
        compose_path: str | None = None,
        enable_semgrep: bool = True,
        enable_slitherin: bool = True,
    ):
        self.compose_path = compose_path or settings.docker_compose_path
        self.enable_semgrep = enable_semgrep
        self.enable_slitherin = enable_slitherin

    async def analyze(
        self,
        file_path: Path,
        analysis_id: str | None = None,
    ) -> MultiToolResult:
        analysis_id = analysis_id or str(uuid.uuid4())

        import time
        start_time = time.time()

        tasks = {
            ToolSource.SLITHER: self._run_slither(file_path),
            ToolSource.MYTHRIL: self._run_mythril(file_path),
        }
        if self.enable_slitherin:
            tasks[ToolSource.SLITHERIN] = self._run_slitherin(file_path)
        if self.enable_semgrep:
            tasks[ToolSource.SEMGREP] = self._run_semgrep(file_path)

        results = await asyncio.gather(
            *[self._wrap_tool_run(tool, coro) for tool, coro in tasks.items()],
            return_exceptions=False,
        )

        tool_results = {r.tool: r for r in results}
        all_findings: list[NormalizedFinding] = []
        for r in results:
            all_findings.extend(r.findings)

        high_conf, medium_conf, lone_sigs = self._cross_validate(
            all_findings, set(tool_results.keys())
        )
        cross_validated = high_conf + medium_conf
        total_time = (time.time() - start_time) * 1000

        return MultiToolResult(
            analysis_id=analysis_id,
            filename=file_path.name,
            tool_results=tool_results,
            all_findings=all_findings,
            cross_validated=cross_validated,
            high_confidence=high_conf,
            medium_confidence=medium_conf,
            lone_signals=lone_sigs,
            total_execution_time_ms=total_time,
        )

    async def _wrap_tool_run(self, tool: ToolSource, coro) -> ToolResult:
        import time
        start = time.time()
        try:
            findings = await coro
            return ToolResult(
                tool=tool,
                findings=findings,
                execution_time_ms=(time.time() - start) * 1000,
            )
        except Exception as e:
            return ToolResult(
                tool=tool,
                error=str(e),
                execution_time_ms=(time.time() - start) * 1000,
            )

    async def _run_slither(self, file_path: Path) -> list[NormalizedFinding]:
        return slither_to_normalized(await run_slither(self.compose_path, file_path))

    async def _run_slitherin(self, file_path: Path) -> list[NormalizedFinding]:
        return slitherin_to_normalized(await run_slitherin(self.compose_path, file_path))

    async def _run_semgrep(self, file_path: Path) -> list[NormalizedFinding]:
        return semgrep_to_normalized(await run_semgrep(self.compose_path, file_path))

    async def _run_mythril(self, file_path: Path) -> list[NormalizedFinding]:
        return mythril_to_normalized(await run_mythril(self.compose_path, file_path))

    def _location_key(self, f: NormalizedFinding) -> str:
        if f.location:
            if f.location.function_name:
                contract = f.location.contract_name or ""
                return f"{contract}::{f.location.function_name}"
            if f.location.line_start is not None:
                filename = f.location.filename or ""
                base = os.path.basename(filename) if filename else ""
                bucket = (f.location.line_start // 5) * 5
                return f"{base}:L{bucket}"
        return ""

    def _mark_finding(
        self,
        f: NormalizedFinding,
        tier: str,
        validated_by_tools: list[str],
        has_dynamic_proof: bool = False,
        confidence_boost: float = 0.0,
    ) -> NormalizedFinding:
        return NormalizedFinding(
            id=f.id,
            tool=f.tool,
            analysis_type=f.analysis_type,
            vulnerability_type=f.vulnerability_type,
            title=f.title,
            description=f.description,
            severity=f.severity,
            severity_score=f.severity_score,
            confidence=min(0.99, f.confidence + confidence_boost),
            location=f.location,
            exploit_trace=f.exploit_trace,
            swc_id=f.swc_id,
            cwe_id=f.cwe_id,
            is_reachable=f.is_reachable or has_dynamic_proof,
            has_exploit_proof=f.has_exploit_proof or has_dynamic_proof,
            raw={
                **f.raw,
                "_cross_validated": tier in ("HIGH_CONFIDENCE", "MEDIUM_CONFIDENCE"),
                "_confidence_tier": tier,
                "_validated_by_tools": validated_by_tools,
                "_has_dynamic_proof": has_dynamic_proof,
            },
        )

    @staticmethod
    def _load_boosts() -> tuple[float, float]:
        from app.services.confidence_loader import boost_high, boost_medium
        return boost_high(), boost_medium()

    @staticmethod
    def _load_precision_weights() -> dict[ToolSource, float]:
        from app.services.confidence_loader import tool_precision_weights
        raw = tool_precision_weights()
        return {ToolSource(k): v for k, v in raw.items() if k in ToolSource._value2member_map_}

    def _weighted_boost(
        self,
        agreeing_tools: set[ToolSource],
        tools_that_ran: set[ToolSource],
        max_boost: float,
    ) -> float:
        weights   = self._load_precision_weights()
        default_w = min(weights.values()) if weights else 0.1
        total_w   = sum(weights.get(t, default_w) for t in tools_that_ran)
        agree_w   = sum(weights.get(t, default_w) for t in agreeing_tools)
        if total_w == 0:
            return 0.0
        return round(max_boost * (agree_w / total_w), 4)

    def _cross_validate(
        self,
        findings: list[NormalizedFinding],
        tools_that_ran: set[ToolSource],
    ) -> tuple[list[NormalizedFinding], list[NormalizedFinding], list[NormalizedFinding]]:
        high_confidence: list[NormalizedFinding] = []
        medium_confidence: list[NormalizedFinding] = []
        classified_ids: set[str] = set()

        by_type_and_loc: dict[tuple[str, str], list[NormalizedFinding]] = {}
        for f in findings:
            key = (f.vulnerability_type, self._location_key(f))
            by_type_and_loc.setdefault(key, []).append(f)

        for (vuln_type, loc_key), group in by_type_and_loc.items():
            tools = {f.tool for f in group}
            if len(tools) < 2:
                continue
            has_dynamic = any(
                f.analysis_type in (AnalysisType.SYMBOLIC, AnalysisType.BYTECODE)
                for f in group
            )
            tool_names = [t.value for t in tools]
            boost_high, _ = self._load_boosts()
            boost = self._weighted_boost(tools, tools_that_ran, boost_high)
            for f in group:
                high_confidence.append(
                    self._mark_finding(
                        f,
                        tier="HIGH_CONFIDENCE",
                        validated_by_tools=tool_names,
                        has_dynamic_proof=has_dynamic,
                        confidence_boost=boost,
                    )
                )
                classified_ids.add(f.id)

        unclassified = [f for f in findings if f.id not in classified_ids]
        by_loc: dict[str, list[NormalizedFinding]] = {}
        for f in unclassified:
            loc = self._location_key(f)
            if loc:
                by_loc.setdefault(loc, []).append(f)

        for loc_key, group in by_loc.items():
            tools = {f.tool for f in group}
            if len(tools) < 2:
                continue
            # already caught by tier 1 if all tools agree on type - skip
            if len({f.vulnerability_type for f in group}) == 1:
                continue
            dynamic_fs = [
                f for f in group
                if f.analysis_type in (AnalysisType.SYMBOLIC, AnalysisType.BYTECODE)
            ]
            has_dynamic_proof = any(f.has_exploit_proof for f in dynamic_fs)
            tool_names = [t.value for t in tools]
            _, boost_medium = self._load_boosts()
            boost = self._weighted_boost(tools, tools_that_ran, boost_medium)
            for f in group:
                if f.id not in classified_ids:
                    medium_confidence.append(
                        self._mark_finding(
                            f,
                            tier="MEDIUM_CONFIDENCE",
                            validated_by_tools=tool_names,
                            has_dynamic_proof=has_dynamic_proof,
                            confidence_boost=boost,
                        )
                    )
                    classified_ids.add(f.id)

        lone_signals = [
            self._mark_finding(f, tier="LONE_SIGNAL", validated_by_tools=[f.tool.value])
            for f in findings
            if f.id not in classified_ids
        ]

        return high_confidence, medium_confidence, lone_signals


def get_finding_stats(result: MultiToolResult) -> dict[str, Any]:
    by_tool = {}
    for tool, tr in result.tool_results.items():
        by_tool[tool.value] = {
            "count": len(tr.findings),
            "error": tr.error,
            "time_ms": tr.execution_time_ms,
        }

    by_severity: dict[str, int] = {}
    for f in result.all_findings:
        sev = f.severity.value
        by_severity[sev] = by_severity.get(sev, 0) + 1

    by_type: dict[str, int] = {}
    for f in result.all_findings:
        by_type[f.vulnerability_type] = by_type.get(f.vulnerability_type, 0) + 1

    return {
        "total_findings": len(result.all_findings),
        "cross_validated_count": len(result.cross_validated),
        "high_confidence_count": len(result.high_confidence),
        "medium_confidence_count": len(result.medium_confidence),
        "lone_signal_count": len(result.lone_signals),
        "tools_succeeded": [t.value for t in result.tools_succeeded],
        "tools_failed": [t.value for t in result.tools_failed],
        "by_tool": by_tool,
        "by_severity": by_severity,
        "by_vulnerability_type": by_type,
        "total_time_ms": result.total_execution_time_ms,
    }
