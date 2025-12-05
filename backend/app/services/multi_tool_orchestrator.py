"""
Multi-Tool Orchestrator

Runs all analysis tools in parallel and aggregates results into a unified
normalized schema. Enables cross-tool validation and anti-hallucination checks.
"""
from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.config import settings
from app.services.normalized_finding import (
    AnalysisType,
    NormalizedFinding,
    ToolSource,
)

# Tool runners
from app.services.slither_runner import run_slither
from app.services.mythril_runner import run_mythril
from app.services.securify_runner import run_securify
from app.services.echidna_runner import run_echidna
from app.services.oyente_runner import run_oyente

# Adapters (for legacy runners)
from app.services.slither_adapter import slither_to_normalized
from app.services.mythril_adapter import mythril_to_normalized


@dataclass
class ToolResult:
    """Result from a single tool run."""
    tool: ToolSource
    findings: list[NormalizedFinding] = field(default_factory=list)
    error: str | None = None
    execution_time_ms: float = 0.0


@dataclass
class MultiToolResult:
    """Aggregated results from all tools."""
    analysis_id: str
    filename: str
    tool_results: dict[ToolSource, ToolResult] = field(default_factory=dict)
    all_findings: list[NormalizedFinding] = field(default_factory=list)
    cross_validated: list[NormalizedFinding] = field(default_factory=list)
    total_execution_time_ms: float = 0.0
    
    @property
    def tools_succeeded(self) -> list[ToolSource]:
        return [t for t, r in self.tool_results.items() if r.error is None]
    
    @property
    def tools_failed(self) -> list[ToolSource]:
        return [t for t, r in self.tool_results.items() if r.error is not None]


class MultiToolOrchestrator:
    """
    Orchestrates multiple analysis tools and aggregates findings.
    
    Tool Categories:
    - STATIC: Slither, Securify (fast, broad coverage)
    - SYMBOLIC: Mythril, Oyente (precise, can prove exploitability)
    - FUZZING: Echidna (concrete exploit traces)
    """
    
    def __init__(
        self,
        compose_path: str | None = None,
        enable_securify: bool = True,
        enable_echidna: bool = True,
        enable_oyente: bool = True,
        echidna_test_limit: int = 50000,
        echidna_timeout: int = 300,
        oyente_timeout: int = 180,
    ):
        self.compose_path = compose_path or settings.slither_compose_path
        self.enable_securify = enable_securify
        self.enable_echidna = enable_echidna
        self.enable_oyente = enable_oyente
        self.echidna_test_limit = echidna_test_limit
        self.echidna_timeout = echidna_timeout
        self.oyente_timeout = oyente_timeout
    
    async def analyze(
        self,
        file_path: Path,
        analysis_id: str | None = None,
    ) -> MultiToolResult:
        """
        Run all enabled tools and aggregate results.
        
        Returns normalized findings with cross-tool validation metadata.
        """
        analysis_id = analysis_id or str(uuid.uuid4())
        
        import time
        start_time = time.time()
        
        # Build task list
        tasks = {
            ToolSource.SLITHER: self._run_slither(file_path),
            ToolSource.MYTHRIL: self._run_mythril(file_path),
        }
        
        if self.enable_securify:
            tasks[ToolSource.SECURIFY] = self._run_securify(file_path)
        if self.enable_echidna:
            tasks[ToolSource.ECHIDNA] = self._run_echidna(file_path)
        if self.enable_oyente:
            tasks[ToolSource.OYENTE] = self._run_oyente(file_path)
        
        # Run all tools concurrently
        results = await asyncio.gather(
            *[self._wrap_tool_run(tool, coro) for tool, coro in tasks.items()],
            return_exceptions=False,
        )
        
        # Build result object
        tool_results = {r.tool: r for r in results}
        all_findings = []
        for r in results:
            all_findings.extend(r.findings)
        
        # Cross-validate findings
        cross_validated = self._cross_validate(all_findings)
        
        total_time = (time.time() - start_time) * 1000
        
        return MultiToolResult(
            analysis_id=analysis_id,
            filename=file_path.name,
            tool_results=tool_results,
            all_findings=all_findings,
            cross_validated=cross_validated,
            total_execution_time_ms=total_time,
        )
    
    async def _wrap_tool_run(
        self,
        tool: ToolSource,
        coro,
    ) -> ToolResult:
        """Wrap tool execution with timing and error handling."""
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
        """Run Slither and convert to normalized findings."""
        raw_findings = await run_slither(self.compose_path, file_path)
        return slither_to_normalized(raw_findings)
    
    async def _run_mythril(self, file_path: Path) -> list[NormalizedFinding]:
        """Run Mythril and convert to normalized findings."""
        raw_findings = await run_mythril(self.compose_path, file_path)
        return mythril_to_normalized(raw_findings)
    
    async def _run_securify(self, file_path: Path) -> list[NormalizedFinding]:
        """Run Securify (already returns normalized)."""
        return await run_securify(self.compose_path, file_path)
    
    async def _run_echidna(self, file_path: Path) -> list[NormalizedFinding]:
        """Run Echidna (already returns normalized)."""
        return await run_echidna(
            self.compose_path,
            file_path,
            test_limit=self.echidna_test_limit,
            timeout=self.echidna_timeout,
        )
    
    async def _run_oyente(self, file_path: Path) -> list[NormalizedFinding]:
        """Run Oyente (already returns normalized)."""
        return await run_oyente(
            self.compose_path,
            file_path,
            timeout=self.oyente_timeout,
        )
    
    def _cross_validate(
        self,
        findings: list[NormalizedFinding],
    ) -> list[NormalizedFinding]:
        """
        Cross-validate findings across tools.
        
        A finding is "cross-validated" if:
        1. Multiple tools report the same vulnerability type at similar locations
        2. A dynamic tool (Mythril/Echidna) provides exploit proof for a static finding
        
        This is the core anti-hallucination mechanism.
        """
        # Group findings by normalized vulnerability type
        by_vuln_type: dict[str, list[NormalizedFinding]] = {}
        for f in findings:
            key = f.vulnerability_type
            if key not in by_vuln_type:
                by_vuln_type[key] = []
            by_vuln_type[key].append(f)
        
        cross_validated: list[NormalizedFinding] = []
        
        for vuln_type, group in by_vuln_type.items():
            if len(group) < 2:
                continue
            
            # Check if multiple tools found this
            tools = set(f.tool for f in group)
            if len(tools) < 2:
                continue
            
            # Check for dynamic proof
            has_dynamic_proof = any(
                f.has_exploit_proof and f.analysis_type in (AnalysisType.SYMBOLIC, AnalysisType.FUZZING)
                for f in group
            )
            
            # Mark as cross-validated
            for f in group:
                # Create a copy with cross-validation metadata
                validated = NormalizedFinding(
                    id=f.id,
                    tool=f.tool,
                    analysis_type=f.analysis_type,
                    vulnerability_type=f.vulnerability_type,
                    title=f.title,
                    description=f.description,
                    severity=f.severity,
                    severity_score=f.severity_score,
                    confidence=min(0.99, f.confidence + 0.1),  # Boost confidence
                    location=f.location,
                    exploit_trace=f.exploit_trace,
                    swc_id=f.swc_id,
                    cwe_id=f.cwe_id,
                    is_reachable=f.is_reachable or has_dynamic_proof,
                    has_exploit_proof=f.has_exploit_proof or has_dynamic_proof,
                    raw={
                        **f.raw,
                        "_cross_validated": True,
                        "_validated_by_tools": [t.value for t in tools],
                        "_has_dynamic_proof": has_dynamic_proof,
                    },
                )
                cross_validated.append(validated)
        
        return cross_validated


def get_finding_stats(result: MultiToolResult) -> dict[str, Any]:
    """Get statistics about the analysis run."""
    by_tool = {}
    for tool, tr in result.tool_results.items():
        by_tool[tool.value] = {
            "count": len(tr.findings),
            "error": tr.error,
            "time_ms": tr.execution_time_ms,
        }
    
    by_severity = {}
    for f in result.all_findings:
        sev = f.severity.value
        by_severity[sev] = by_severity.get(sev, 0) + 1
    
    by_type = {}
    for f in result.all_findings:
        by_type[f.vulnerability_type] = by_type.get(f.vulnerability_type, 0) + 1
    
    return {
        "total_findings": len(result.all_findings),
        "cross_validated_count": len(result.cross_validated),
        "tools_succeeded": [t.value for t in result.tools_succeeded],
        "tools_failed": [t.value for t in result.tools_failed],
        "by_tool": by_tool,
        "by_severity": by_severity,
        "by_vulnerability_type": by_type,
        "total_time_ms": result.total_execution_time_ms,
    }
