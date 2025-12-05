"""
Multi-Tool Analysis API

Endpoints for running the expanded 5-tool analysis pipeline.
"""
from __future__ import annotations

import asyncio
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, File, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field

from app.config import settings
from app.services.multi_tool_orchestrator import (
    MultiToolOrchestrator,
    MultiToolResult,
    get_finding_stats,
)
from app.services.normalized_finding import NormalizedFinding, Severity, ToolSource


router = APIRouter(prefix="/api/v2", tags=["Multi-Tool Analysis"])


# Response models
class NormalizedFindingResponse(BaseModel):
    id: str
    tool: str
    analysis_type: str
    vulnerability_type: str
    title: str
    description: str
    severity: str
    severity_score: float
    confidence: float
    location: str | None
    swc_id: str | None
    is_reachable: bool
    has_exploit_proof: bool


class ToolResultResponse(BaseModel):
    tool: str
    finding_count: int
    error: str | None
    execution_time_ms: float


class MultiToolAnalysisResponse(BaseModel):
    analysis_id: str
    filename: str
    status: str
    tool_results: list[ToolResultResponse]
    total_findings: int
    cross_validated_count: int
    findings: list[NormalizedFindingResponse]
    cross_validated: list[NormalizedFindingResponse]
    stats: dict[str, Any]
    total_execution_time_ms: float


class AnalysisQueuedResponse(BaseModel):
    analysis_id: str
    status: str = "queued"
    enabled_tools: list[str]


# In-memory store for multi-tool results
_multi_tool_store: dict[str, MultiToolResult | str] = {}


def _finding_to_response(f: NormalizedFinding) -> NormalizedFindingResponse:
    return NormalizedFindingResponse(
        id=f.id,
        tool=f.tool.value,
        analysis_type=f.analysis_type.value,
        vulnerability_type=f.vulnerability_type,
        title=f.title,
        description=f.description,
        severity=f.severity.value,
        severity_score=f.severity_score,
        confidence=f.confidence,
        location=str(f.location) if f.location else None,
        swc_id=f.swc_id,
        is_reachable=f.is_reachable,
        has_exploit_proof=f.has_exploit_proof,
    )


@router.post("/analyze", response_model=AnalysisQueuedResponse)
async def analyze_multi_tool(
    file: UploadFile = File(...),
    enable_securify: bool = Query(default=True, description="Enable Securify static analysis"),
    enable_echidna: bool = Query(default=True, description="Enable Echidna fuzzing"),
    enable_oyente: bool = Query(default=True, description="Enable Oyente baseline"),
) -> AnalysisQueuedResponse:
    """
    Start a multi-tool analysis using all 5 tools:
    - Slither (static)
    - Securify (static)
    - Mythril (symbolic)
    - Echidna (fuzzing)
    - Oyente (symbolic baseline)
    
    Returns immediately with an analysis_id. Poll /analysis/{id} for results.
    """
    if not file.filename.endswith(".sol"):
        raise HTTPException(status_code=400, detail="Only .sol files are supported")

    analysis_id = str(uuid.uuid4())
    storage_dir = Path(settings.analysis_storage_path)
    storage_dir.mkdir(parents=True, exist_ok=True)
    file_path = storage_dir / f"{analysis_id}-{file.filename}"

    content = await file.read()
    file_path.write_bytes(content)

    # Mark as pending
    _multi_tool_store[analysis_id] = "pending"
    
    # Build enabled tools list
    enabled_tools = ["slither", "mythril"]
    if enable_securify:
        enabled_tools.append("securify")
    if enable_echidna:
        enabled_tools.append("echidna")
    if enable_oyente:
        enabled_tools.append("oyente")

    # Start async analysis
    asyncio.create_task(_run_multi_tool_analysis(
        file_path,
        analysis_id,
        enable_securify=enable_securify,
        enable_echidna=enable_echidna,
        enable_oyente=enable_oyente,
    ))

    return AnalysisQueuedResponse(
        analysis_id=analysis_id,
        status="queued",
        enabled_tools=enabled_tools,
    )


async def _run_multi_tool_analysis(
    file_path: Path,
    analysis_id: str,
    enable_securify: bool,
    enable_echidna: bool,
    enable_oyente: bool,
) -> None:
    """Background task to run multi-tool analysis."""
    try:
        orchestrator = MultiToolOrchestrator(
            compose_path=settings.slither_compose_path,
            enable_securify=enable_securify,
            enable_echidna=enable_echidna,
            enable_oyente=enable_oyente,
            echidna_test_limit=settings.echidna_test_limit,
            echidna_timeout=settings.echidna_timeout,
            oyente_timeout=settings.oyente_timeout,
        )
        result = await orchestrator.analyze(file_path, analysis_id)
        _multi_tool_store[analysis_id] = result
    except Exception as e:
        _multi_tool_store[analysis_id] = f"error:{str(e)}"


@router.get("/analysis/{analysis_id}", response_model=MultiToolAnalysisResponse)
async def get_multi_tool_analysis(analysis_id: str) -> MultiToolAnalysisResponse:
    """
    Get results of a multi-tool analysis.
    
    Returns detailed findings from all tools with cross-validation status.
    """
    stored = _multi_tool_store.get(analysis_id)
    
    if stored is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    if stored == "pending":
        raise HTTPException(status_code=202, detail="Analysis still in progress")
    
    if isinstance(stored, str) and stored.startswith("error:"):
        raise HTTPException(status_code=500, detail=stored[6:])
    
    result: MultiToolResult = stored
    
    tool_results = [
        ToolResultResponse(
            tool=tool.value,
            finding_count=len(tr.findings),
            error=tr.error,
            execution_time_ms=tr.execution_time_ms,
        )
        for tool, tr in result.tool_results.items()
    ]
    
    findings = [_finding_to_response(f) for f in result.all_findings]
    cross_validated = [_finding_to_response(f) for f in result.cross_validated]
    
    return MultiToolAnalysisResponse(
        analysis_id=result.analysis_id,
        filename=result.filename,
        status="completed",
        tool_results=tool_results,
        total_findings=len(result.all_findings),
        cross_validated_count=len(result.cross_validated),
        findings=findings,
        cross_validated=cross_validated,
        stats=get_finding_stats(result),
        total_execution_time_ms=result.total_execution_time_ms,
    )


@router.get("/analysis/{analysis_id}/by-tool/{tool}")
async def get_findings_by_tool(
    analysis_id: str,
    tool: str,
) -> list[NormalizedFindingResponse]:
    """Get findings from a specific tool."""
    stored = _multi_tool_store.get(analysis_id)
    
    if stored is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    if not isinstance(stored, MultiToolResult):
        raise HTTPException(status_code=202, detail="Analysis not ready")
    
    try:
        tool_source = ToolSource(tool.lower())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Unknown tool: {tool}")
    
    tool_result = stored.tool_results.get(tool_source)
    if not tool_result:
        raise HTTPException(status_code=404, detail=f"Tool {tool} not found in results")
    
    return [_finding_to_response(f) for f in tool_result.findings]


@router.get("/analysis/{analysis_id}/cross-validated")
async def get_cross_validated_findings(
    analysis_id: str,
    min_confidence: float = Query(default=0.0, ge=0.0, le=1.0),
) -> list[NormalizedFindingResponse]:
    """
    Get only cross-validated findings (confirmed by multiple tools).
    
    These are high-confidence findings suitable for LLM summarization
    without hallucination risk.
    """
    stored = _multi_tool_store.get(analysis_id)
    
    if stored is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    if not isinstance(stored, MultiToolResult):
        raise HTTPException(status_code=202, detail="Analysis not ready")
    
    filtered = [
        f for f in stored.cross_validated
        if f.confidence >= min_confidence
    ]
    
    return [_finding_to_response(f) for f in filtered]
