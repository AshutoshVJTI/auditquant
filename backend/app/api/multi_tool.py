import asyncio
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, File, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field

from app.config import settings
from app.models.schemas import (
    Finding,
    HealthResponse,
    RemediationPatch,
    RiskScores,
)
from app.services.orchestrator_v2 import EnhancedAnalysisResult, Orchestrator

router = APIRouter(prefix="/api", tags=["analysis"])

# in-memory -- will lose data on restart, but fine for demo purposes
_analysis_store: dict[str, EnhancedAnalysisResult | str] = {}


class AnalysisQueuedResponse(BaseModel):
    analysis_id: str
    status: str = "queued"
    enabled_tools: list[str]


class VerificationInfo(BaseModel):
    status: str
    hallucination_rate: float


class ToolResultSummary(BaseModel):
    tool: str
    finding_count: int
    error: str | None
    execution_time_ms: float


class AnalysisResponse(BaseModel):
    analysis_id: str
    filename: str
    status: str
    defi_category: str | None = None
    scores: RiskScores | None = None
    total_findings: int = 0
    cross_validated_count: int = 0
    findings: list[Finding] = Field(default_factory=list)
    verification: VerificationInfo | None = None
    summary: str | None = None
    remediation: list[RemediationPatch] = Field(default_factory=list)
    loss_percentage: float = 0.0
    tool_results: list[ToolResultSummary] = Field(default_factory=list)
    total_execution_time_ms: float = 0.0
    error: str | None = None


@router.get("/health", response_model=HealthResponse)
async def health():
    return HealthResponse(
        status="ok",
        service=settings.api_title,
        version=settings.api_version,
    )


@router.post("/analyze", response_model=AnalysisQueuedResponse)
async def analyze(file: UploadFile = File(...)) -> AnalysisQueuedResponse:
    """Upload a .sol file. Returns analysis_id; poll GET /api/analysis/{id} for results."""
    if not file.filename or not file.filename.endswith(".sol"):
        raise HTTPException(status_code=400, detail="Only .sol files are supported")

    analysis_id = str(uuid.uuid4())
    storage_dir = Path(settings.analysis_storage_path)
    storage_dir.mkdir(parents=True, exist_ok=True)
    file_path = storage_dir / f"{analysis_id}-{file.filename}"

    content = await file.read()
    file_path.write_bytes(content)

    _analysis_store[analysis_id] = "pending"

    enabled_tools = ["slither", "mythril"]
    if settings.enable_oyente:
        enabled_tools.append("oyente")

    asyncio.create_task(
        _run_analysis(file_path, analysis_id)
    )

    return AnalysisQueuedResponse(
        analysis_id=analysis_id,
        status="queued",
        enabled_tools=enabled_tools,
    )


@router.get("/analysis/{analysis_id}", response_model=AnalysisResponse)
async def get_analysis(analysis_id: str) -> AnalysisResponse:
    stored = _analysis_store.get(analysis_id)

    if stored is None:
        raise HTTPException(status_code=404, detail="Analysis not found")

    if stored == "pending":
        raise HTTPException(status_code=202, detail="Analysis still in progress")

    if isinstance(stored, str) and stored.startswith("error:"):
        raise HTTPException(status_code=500, detail=stored[6:])

    result: EnhancedAnalysisResult = stored

    tool_summaries: list[ToolResultSummary] = []
    stats = result.tool_stats or {}
    for tool_name, tool_data in stats.get("by_tool", {}).items():
        tool_summaries.append(
            ToolResultSummary(
                tool=tool_name,
                finding_count=tool_data.get("count", 0),
                error=tool_data.get("error"),
                execution_time_ms=tool_data.get("time_ms", 0.0),
            )
        )

    return AnalysisResponse(
        analysis_id=result.analysis_id,
        filename=result.filename,
        status=result.status,
        defi_category=result.defi_category,
        scores=result.scores,
        total_findings=result.total_findings,
        cross_validated_count=result.cross_validated_count,
        findings=result.verified_findings or result.findings,
        verification=VerificationInfo(
            status=result.verification_status,
            hallucination_rate=result.hallucination_rate,
        ),
        summary=result.summary,
        remediation=result.remediation,
        loss_percentage=result.loss_percentage,
        tool_results=tool_summaries,
        total_execution_time_ms=stats.get("total_time_ms", 0.0),
        error=result.error,
    )


@router.get("/analysis/{analysis_id}/business-risk")
async def get_business_risk(analysis_id: str) -> dict[str, Any]:
    stored = _analysis_store.get(analysis_id)

    if stored is None:
        raise HTTPException(status_code=404, detail="Analysis not found")

    if not isinstance(stored, EnhancedAnalysisResult):
        raise HTTPException(status_code=202, detail="Analysis not ready")

    return {
        "analysis_id": analysis_id,
        "defi_category": stored.defi_category,
        **stored.business_risk_report,
    }


async def _run_analysis(file_path: Path, analysis_id: str) -> None:
    """Background task: runs the full pipeline and stores the result."""
    try:
        orchestrator = Orchestrator(
            enable_oyente=settings.enable_oyente,
        )
        result = await orchestrator.analyze(file_path, analysis_id)
        _analysis_store[analysis_id] = result
    except Exception as e:
        _analysis_store[analysis_id] = f"error:{e}"
