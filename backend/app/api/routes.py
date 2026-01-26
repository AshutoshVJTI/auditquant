from __future__ import annotations

import asyncio
import logging
import uuid
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile

from app.config import settings
from app.models.schemas import (
    AnalysisCreateResponse,
    AnalysisResult,
    HealthResponse,
    RemediationRequest,
    RemediationResponse,
)
from app.services.orchestrator import run_analysis
from app.services.store import store
from remediation.codet5_model import CodeT5Remediator

router = APIRouter(prefix="/api")
logger = logging.getLogger(__name__)

ANALYSIS_TIMEOUT_SECONDS = 420


def _log_analysis_task_result(task: asyncio.Task) -> None:
    try:
        task.result()
    except asyncio.CancelledError:
        pass
    except Exception as exc:
        logger.exception("Background analysis task failed: %s", exc)


async def _run_analysis_with_timeout(file_path: Path, analysis_id: str) -> None:
    try:
        await asyncio.wait_for(run_analysis(file_path, analysis_id), timeout=ANALYSIS_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        logger.warning("Analysis %s timed out after %ss", analysis_id, ANALYSIS_TIMEOUT_SECONDS)
        existing = store.get(analysis_id)
        if existing:
            store.update(
                analysis_id,
                AnalysisResult(
                    analysis_id=analysis_id,
                    filename=file_path.name,
                    created_at=existing.created_at,
                    status="failed",
                    error=f"Analysis timed out after {ANALYSIS_TIMEOUT_SECONDS}s. Check Docker (Slither/Mythril) and network (LLM).",
                ),
            )


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    return HealthResponse(status="ok", service="auditquant", version=settings.api_version)


@router.post("/analyze", response_model=AnalysisCreateResponse)
async def analyze_contract(file: UploadFile = File(...)) -> AnalysisCreateResponse:
    if not file.filename.endswith(".sol"):
        raise HTTPException(status_code=400, detail="Only .sol files are supported")

    analysis_id = str(uuid.uuid4())
    repo_root = Path(__file__).resolve().parents[3]
    storage_dir = (repo_root / settings.analysis_storage_path).resolve()
    storage_dir.mkdir(parents=True, exist_ok=True)
    file_path = storage_dir / f"{analysis_id}-{file.filename}"

    content = await file.read()
    file_path.write_bytes(content)

    store.create(analysis_id, file.filename)
    task = asyncio.create_task(_run_analysis_with_timeout(file_path, analysis_id))
    task.add_done_callback(_log_analysis_task_result)

    return AnalysisCreateResponse(analysis_id=analysis_id, status="queued")


@router.get("/analysis/{analysis_id}", response_model=AnalysisResult)
async def get_analysis(analysis_id: str) -> AnalysisResult:
    result = store.get(analysis_id)
    if not result:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return result


@router.post("/remediate", response_model=RemediationResponse)
async def remediate_finding(request: RemediationRequest) -> RemediationResponse:
    """Generate a CodeT5 patch for a specific vulnerability finding."""
    result = store.get(request.analysis_id)
    if not result:
        raise HTTPException(status_code=404, detail="Analysis not found")

    # Find the specific finding
    finding = next((f for f in result.findings if f.id == request.finding_id), None)
    if not finding:
        raise HTTPException(
            status_code=404,
            detail=f"Finding {request.finding_id} not found in analysis",
        )

    # Get the vulnerable code snippet
    if request.code_snippet:
        vulnerable_code = request.code_snippet
    else:
        # Try to extract from the stored analysis file
        storage_dir = Path(settings.analysis_storage_path)
        matching_files = list(storage_dir.glob(f"{request.analysis_id}-*.sol"))
        if not matching_files:
            raise HTTPException(
                status_code=400,
                detail="No code snippet provided and source file not found",
            )
        vulnerable_code = matching_files[0].read_text(encoding="utf-8")

    # Generate patch using CodeT5
    try:
        remediator = CodeT5Remediator()
        patched_code = await asyncio.to_thread(
            remediator.generate_patch, vulnerable_code, finding.title
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    return RemediationResponse(
        finding_id=finding.id,
        vulnerability_type=finding.title,
        original_code=vulnerable_code,
        patched_code=patched_code,
        explanation=f"Applied Checks-Effects-Interactions pattern to fix {finding.title}",
    )
