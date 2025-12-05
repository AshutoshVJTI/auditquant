from __future__ import annotations

import asyncio
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


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    return HealthResponse(status="ok", service="auditquant", version=settings.api_version)


@router.post("/analyze", response_model=AnalysisCreateResponse)
async def analyze_contract(file: UploadFile = File(...)) -> AnalysisCreateResponse:
    if not file.filename.endswith(".sol"):
        raise HTTPException(status_code=400, detail="Only .sol files are supported")

    analysis_id = str(uuid.uuid4())
    storage_dir = Path(settings.analysis_storage_path)
    storage_dir.mkdir(parents=True, exist_ok=True)
    file_path = storage_dir / f"{analysis_id}-{file.filename}"

    content = await file.read()
    file_path.write_bytes(content)

    store.create(analysis_id, file.filename)
    asyncio.create_task(run_analysis(file_path, analysis_id))

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
