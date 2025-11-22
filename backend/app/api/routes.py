from __future__ import annotations

import asyncio
import uuid
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile

from app.config import settings
from app.models.schemas import AnalysisCreateResponse, AnalysisResult, HealthResponse
from app.services.orchestrator import run_analysis
from app.services.store import store

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
