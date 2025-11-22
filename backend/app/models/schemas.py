from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class AnalysisCreateResponse(BaseModel):
    analysis_id: str = Field(..., description="Unique analysis identifier")
    status: str = Field(..., description="Queued status")


class RiskScores(BaseModel):
    r_sast: float
    r_dast: float
    r_comp: float


class Finding(BaseModel):
    id: str
    title: str
    impact: str
    confidence: str
    description: str
    source: str
    location: str | None = None
    vulnerable: bool
    loss_percentage: float | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class AnalysisResult(BaseModel):
    analysis_id: str
    filename: str
    created_at: datetime
    status: str
    scores: RiskScores | None = None
    findings: list[Finding] = Field(default_factory=list)
    summary: str | None = None
    error: str | None = None


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
