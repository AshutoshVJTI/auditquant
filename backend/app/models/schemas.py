from typing import Any

from pydantic import BaseModel, Field


class RiskScores(BaseModel):
    r_sast: float
    r_dast: float
    r_comp: float
    composite: float
    r_model: float | None = None   # CodeBERT risk regression output (None if model not loaded)


class ModelPrediction(BaseModel):
    available: bool
    vuln_types: list[str] = Field(default_factory=list)
    risk_score: float = 0.0
    probabilities: dict[str, float] = Field(default_factory=dict)
    error: str | None = None


class VerificationInfo(BaseModel):
    status: str
    hallucination_rate: float = 0.0
    total_claims: int = 0
    verified_count: int = 0
    rejected_count: int = 0
    unverified_count: int = 0
    needs_review_count: int = 0


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


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
