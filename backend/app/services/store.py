from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Optional

from app.models.schemas import AnalysisResult


@dataclass
class AnalysisStore:
    analyses: Dict[str, AnalysisResult] = field(default_factory=dict)

    def create(self, analysis_id: str, filename: str) -> AnalysisResult:
        result = AnalysisResult(
            analysis_id=analysis_id,
            filename=filename,
            created_at=datetime.utcnow(),
            status="pending",
        )
        self.analyses[analysis_id] = result
        return result

    def update(self, analysis_id: str, result: AnalysisResult) -> None:
        self.analyses[analysis_id] = result

    def get(self, analysis_id: str) -> Optional[AnalysisResult]:
        return self.analyses.get(analysis_id)


store = AnalysisStore()
