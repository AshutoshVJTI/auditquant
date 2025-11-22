from __future__ import annotations

import asyncio
import uuid
from dataclasses import asdict
from pathlib import Path

from app.config import settings
from app.models.schemas import AnalysisResult, Finding, RiskScores
from app.services.mythril_runner import run_mythril
from app.services.slither_runner import run_slither
from app.services.store import store
from llm.client import LLMClient, LLMConfig
from riskquant.complexity import estimate_cyclomatic_complexity
from riskquant.engine import compute_r_comp, compute_r_dast, compute_r_sast
from riskquant.financial import map_loss_percentage


async def run_analysis(file_path: Path, analysis_id: str | None = None) -> AnalysisResult:
    analysis_id = analysis_id or str(uuid.uuid4())
    if not store.get(analysis_id):
        store.create(analysis_id, file_path.name)

    llm = LLMClient(LLMConfig(api_key=settings.openai_api_key, model=settings.openai_model))

    try:
        source_code = file_path.read_text(encoding="utf-8")
        slither_task = asyncio.create_task(run_slither(settings.slither_compose_path, file_path))
        mythril_task = asyncio.create_task(run_mythril(settings.slither_compose_path, file_path))

        slither_result, mythril_result = await asyncio.gather(
            slither_task, mythril_task, return_exceptions=True
        )

        slither_findings = (
            slither_result if not isinstance(slither_result, Exception) else []
        )
        mythril_findings = (
            mythril_result if not isinstance(mythril_result, Exception) else []
        )

        findings: list[Finding] = []
        for idx, finding in enumerate(slither_findings, start=1):
            loss_percentage = map_loss_percentage(finding.title)
            if loss_percentage is None:
                loss_percentage = await llm.classify_financial_impact_async(
                    finding.title, "Solidity smart contract"
                )

            vulnerable = await llm.validate_vulnerability_async(
                asdict(finding), source_code
            )
            findings.append(
                Finding(
                    id=f"F-{idx}",
                    title=finding.title,
                    impact=finding.impact,
                    confidence=finding.confidence,
                    description=finding.description,
                    source="slither",
                    location=finding.location,
                    vulnerable=vulnerable,
                    loss_percentage=loss_percentage,
                    metadata={"raw": finding.raw},
                )
            )

        for idx, finding in enumerate(mythril_findings, start=1):
            findings.append(
                Finding(
                    id=f"M-{idx}",
                    title=finding.title,
                    impact=finding.severity,
                    confidence="High",
                    description=finding.description,
                    source="mythril",
                    location=finding.location,
                    vulnerable=True,
                    loss_percentage=map_loss_percentage(finding.title),
                    metadata={
                        "swc_id": finding.swc_id,
                        "reachable": finding.reachable,
                        "base_severity": finding.base_severity,
                        "exploit_trace": finding.exploit_trace,
                        "raw": finding.raw,
                    },
                )
            )

        filtered_findings = [f for f in findings if f.vulnerable]
        slither_filtered = [f for f in filtered_findings if f.source == "slither"]

        r_sast = compute_r_sast([(f.impact, f.confidence) for f in slither_filtered])
        r_dast = compute_r_dast(
            [
                (finding.base_severity, finding.reachable)
                for finding in mythril_findings
            ]
        )
        r_comp = compute_r_comp(estimate_cyclomatic_complexity(source_code))

        summary = await llm.generate_summary_async([f.model_dump() for f in filtered_findings])

        result = AnalysisResult(
            analysis_id=analysis_id,
            filename=file_path.name,
            created_at=store.get(analysis_id).created_at,
            status="completed",
            scores=RiskScores(r_sast=r_sast, r_dast=r_dast, r_comp=r_comp),
            findings=filtered_findings,
            summary=summary,
        )
        store.update(analysis_id, result)
        return result
    except Exception as exc:
        result = AnalysisResult(
            analysis_id=analysis_id,
            filename=file_path.name,
            created_at=store.get(analysis_id).created_at,
            status="failed",
            error=str(exc),
        )
        store.update(analysis_id, result)
        return result
