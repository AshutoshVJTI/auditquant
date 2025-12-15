from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import asdict
from pathlib import Path

from app.config import settings
from app.models.schemas import AnalysisResult, Finding, RemediationPatch, RiskScores
from app.services.mythril_runner import run_mythril
from app.services.slither_runner import run_slither
from app.services.store import store
from llm.client import LLMClient, LLMConfig
from riskquant.complexity import estimate_cyclomatic_complexity
from riskquant.engine import compute_r_comp, compute_r_dast, compute_r_sast
from remediation.code_t5 import generate_patch
from riskquant.financial import map_loss_percentage

logger = logging.getLogger(__name__)


async def run_analysis(file_path: Path, analysis_id: str | None = None) -> AnalysisResult:
    analysis_id = analysis_id or str(uuid.uuid4())
    if not store.get(analysis_id):
        store.create(analysis_id, file_path.name)

    logger.info("Analysis %s started for %s", analysis_id, file_path)

    llm = LLMClient(LLMConfig(api_key=settings.openai_api_key, model=settings.openai_model))

    try:
        # Fail fast if Docker isn't available (avoid hanging for 2+ min on Slither)
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "info",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.communicate(), timeout=5.0)
            if proc.returncode != 0:
                raise RuntimeError("Docker not available (docker info failed)")
        except (FileNotFoundError, asyncio.TimeoutError, RuntimeError) as e:
            logger.warning("Docker check failed for %s: %s", analysis_id, e)
            result = AnalysisResult(
                analysis_id=analysis_id,
                filename=file_path.name,
                created_at=store.get(analysis_id).created_at,
                status="failed",
                error="Docker is not running or not in PATH. Start Docker Desktop and run: docker compose -f docker/docker-compose.yml build slither",
            )
            store.update(analysis_id, result)
            return result

        source_code = file_path.read_text(encoding="utf-8")
        compose_path = settings.docker_compose_path or settings.slither_compose_path
        slither_task = asyncio.create_task(run_slither(compose_path, file_path))
        mythril_task = asyncio.create_task(run_mythril(compose_path, file_path))

        slither_result, mythril_result = await asyncio.gather(
            slither_task, mythril_task, return_exceptions=True
        )

        if isinstance(slither_result, Exception):
            logger.warning("Slither failed for %s: %s", analysis_id, slither_result)
        if isinstance(mythril_result, Exception):
            logger.warning("Mythril failed for %s: %s", analysis_id, mythril_result)

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

        # --- Remediation: generate patches for validated findings ---
        patches: list[RemediationPatch] = []
        for finding in filtered_findings:
            patch_code = generate_patch(source_code, finding.title)
            patches.append(
                RemediationPatch(
                    finding_id=finding.id,
                    vuln_type=finding.title,
                    original=source_code,
                    patch=patch_code,
                    explanation=f"Auto-generated patch for {finding.title} vulnerability.",
                )
            )

        result = AnalysisResult(
            analysis_id=analysis_id,
            filename=file_path.name,
            created_at=store.get(analysis_id).created_at,
            status="completed",
            scores=RiskScores(r_sast=r_sast, r_dast=r_dast, r_comp=r_comp),
            findings=filtered_findings,
            remediation=patches,
            summary=summary,
        )
        store.update(analysis_id, result)
        logger.info("Analysis %s completed", analysis_id)
        return result
    except Exception as exc:
        logger.exception("Analysis %s failed: %s", analysis_id, exc)
        result = AnalysisResult(
            analysis_id=analysis_id,
            filename=file_path.name,
            created_at=store.get(analysis_id).created_at,
            status="failed",
            error=str(exc),
        )
        store.update(analysis_id, result)
        return result
