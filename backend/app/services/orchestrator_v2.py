import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from app.config import settings
from app.models.schemas import (
    Finding,
    ModelPrediction,
    RiskScores,
    VerificationInfo,
)
from app.services.anti_hallucination import (
    AntiHallucinationVerifier,
    vulnerability_types_compatible,
)
from app.services.codebert_runner import CodeBERTResult, run_codebert
from app.services.llm_summary import generate_summary
from app.services.defi_classifier import (
    ClassificationResult,
    classify_contract,
    get_business_context,
)
from app.services.multi_tool_orchestrator import (
    MultiToolOrchestrator,
    MultiToolResult,
    get_finding_stats,
)
from app.services.normalized_finding import (
    AnalysisType,
    NormalizedFinding,
    normalize_vuln_type,
)
from riskquant.business_risk_rubric import (
    BusinessRiskReport,
    compare_rubric_vs_llm,
    compute_business_risk_rubric,
    compute_loss_percentage,
)
from riskquant.complexity import estimate_cyclomatic_complexity
from riskquant.engine import compute_composite, compute_r_comp, compute_r_dast, compute_r_sast


@dataclass
class EnhancedAnalysisResult:
    analysis_id: str
    filename: str
    created_at: datetime
    status: str
    defi_category: str | None = None
    defi_confidence: float = 0.0
    business_context: dict[str, Any] = field(default_factory=dict)
    scores: RiskScores | None = None
    total_findings: int = 0
    cross_validated_count: int = 0
    findings: list[Finding] = field(default_factory=list)
    tool_stats: dict[str, Any] = field(default_factory=dict)
    business_risk_report: dict[str, Any] = field(default_factory=dict)
    loss_percentage: float = 0.0
    model_prediction: ModelPrediction | None = None
    verification: VerificationInfo | None = None
    summary: str | None = None
    summary_error: str | None = None
    error: str | None = None


class Orchestrator:

    def __init__(self):
        self.multi_tool = MultiToolOrchestrator(
            compose_path=settings.docker_compose_path,
        )
        self.verifier = AntiHallucinationVerifier(require_dynamic_proof=True)
        self._summary_verifier = AntiHallucinationVerifier(require_dynamic_proof=False)

    async def analyze(
        self,
        file_path: Path,
        analysis_id: str | None = None,
    ) -> EnhancedAnalysisResult:
        analysis_id = analysis_id or str(uuid.uuid4())
        created_at = datetime.utcnow()

        try:
            source_code = file_path.read_text(encoding="utf-8")

            ckpt_path = Path(settings.codebert_checkpoint_path)
            codebert_result: CodeBERTResult = await asyncio.to_thread(
                run_codebert, source_code, ckpt_path
            )
            model_prediction = ModelPrediction(
                available=codebert_result.available,
                vuln_types=codebert_result.vuln_types,
                risk_score=codebert_result.risk_score,
                probabilities=codebert_result.probabilities,
                error=codebert_result.error,
            )

            classification = classify_contract(source_code)
            business_context = get_business_context(classification)

            tool_result = await self.multi_tool.analyze(file_path, analysis_id)
            findings = self._convert_findings(tool_result, classification)

            findings = self._annotate_model_verified(findings, codebert_result)

            summary_text: str | None = None
            summary_error: str | None = None
            summary_verification: VerificationInfo | None = None
            if not settings.openai_api_key:
                summary_error = (
                    "Executive summary is not configured. Set OPENAI_API_KEY in the API environment "
                    "(or backend/.env). Optionally set OPENAI_BASE_URL for compatible providers."
                )
            else:
                llm_result = await asyncio.to_thread(
                    generate_summary,
                    findings,
                    classification.primary_category.value,
                    file_path.name,
                )
                if llm_result.error:
                    summary_error = llm_result.error
                elif llm_result.summary:
                    summary_text = llm_result.summary
                else:
                    summary_error = (
                        "OpenAI returned no summary markdown. Check the model response or try again."
                    )
                if llm_result.claims:
                    expected_losses = {
                        c.vulnerability_type: classification.get_loss_impact(c.vulnerability_type)
                        for c in llm_result.claims
                        if c.vulnerability_type
                    }
                    verification_report = self._summary_verifier.verify_summary(
                        llm_result.claims,
                        tool_result.all_findings,
                        category_expected_losses=expected_losses,
                    )
                    summary_verification = VerificationInfo(
                        status=verification_report.get("overall_status", "unverified"),
                        hallucination_rate=verification_report.get("hallucination_rate", 0.0),
                        total_claims=verification_report.get("total_claims", 0),
                        verified_count=verification_report.get("verified_count", 0),
                        rejected_count=verification_report.get("rejected_count", 0),
                        unverified_count=verification_report.get("unverified_count", 0),
                        needs_review_count=verification_report.get("needs_review_count", 0),
                    )

            scores = self._compute_risk_scores(
                tool_result, classification, source_code, codebert_result
            )

            business_risk_report = self._compute_business_risk(
                tool_result, classification, findings
            )

            vulns = [(f.metadata.get("vulnerability_type", f.title), 1.0) for f in findings]
            loss_pct = compute_loss_percentage(vulns)

            return EnhancedAnalysisResult(
                analysis_id=analysis_id,
                filename=file_path.name,
                created_at=created_at,
                status="completed",
                defi_category=classification.primary_category.value,
                defi_confidence=classification.confidence,
                business_context=business_context,
                scores=scores,
                total_findings=len(findings),
                cross_validated_count=len(tool_result.cross_validated),
                findings=findings,
                tool_stats=get_finding_stats(tool_result),
                business_risk_report=business_risk_report,
                loss_percentage=loss_pct,
                model_prediction=model_prediction,
                verification=summary_verification,
                summary=summary_text,
                summary_error=summary_error,
            )

        except Exception as exc:
            return EnhancedAnalysisResult(
                analysis_id=analysis_id,
                filename=file_path.name,
                created_at=created_at,
                status="failed",
                error=str(exc),
            )

    def _codebert_canonical_predicted_types(self, cr: CodeBERTResult | None) -> set[str]:
        out: set[str] = set()
        if not cr or not cr.available:
            return out
        for v in cr.vuln_types or []:
            c = normalize_vuln_type(v).lower().replace("_", "-")
            if c:
                out.add(c)
        if out:
            return out
        probs = cr.probabilities or {}
        thr_map = cr.thresholds or {}
        if not probs:
            return out
        for lab, p in probs.items():
            thr = float(thr_map.get(lab, 0.5))
            if p >= max(0.28, thr * 0.75):  # slightly relaxed threshold to catch borderline cases
                c = normalize_vuln_type(lab).lower().replace("_", "-")
                if c:
                    out.add(c)
        return out

    def _annotate_model_verified(
        self,
        findings: list[Finding],
        codebert_result: CodeBERTResult | None,
    ) -> list[Finding]:
        predicted = self._codebert_canonical_predicted_types(codebert_result)
        annotated: list[Finding] = []
        for f in findings:
            raw_vt = f.metadata.get("vulnerability_type") or f.title or ""
            finding_vt = (
                normalize_vuln_type(raw_vt).lower().replace("_", "-") if raw_vt else ""
            )
            model_verified = bool(finding_vt) and bool(predicted) and any(
                vulnerability_types_compatible(pc, finding_vt) for pc in predicted
            )
            annotated.append(Finding(
                id=f.id,
                title=f.title,
                impact=f.impact,
                confidence=f.confidence,
                description=f.description,
                source=f.source,
                location=f.location,
                vulnerable=f.vulnerable,
                loss_percentage=f.loss_percentage,
                metadata={**f.metadata, "model_verified": model_verified},
            ))
        return annotated

    def _convert_findings(
        self,
        tool_result: MultiToolResult,
        classification: ClassificationResult,
    ) -> list[Finding]:
        tier_by_id: dict[str, str] = {}
        for f in tool_result.high_confidence:
            tier_by_id[f.id] = "HIGH_CONFIDENCE"
        for f in tool_result.medium_confidence:
            tier_by_id[f.id] = "MEDIUM_CONFIDENCE"
        for f in tool_result.lone_signals:
            tier_by_id.setdefault(f.id, "LONE_SIGNAL")

        findings: list[Finding] = []
        for nf in tool_result.all_findings:
            loss_pct = classification.get_loss_impact(nf.vulnerability_type)
            tier = tier_by_id.get(nf.id, "LONE_SIGNAL")
            is_cross_validated = tier in ("HIGH_CONFIDENCE", "MEDIUM_CONFIDENCE")
            findings.append(Finding(
                id=nf.id,
                title=nf.title,
                impact=nf.severity.value,
                confidence=f"{nf.confidence:.0%}",
                description=nf.description,
                source=nf.tool.value,
                location=str(nf.location) if nf.location else None,
                vulnerable=nf.is_reachable or is_cross_validated,
                loss_percentage=loss_pct,
                metadata={
                    "analysis_type": nf.analysis_type.value,
                    "vulnerability_type": nf.vulnerability_type,
                    "swc_id": nf.swc_id,
                    "is_reachable": nf.is_reachable,
                    "has_exploit_proof": nf.has_exploit_proof,
                    "cross_validated": is_cross_validated,
                    "confidence_tier": tier,
                },
            ))
        return findings

    def _compute_risk_scores(
        self,
        tool_result: MultiToolResult,
        classification: ClassificationResult,
        source_code: str,
        codebert_result: CodeBERTResult | None = None,
    ) -> RiskScores:
        static_findings = [
            f
            for f in tool_result.all_findings
            if f.analysis_type in (AnalysisType.STATIC, AnalysisType.PATTERN)
        ]
        dynamic_findings = [
            f for f in tool_result.all_findings
            if f.analysis_type in (AnalysisType.SYMBOLIC, AnalysisType.BYTECODE)
        ]

        sast_issues: list[tuple[str, str]] = []
        for f in static_findings:
            try:
                conf_val = int(f"{f.confidence:.0%}".replace("%", ""))
                conf_cat = "High" if conf_val >= 80 else "Medium" if conf_val >= 50 else "Low"
            except ValueError:
                conf_cat = "Medium"
            sast_issues.append((f.severity.value, conf_cat))
        r_sast = compute_r_sast(sast_issues)

        dast_severities = [(f.severity_score, f.is_reachable) for f in dynamic_findings]
        r_dast = compute_r_dast(dast_severities)

        cc = estimate_cyclomatic_complexity(source_code)
        r_comp = compute_r_comp(cc)

        r_model: float | None = None
        if codebert_result and codebert_result.available and not codebert_result.error:
            r_model = codebert_result.risk_score
            composite = round(
                0.35 * r_sast + 0.25 * r_dast + 0.15 * r_comp + 0.25 * r_model, 4
            )
        else:
            composite = compute_composite(r_sast, r_dast, r_comp)

        return RiskScores(r_sast=r_sast, r_dast=r_dast, r_comp=r_comp, composite=composite, r_model=r_model)

    def _compute_business_risk(
        self,
        tool_result: MultiToolResult,
        classification: ClassificationResult,
        findings: list[Finding],
    ) -> dict[str, Any]:
        defi_cat = classification.primary_category.value
        total_tools_run = len(tool_result.tool_results)
        cross_validated_ids = {cv.id for cv in tool_result.cross_validated}

        report = BusinessRiskReport()

        for finding in findings:
            vuln_type = finding.metadata.get("vulnerability_type", finding.title)
            has_proof = finding.metadata.get("has_exploit_proof", False)
            is_reachable = finding.metadata.get("is_reachable", False)
            is_cv = finding.metadata.get("cross_validated", False) or (
                finding.id in cross_validated_ids
            )

            matched_tools: set[str] = set()
            vuln_key = vuln_type.lower().replace("_", "-")
            for nf in tool_result.all_findings:
                if vuln_key in nf.vulnerability_type.lower().replace("_", "-"):
                    matched_tools.add(nf.tool.value)

            rubric = compute_business_risk_rubric(
                vulnerability_type=vuln_type,
                loss_percentage=finding.loss_percentage,
                defi_category=defi_cat,
                tools_reporting=len(matched_tools),
                total_tools_run=total_tools_run,
                is_cross_validated=is_cv,
                has_exploit_proof=has_proof,
                is_reachable=is_reachable,
            )
            comparison = compare_rubric_vs_llm(
                vulnerability_type=vuln_type,
                rubric=rubric,
                llm_loss_percentage=None,
            )
            report.per_finding.append(comparison)

        return report.to_dict()
