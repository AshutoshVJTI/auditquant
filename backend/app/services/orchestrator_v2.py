"""
Main orchestrator for the AuditQuant analysis pipeline.
Ties together tool runners, LLM summarization, verification, and risk scoring.
"""

import asyncio
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from app.config import settings
from app.models.schemas import (
    AnalysisResult,
    Finding,
    RemediationPatch,
    RiskScores,
)
from app.services.anti_hallucination import (
    AntiHallucinationVerifier,
    LLMClaim,
    VerificationStatus,
    extract_claims_from_llm_output,
)
from app.services.defi_classifier import (
    ClassificationResult,
    DeFiCategory,
    classify_contract,
    get_business_context,
)
from app.services.multi_tool_orchestrator import (
    MultiToolOrchestrator,
    MultiToolResult,
    get_finding_stats,
)
from app.services.normalized_finding import AnalysisType, NormalizedFinding, Severity
from app.services.store import store
from app.services.swc_knowledge import get_swc_knowledge_base
from llm.client import LLMClient, LLMConfig
from remediation.code_t5 import generate_patch
from riskquant.business_risk_rubric import (
    BusinessRiskReport,
    RubricScores,
    compare_rubric_vs_llm,
    compute_business_risk_rubric,
)
from riskquant.complexity import estimate_cyclomatic_complexity
from riskquant.engine import compute_r_comp, compute_r_dast, compute_r_sast
from riskquant.financial import compute_loss_percentage, map_loss_percentage


@dataclass
class EnhancedAnalysisResult:
    """Everything the pipeline produces for a single contract analysis."""

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

    verification_status: str = "pending"
    hallucination_rate: float = 0.0
    verified_findings: list[Finding] = field(default_factory=list)

    tool_stats: dict[str, Any] = field(default_factory=dict)
    business_risk_report: dict[str, Any] = field(default_factory=dict)
    summary: str | None = None
    remediation: list[RemediationPatch] = field(default_factory=list)
    loss_percentage: float = 0.0
    error: str | None = None


class Orchestrator:

    def __init__(
        self,
        enable_oyente: bool = True,
        enable_llm_validation: bool = True,
        require_dynamic_proof: bool = True,
    ):
        self.multi_tool = MultiToolOrchestrator(
            compose_path=settings.docker_compose_path or settings.slither_compose_path,
            enable_oyente=enable_oyente,
        )
        self.verifier = AntiHallucinationVerifier(
            require_dynamic_proof=require_dynamic_proof,
        )
        self.enable_llm_validation = enable_llm_validation

        if settings.openai_api_key:
            self.llm = LLMClient(
                LLMConfig(
                    api_key=settings.openai_api_key,
                    model=settings.openai_model,
                    base_url=settings.openai_base_url,
                )
            )
        else:
            self.llm = None

    async def analyze(
        self,
        file_path: Path,
        analysis_id: str | None = None,
    ) -> EnhancedAnalysisResult:
        """Run the full pipeline on a single .sol file."""
        analysis_id = analysis_id or str(uuid.uuid4())
        created_at = datetime.utcnow()

        if not store.get(analysis_id):
            store.create(analysis_id, file_path.name)

        try:
            source_code = file_path.read_text(encoding="utf-8")

            # classify the contract so risk scoring has business context
            classification = classify_contract(source_code)
            business_context = get_business_context(classification)

            # run all tools in parallel
            tool_result = await self.multi_tool.analyze(file_path, analysis_id)
            findings = self._convert_findings(tool_result, classification)

            # LLM summary + verification
            verified_findings = findings
            verification_report: dict[str, Any] = {}
            summary = None

            if self.llm and self.enable_llm_validation:
                summary, claims = await self._generate_verified_summary(
                    tool_result.all_findings,
                    classification,
                    source_code,
                )
                if claims:
                    expected_losses = self._get_expected_losses(classification)
                    verification_report = self.verifier.verify_summary(
                        claims,
                        tool_result.all_findings,
                        expected_losses,
                    )
                    if verification_report.get("overall_status") != "rejected":
                        verified_findings = self._filter_verified_findings(
                            findings,
                            verification_report,
                        )

            scores = self._compute_risk_scores(tool_result, classification, source_code)
            business_risk_report = self._compute_business_risk(
                tool_result, classification, verified_findings,
            )
            loss_pct = self._compute_loss_percentage(verified_findings)
            patches = self._generate_remediation(source_code, verified_findings)

            result = EnhancedAnalysisResult(
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
                verification_status=verification_report.get(
                    "overall_status", "skipped"
                ),
                hallucination_rate=verification_report.get(
                    "hallucination_rate", 0.0
                ),
                verified_findings=verified_findings,
                tool_stats=get_finding_stats(tool_result),
                business_risk_report=business_risk_report,
                summary=summary,
                remediation=patches,
                loss_percentage=loss_pct,
            )

            self._update_store(analysis_id, result)
            return result

        except Exception as exc:
            result = EnhancedAnalysisResult(
                analysis_id=analysis_id,
                filename=file_path.name,
                created_at=created_at,
                status="failed",
                error=str(exc),
            )
            return result

    def _convert_findings(
        self,
        tool_result: MultiToolResult,
        classification: ClassificationResult,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for nf in tool_result.all_findings:
            loss_pct = classification.get_loss_impact(nf.vulnerability_type)
            is_cross_validated = any(
                cv.id == nf.id for cv in tool_result.cross_validated
            )
            finding = Finding(
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
                },
            )
            findings.append(finding)
        return findings

    async def _generate_verified_summary(
        self,
        findings: list[NormalizedFinding],
        classification: ClassificationResult,
        source_code: str,
    ) -> tuple[str, list[LLMClaim]]:
        if not self.llm:
            return "", []

        business_ctx = get_business_context(classification)
        findings_text = "\n".join(
            f"- [{f.tool.value}] {f.title}: {f.description} "
            f"(Severity: {f.severity.value}, Reachable: {f.is_reachable})"
            for f in findings[:15]
        )

        # Enrich prompt with authoritative SWC knowledge
        swc_kb = get_swc_knowledge_base()
        finding_types = [f.vulnerability_type for f in findings[:15]]
        swc_ids = [f.swc_id for f in findings[:15]]
        swc_context = swc_kb.get_context_for_findings(finding_types, swc_ids)

        prompt = f"""You are a smart contract security auditor analyzing a {business_ctx['description']}.

Contract Category: {classification.primary_category.value}
Assets at Risk: {business_ctx['assets_at_risk']}
Known Attack Vectors: {', '.join(business_ctx['attack_vectors'])}

Tool Findings:
{findings_text}

{swc_context}
For each REAL vulnerability (ignore false positives), provide:

VULNERABILITY: <type>
LOCATION: <file:line or function name>
EXPLOITABLE: <yes/no — only yes if tools provided proof>
LOSS_PERCENTAGE: <0-100 based on category and severity>
DESCRIPTION: <what the vulnerability is and why it exists — use the SWC description above for accuracy>
EXPLOIT_SCENARIO: <step-by-step attack scenario — ground this in the SWC reference>
TECHNICAL_IMPACT: <code-level technical consequences>
FIX_RECOMMENDATION: <specific, actionable remediation steps — use the SWC remediation guidance above>

Rules:
- Only report vulnerabilities actually found by tools
- Do not invent new vulnerabilities not in the tool output
- EXPLOITABLE=yes requires proof from Mythril or Oyente
- Loss percentage should match the DeFi category
- Base your DESCRIPTION and FIX_RECOMMENDATION on the SWC reference when available

Summary:"""

        try:
            summary = await self.llm.generate_summary_async(
                [{"prompt": prompt, "findings": [f.to_dict() for f in findings]}]
            )
            claims = extract_claims_from_llm_output(summary)
            return summary, claims
        except Exception:
            return "", []

    def _get_expected_losses(
        self,
        classification: ClassificationResult,
    ) -> dict[str, float]:
        from app.services.defi_classifier import CATEGORY_LOSS_IMPACT

        expected: dict[str, float] = {}
        for (cat, vuln), loss in CATEGORY_LOSS_IMPACT.items():
            if cat == classification.primary_category:
                expected[vuln] = loss
        return expected

    def _filter_verified_findings(
        self,
        findings: list[Finding],
        verification_report: dict[str, Any],
    ) -> list[Finding]:
        verified_vulns: set[str] = set()
        for claim_result in verification_report.get("per_claim_results", []):
            if claim_result.get("status") in ("verified", "needs_review"):
                if claim_result.get("vulnerability_type"):
                    verified_vulns.add(claim_result["vulnerability_type"].lower())

        if not verified_vulns:
            return [
                f
                for f in findings
                if f.metadata.get("has_exploit_proof")
                or f.metadata.get("cross_validated")
            ]

        return [
            f
            for f in findings
            if f.metadata.get("vulnerability_type", "").lower() in verified_vulns
            or f.metadata.get("has_exploit_proof")
        ]

    def _compute_risk_scores(
        self,
        tool_result: MultiToolResult,
        classification: ClassificationResult,
        source_code: str,
    ) -> RiskScores:
        static_findings = [
            f
            for f in tool_result.all_findings
            if f.analysis_type == AnalysisType.STATIC
        ]
        dynamic_findings = [
            f
            for f in tool_result.all_findings
            if f.analysis_type in (AnalysisType.SYMBOLIC, AnalysisType.BYTECODE)
        ]

        sast_issues: list[tuple[str, str]] = []
        for f in static_findings:
            try:
                conf_val = int(f"{f.confidence:.0%}".replace("%", ""))
                conf_cat = (
                    "High" if conf_val >= 80 else "Medium" if conf_val >= 50 else "Low"
                )
            except ValueError:
                conf_cat = "Medium"
            sast_issues.append((f.severity.value, conf_cat))
        r_sast = compute_r_sast(sast_issues)

        dast_severities = [
            (f.severity_score, f.is_reachable) for f in dynamic_findings
        ]
        r_dast = compute_r_dast(dast_severities)

        # bump R_DAST when cross-validated findings include an exploit proof
        if any(f.has_exploit_proof for f in tool_result.cross_validated):
            r_dast = min(100.0, r_dast * 1.2)

        cc = estimate_cyclomatic_complexity(source_code)
        r_comp = compute_r_comp(cc)

        return RiskScores(r_sast=r_sast, r_dast=r_dast, r_comp=r_comp)

    def _compute_business_risk(
        self,
        tool_result: MultiToolResult,
        classification: ClassificationResult,
        findings: list[Finding],
    ) -> dict[str, Any]:
        """Score each finding on a 4-part rubric and compare vs LLM loss bucket."""
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
                llm_loss_percentage=finding.loss_percentage,
            )
            report.per_finding.append(comparison)

        return report.to_dict()

    def _compute_loss_percentage(self, findings: list[Finding]) -> float:
        vulns: list[tuple[str, float]] = []
        for f in findings:
            vuln_type = f.metadata.get("vulnerability_type", f.title)
            vulns.append((vuln_type, 1.0))
        return compute_loss_percentage(vulns)

    def _generate_remediation(
        self,
        source_code: str,
        findings: list[Finding],
    ) -> list[RemediationPatch]:
        patches: list[RemediationPatch] = []
        for finding in findings:
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
        return patches

    def _update_store(
        self,
        analysis_id: str,
        result: EnhancedAnalysisResult,
    ) -> None:
        legacy_result = AnalysisResult(
            analysis_id=result.analysis_id,
            filename=result.filename,
            created_at=result.created_at,
            status=result.status,
            scores=result.scores,
            findings=result.verified_findings or result.findings,
            remediation=result.remediation,
            summary=result.summary,
            error=result.error,
        )
        store.update(analysis_id, legacy_result)


async def run_analysis(
    file_path: Path,
    analysis_id: str | None = None,
) -> EnhancedAnalysisResult:
    orchestrator = Orchestrator(
        enable_oyente=settings.enable_oyente,
    )
    return await orchestrator.analyze(file_path, analysis_id)
