"""
AuditQuant Orchestrator V2

Enhanced orchestrator that integrates:
1. Multi-tool analysis (5 tools: Slither, Securify, Mythril, Echidna, Oyente)
2. DeFi contract classification for business context
3. Anti-hallucination verification layer
4. Enhanced RiskQuant with multi-tool inputs

Pipeline:
1. Input contract → 5 Audit tools (parallel) → Normalize outputs
2. Tool output → DeFi classification → Business context
3. Normalized findings → LLM summary (structured fields)
4. LLM output → Anti-hallucination check → Verified findings
5. Verified findings → RiskQuant → Final scores
6. Optional: CodeT5 remediation
"""
from __future__ import annotations

import asyncio
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from app.config import settings
from app.models.schemas import AnalysisResult, Finding, RiskScores
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
from app.services.normalized_finding import NormalizedFinding, Severity
from app.services.store import store
from llm.client import LLMClient, LLMConfig
from riskquant.complexity import estimate_cyclomatic_complexity
from riskquant.engine import compute_r_comp, compute_r_dast, compute_r_sast


@dataclass
class EnhancedAnalysisResult:
    """Extended analysis result with multi-tool and verification data."""
    analysis_id: str
    filename: str
    created_at: datetime
    status: str
    
    # DeFi classification
    defi_category: str | None = None
    defi_confidence: float = 0.0
    business_context: dict[str, Any] = field(default_factory=dict)
    
    # Risk scores (unchanged formula, but more inputs)
    scores: RiskScores | None = None
    
    # Multi-tool findings
    total_findings: int = 0
    cross_validated_count: int = 0
    findings: list[Finding] = field(default_factory=list)
    
    # Anti-hallucination results
    verification_status: str = "pending"
    hallucination_rate: float = 0.0
    verified_findings: list[Finding] = field(default_factory=list)
    
    # Tool execution stats
    tool_stats: dict[str, Any] = field(default_factory=dict)
    
    # LLM outputs
    summary: str | None = None
    
    # Error handling
    error: str | None = None


class OrchestratorV2:
    """
    Enhanced orchestrator with multi-tool support and anti-hallucination.
    """
    
    def __init__(
        self,
        enable_securify: bool = True,
        enable_echidna: bool = True,
        enable_oyente: bool = True,
        enable_llm_validation: bool = True,
        require_dynamic_proof: bool = True,
    ):
        self.multi_tool = MultiToolOrchestrator(
            compose_path=settings.slither_compose_path,
            enable_securify=enable_securify,
            enable_echidna=enable_echidna,
            enable_oyente=enable_oyente,
        )
        self.verifier = AntiHallucinationVerifier(
            require_dynamic_proof=require_dynamic_proof,
        )
        self.enable_llm_validation = enable_llm_validation
        
        # LLM client
        if settings.openai_api_key:
            self.llm = LLMClient(LLMConfig(
                api_key=settings.openai_api_key,
                model=settings.openai_model,
            ))
        else:
            self.llm = None
    
    async def analyze(
        self,
        file_path: Path,
        analysis_id: str | None = None,
    ) -> EnhancedAnalysisResult:
        """
        Run the complete enhanced analysis pipeline.
        """
        analysis_id = analysis_id or str(uuid.uuid4())
        created_at = datetime.utcnow()
        
        # Store initial state
        if not store.get(analysis_id):
            store.create(analysis_id, file_path.name)
        
        try:
            # Step 1: Read source code
            source_code = file_path.read_text(encoding="utf-8")
            
            # Step 2: DeFi classification (fast, sync)
            classification = classify_contract(source_code)
            business_context = get_business_context(classification)
            
            # Step 3: Multi-tool analysis (parallel, async)
            tool_result = await self.multi_tool.analyze(file_path, analysis_id)
            
            # Step 4: Convert findings to legacy format + enhance
            findings = self._convert_findings(tool_result, classification)
            
            # Step 5: LLM validation and summary (if enabled)
            verified_findings = findings
            verification_report = {}
            summary = None
            
            if self.llm and self.enable_llm_validation:
                # Generate LLM summary
                summary, claims = await self._generate_verified_summary(
                    tool_result.all_findings,
                    classification,
                    source_code,
                )
                
                # Verify claims
                if claims:
                    expected_losses = self._get_expected_losses(classification)
                    verification_report = self.verifier.verify_summary(
                        claims,
                        tool_result.all_findings,
                        expected_losses,
                    )
                    
                    # Filter to verified findings only
                    if verification_report.get("overall_status") != "rejected":
                        verified_findings = self._filter_verified_findings(
                            findings,
                            verification_report,
                        )
            
            # Step 6: Compute risk scores using all tool data
            scores = self._compute_enhanced_scores(
                tool_result,
                classification,
                source_code,
            )
            
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
                verification_status=verification_report.get("overall_status", "skipped"),
                hallucination_rate=verification_report.get("hallucination_rate", 0.0),
                verified_findings=verified_findings,
                tool_stats=get_finding_stats(tool_result),
                summary=summary,
            )
            
            # Update store with legacy format
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
        """Convert normalized findings to legacy Finding format."""
        findings: list[Finding] = []
        
        for nf in tool_result.all_findings:
            # Get loss percentage based on DeFi category
            loss_pct = classification.get_loss_impact(nf.vulnerability_type)
            
            # Check if cross-validated
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
        """Generate LLM summary with structured output for verification."""
        if not self.llm:
            return "", []
        
        # Build context-aware prompt
        business_ctx = get_business_context(classification)
        
        findings_text = "\n".join(
            f"- [{f.tool.value}] {f.title}: {f.description} "
            f"(Severity: {f.severity.value}, Reachable: {f.is_reachable})"
            for f in findings[:15]  # Limit to avoid token overflow
        )
        
        prompt = f"""You are a smart contract security auditor analyzing a {business_ctx['description']}.

Contract Category: {classification.primary_category.value}
Assets at Risk: {business_ctx['assets_at_risk']}
Known Attack Vectors for this category: {', '.join(business_ctx['attack_vectors'])}

Tool Findings:
{findings_text}

For each REAL vulnerability (ignore false positives), provide a structured analysis:

VULNERABILITY: <vulnerability type>
LOCATION: <file:line or function name>
EXPLOITABLE: <yes/no - only say yes if tools provided proof>
LOSS_PERCENTAGE: <0-100 based on category and severity>
EXPLANATION: <brief explanation of the risk>

Rules:
- Only report vulnerabilities that tools actually found
- Do not invent new vulnerabilities not in the tool output
- EXPLOITABLE=yes requires proof from Mythril, Echidna, or Oyente
- Loss percentage should match the DeFi category (e.g., reentrancy in AMM = 100%)

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
        """Get expected loss percentages for vulnerability types in this category."""
        from app.services.defi_classifier import CATEGORY_LOSS_IMPACT
        
        expected = {}
        for (cat, vuln), loss in CATEGORY_LOSS_IMPACT.items():
            if cat == classification.primary_category:
                expected[vuln] = loss
        
        return expected
    
    def _filter_verified_findings(
        self,
        findings: list[Finding],
        verification_report: dict[str, Any],
    ) -> list[Finding]:
        """Filter findings to only those verified by anti-hallucination check."""
        verified_vulns = set()
        
        for claim_result in verification_report.get("per_claim_results", []):
            if claim_result.get("status") in ("verified", "needs_review"):
                if claim_result.get("vulnerability_type"):
                    verified_vulns.add(claim_result["vulnerability_type"].lower())
        
        if not verified_vulns:
            # If no verified claims, return all findings with dynamic proof
            return [
                f for f in findings
                if f.metadata.get("has_exploit_proof") or f.metadata.get("cross_validated")
            ]
        
        return [
            f for f in findings
            if f.metadata.get("vulnerability_type", "").lower() in verified_vulns
            or f.metadata.get("has_exploit_proof")
        ]
    
    def _compute_enhanced_scores(
        self,
        tool_result: MultiToolResult,
        classification: ClassificationResult,
        source_code: str,
    ) -> RiskScores:
        """
        Compute risk scores using multi-tool data.
        
        Uses same formulas from the report:
        - R_SAST: Static Density Score (now aggregates Slither + Securify)
        - R_DAST: Dynamic Certainty Score (now aggregates Mythril + Echidna + Oyente)
        - R_COMP: Complexity Risk Score (unchanged)
        """
        from app.services.normalized_finding import AnalysisType, ToolSource
        
        # Separate static vs dynamic findings
        static_findings = [
            f for f in tool_result.all_findings
            if f.analysis_type == AnalysisType.STATIC
        ]
        dynamic_findings = [
            f for f in tool_result.all_findings
            if f.analysis_type in (AnalysisType.SYMBOLIC, AnalysisType.FUZZING)
        ]
        
        # R_SAST: Aggregate static tool findings
        sast_issues = [
            (f.severity.value, f"{f.confidence:.0%}".replace("%", ""))
            for f in static_findings
        ]
        # Convert confidence percentage string to category
        sast_issues_converted = []
        for impact, conf_str in sast_issues:
            try:
                conf_val = int(conf_str) if conf_str else 50
                conf_cat = "High" if conf_val >= 80 else "Medium" if conf_val >= 50 else "Low"
            except ValueError:
                conf_cat = "Medium"
            sast_issues_converted.append((impact, conf_cat))
        
        r_sast = compute_r_sast(sast_issues_converted)
        
        # R_DAST: Aggregate dynamic tool findings
        dast_severities = [
            (f.severity_score, f.is_reachable)
            for f in dynamic_findings
        ]
        r_dast = compute_r_dast(dast_severities)
        
        # Boost R_DAST if we have cross-validated findings with exploit proof
        if any(f.has_exploit_proof for f in tool_result.cross_validated):
            r_dast = min(100.0, r_dast * 1.2)
        
        # R_COMP: Complexity (unchanged)
        cc = estimate_cyclomatic_complexity(source_code)
        r_comp = compute_r_comp(cc)
        
        return RiskScores(r_sast=r_sast, r_dast=r_dast, r_comp=r_comp)
    
    def _update_store(
        self,
        analysis_id: str,
        result: EnhancedAnalysisResult,
    ) -> None:
        """Update the legacy store with enhanced result."""
        legacy_result = AnalysisResult(
            analysis_id=result.analysis_id,
            filename=result.filename,
            created_at=result.created_at,
            status=result.status,
            scores=result.scores,
            findings=result.verified_findings or result.findings,
            summary=result.summary,
            error=result.error,
        )
        store.update(analysis_id, legacy_result)


async def run_analysis_v2(
    file_path: Path,
    analysis_id: str | None = None,
) -> EnhancedAnalysisResult:
    """Convenience function to run enhanced analysis."""
    orchestrator = OrchestratorV2(
        enable_securify=settings.enable_securify,
        enable_echidna=settings.enable_echidna,
        enable_oyente=settings.enable_oyente,
    )
    return await orchestrator.analyze(file_path, analysis_id)
