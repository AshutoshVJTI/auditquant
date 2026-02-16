"""
Checks LLM claims against actual tool evidence to catch hallucinations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from app.services.normalized_finding import (
    AnalysisType,
    NormalizedFinding,
    ToolSource,
)
from app.services.swc_knowledge import get_swc_knowledge_base


class VerificationStatus(str, Enum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    REJECTED = "rejected"
    NEEDS_REVIEW = "needs_review"


@dataclass
class VerificationResult:
    status: VerificationStatus
    confidence: float
    evidence_summary: str
    issues: list[str] = field(default_factory=list)
    supporting_tools: list[str] = field(default_factory=list)
    has_dynamic_proof: bool = False


@dataclass
class LLMClaim:
    """One claim parsed from LLM output that we need to check."""
    claim_type: str
    vulnerability_type: str | None = None
    location: str | None = None
    function_name: str | None = None
    is_exploitable: bool = False
    loss_percentage: float | None = None
    explanation: str = ""
    description: str = ""
    exploit_scenario: str = ""
    technical_impact: str = ""
    fix_recommendation: str = ""


class AntiHallucinationVerifier:
    
    def __init__(
        self,
        require_dynamic_proof: bool = True,
        min_tool_agreement: int = 1,
        loss_variance_threshold: float = 30.0,
    ):
        self.require_dynamic_proof = require_dynamic_proof
        self.min_tool_agreement = min_tool_agreement
        self.loss_variance_threshold = loss_variance_threshold
    
    def verify_claim(
        self,
        claim: LLMClaim,
        findings: list[NormalizedFinding],
        category_expected_loss: float | None = None,
    ) -> VerificationResult:
        issues: list[str] = []
        supporting_tools: list[str] = []
        has_dynamic_proof = False

        swc_kb = get_swc_knowledge_base()

        # Find matching findings
        matching_findings = self._find_matching_findings(claim, findings)

        if not matching_findings:
            return VerificationResult(
                status=VerificationStatus.REJECTED,
                confidence=0.0,
                evidence_summary="No tool found this vulnerability type",
                issues=["LLM claimed vulnerability not detected by any tool"],
            )

        if claim.vulnerability_type and swc_kb.is_loaded:
            if not swc_kb.is_known_vulnerability(claim.vulnerability_type):
                issues.append(
                    f"Vulnerability type '{claim.vulnerability_type}' not recognised in SWC registry"
                )

        # check exploit scenario references expected SWC keywords
        if claim.exploit_scenario and claim.vulnerability_type and swc_kb.is_loaded:
            expected_kw = swc_kb.get_known_exploit_keywords(claim.vulnerability_type)
            if expected_kw:
                scenario_lower = claim.exploit_scenario.lower()
                hits = sum(1 for kw in expected_kw if kw in scenario_lower)
                if hits == 0:
                    issues.append(
                        "Exploit scenario does not reference any expected SWC keywords"
                    )

        # check fix recommendation aligns with SWC remediation guidance
        if claim.fix_recommendation and claim.vulnerability_type and swc_kb.is_loaded:
            swc_entry = swc_kb.get_by_vuln_type(claim.vulnerability_type)
            if swc_entry and swc_entry.get("remediation"):
                rem_lower = swc_entry["remediation"].lower()
                fix_lower = claim.fix_recommendation.lower()
                # rough semantic overlap -- at least 2 non-stopword matches
                rem_words = set(rem_lower.split()) - {"the", "a", "to", "and", "of", "is", "in", "for", "with", "be", "that"}
                fix_words = set(fix_lower.split()) - {"the", "a", "to", "and", "of", "is", "in", "for", "with", "be", "that"}
                common = rem_words & fix_words
                if len(common) < 2:
                    issues.append(
                        "Fix recommendation does not align with SWC remediation guidance"
                    )

        tools_reporting = set(f.tool for f in matching_findings)
        supporting_tools = [t.value for t in tools_reporting]

        if len(tools_reporting) < self.min_tool_agreement:
            issues.append(f"Only {len(tools_reporting)} tool(s) reported this; minimum {self.min_tool_agreement} required")

        dynamic_findings = [
            f for f in matching_findings
            if f.analysis_type in (AnalysisType.SYMBOLIC, AnalysisType.BYTECODE)
        ]

        if dynamic_findings:
            has_dynamic_proof = any(f.has_exploit_proof for f in dynamic_findings)

        if claim.is_exploitable and self.require_dynamic_proof:
            if not has_dynamic_proof:
                return VerificationResult(
                    status=VerificationStatus.REJECTED,
                    confidence=0.0,
                    evidence_summary="Exploitability claim requires dynamic proof",
                    issues=["LLM claimed exploitable but no dynamic tool provided exploit trace"],
                    supporting_tools=supporting_tools,
                    has_dynamic_proof=False,
                )

        if claim.location:
            location_match = any(
                f.location and self._locations_match(claim.location, str(f.location))
                for f in matching_findings
            )
            if not location_match:
                issues.append("Claimed location does not match any tool finding")

        if claim.loss_percentage is not None and category_expected_loss is not None:
            variance = abs(claim.loss_percentage - category_expected_loss)
            if variance > self.loss_variance_threshold:
                issues.append(
                    f"Loss % ({claim.loss_percentage}%) differs significantly from "
                    f"category baseline ({category_expected_loss}%)"
                )

        # confidence heuristic
        base_confidence = 0.5
        base_confidence += min(0.2, len(tools_reporting) * 0.1)
        if has_dynamic_proof:
            base_confidence += 0.25
        if claim.vulnerability_type and swc_kb.is_known_vulnerability(claim.vulnerability_type):
            base_confidence += 0.05
        base_confidence -= len(issues) * 0.1

        confidence = max(0.0, min(1.0, base_confidence))

        if not issues:
            status = VerificationStatus.VERIFIED
        elif len(issues) <= 1 and confidence >= 0.5:
            status = VerificationStatus.NEEDS_REVIEW
        else:
            status = VerificationStatus.UNVERIFIED

        evidence_parts = [
            f"Found by {len(tools_reporting)} tool(s): {', '.join(supporting_tools)}",
        ]
        if has_dynamic_proof:
            evidence_parts.append("Has dynamic exploit proof")

        return VerificationResult(
            status=status,
            confidence=confidence,
            evidence_summary="; ".join(evidence_parts),
            issues=issues,
            supporting_tools=supporting_tools,
            has_dynamic_proof=has_dynamic_proof,
        )
    
    def verify_summary(
        self,
        summary_claims: list[LLMClaim],
        findings: list[NormalizedFinding],
        category_expected_losses: dict[str, float] | None = None,
    ) -> dict[str, Any]:
        """Verify all claims and return {overall_status, hallucination_rate, ...}."""
        results: list[VerificationResult] = []
        
        for claim in summary_claims:
            expected_loss = None
            if category_expected_losses and claim.vulnerability_type:
                expected_loss = category_expected_losses.get(claim.vulnerability_type)
            
            result = self.verify_claim(claim, findings, expected_loss)
            results.append(result)
        
        rejected_count = sum(1 for r in results if r.status == VerificationStatus.REJECTED)
        unverified_count = sum(1 for r in results if r.status == VerificationStatus.UNVERIFIED)
        
        hallucination_rate = (rejected_count / len(results)) if results else 0.0
        unverified_rate = (unverified_count / len(results)) if results else 0.0
        
        # Overall status
        if hallucination_rate > 0.3:
            overall_status = VerificationStatus.REJECTED
        elif hallucination_rate > 0 or unverified_rate > 0.5:
            overall_status = VerificationStatus.NEEDS_REVIEW
        elif all(r.status == VerificationStatus.VERIFIED for r in results):
            overall_status = VerificationStatus.VERIFIED
        else:
            overall_status = VerificationStatus.UNVERIFIED
        
        return {
            "overall_status": overall_status.value,
            "total_claims": len(summary_claims),
            "verified_count": sum(1 for r in results if r.status == VerificationStatus.VERIFIED),
            "rejected_count": rejected_count,
            "unverified_count": unverified_count,
            "needs_review_count": sum(1 for r in results if r.status == VerificationStatus.NEEDS_REVIEW),
            "hallucination_rate": hallucination_rate,
            "average_confidence": sum(r.confidence for r in results) / len(results) if results else 0.0,
            "claims_with_dynamic_proof": sum(1 for r in results if r.has_dynamic_proof),
            "per_claim_results": [
                {
                    "claim_type": claim.claim_type,
                    "vulnerability_type": claim.vulnerability_type,
                    "status": result.status.value,
                    "confidence": result.confidence,
                    "evidence": result.evidence_summary,
                    "issues": result.issues,
                }
                for claim, result in zip(summary_claims, results)
            ],
        }
    
    def _find_matching_findings(
        self,
        claim: LLMClaim,
        findings: list[NormalizedFinding],
    ) -> list[NormalizedFinding]:
        if not claim.vulnerability_type:
            return []
        
        claim_type = claim.vulnerability_type.lower().replace("_", "-")
        
        matches = []
        for f in findings:
            finding_type = f.vulnerability_type.lower().replace("_", "-")
            
            # Check for type match (allowing partial matches)
            if claim_type in finding_type or finding_type in claim_type:
                matches.append(f)
            elif self._types_are_related(claim_type, finding_type):
                matches.append(f)
        
        return matches
    
    def _types_are_related(self, type1: str, type2: str) -> bool:
        related_groups = [
            {"reentrancy", "reentrancy-eth", "reentrancy-no-eth", "external-call"},
            {"access-control", "unprotected-function", "tx-origin", "arbitrary-send"},
            {"integer-overflow", "integer-underflow", "overflow", "underflow"},
            {"oracle", "price-manipulation", "price-feed"},
        ]
        
        for group in related_groups:
            if type1 in group and type2 in group:
                return True
            if any(t in type1 for t in group) and any(t in type2 for t in group):
                return True
        
        return False
    
    def _locations_match(self, loc1: str, loc2: str) -> bool:
        # TODO: this is pretty naive, could do something smarter
        loc1_parts = loc1.lower().replace(":", " ").split()
        loc2_parts = loc2.lower().replace(":", " ").split()
        
        # Check for any common parts
        return bool(set(loc1_parts) & set(loc2_parts))


def extract_claims_from_llm_output(llm_output: str) -> list[LLMClaim]:
    """Parse VULNERABILITY/LOCATION/EXPLOITABLE/... blocks from the LLM text."""
    import re

    claims: list[LLMClaim] = []

    # Split into sections if multiple vulnerabilities
    sections = re.split(r'\n(?=VULNERABILITY:|Finding \d+:|##)', llm_output)

    def _extract_field(pattern: str, text: str) -> str:
        m = re.search(pattern + r'[:\s]+([^\n]+(?:\n(?![A-Z_]{3,}:)[^\n]+)*)', text, re.IGNORECASE)
        return m.group(1).strip() if m else ""

    for section in sections:
        claim = LLMClaim(claim_type="vulnerability")

        vuln_match = re.search(r'VULNERABILITY[:\s]+([^\n]+)', section, re.IGNORECASE)
        if vuln_match:
            claim.vulnerability_type = vuln_match.group(1).strip()

        loc_match = re.search(r'LOCATION[:\s]+([^\n]+)', section, re.IGNORECASE)
        if loc_match:
            claim.location = loc_match.group(1).strip()

        func_match = re.search(r'FUNCTION[:\s]+([^\n]+)', section, re.IGNORECASE)
        if func_match:
            claim.function_name = func_match.group(1).strip()

        exploit_match = re.search(r'EXPLOITABLE[:\s]+(yes|true|1)', section, re.IGNORECASE)
        if exploit_match:
            claim.is_exploitable = True

        loss_match = re.search(r'LOSS[_\s]?PERCENTAGE[:\s]+(\d+(?:\.\d+)?)', section, re.IGNORECASE)
        if loss_match:
            claim.loss_percentage = float(loss_match.group(1))

        claim.explanation = _extract_field("EXPLANATION", section)
        claim.description = _extract_field("DESCRIPTION", section)
        claim.exploit_scenario = _extract_field("EXPLOIT_SCENARIO", section)
        claim.technical_impact = _extract_field("TECHNICAL_IMPACT", section)
        claim.fix_recommendation = _extract_field("FIX_RECOMMENDATION", section)

        # fallback so downstream code that reads .explanation still gets content
        if not claim.explanation and claim.description:
            claim.explanation = claim.description

        if claim.vulnerability_type:
            claims.append(claim)

    return claims
