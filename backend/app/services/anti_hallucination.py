from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from app.services.normalized_finding import (
    AnalysisType,
    NormalizedFinding,
    ToolSource,
)
from app.services.swc_knowledge import get_swc_knowledge_base

RELATED_VULN_GROUPS: tuple[frozenset[str], ...] = (
    frozenset({"reentrancy", "reentrancy-eth", "reentrancy-no-eth", "external-call"}),
    frozenset({"access-control", "unprotected-function", "tx-origin", "arbitrary-send"}),
    frozenset({"integer-overflow", "integer-underflow", "overflow", "underflow", "arithmetic"}),
    frozenset({"oracle", "price-manipulation", "price-feed"}),
    frozenset(
        {
            "unchecked-return",
            "unchecked-lowlevel",
            "low-level-calls",
            "unchecked-low-level-calls",
            "unchecked-call",
            "unchecked-send",
        }
    ),
)
def vulnerability_types_compatible(claim_vuln_type: str, finding_vuln_type: str) -> bool:
    """
    True if a CodeBERT / LLM claim type aligns with a tool finding type
    (same rules as AntiHallucinationVerifier.verify_claim).
    """
    if not claim_vuln_type or not finding_vuln_type:
        return False
    claim_type = claim_vuln_type.lower().replace("_", "-")
    ftype = finding_vuln_type.lower().replace("_", "-")
    if claim_type in ftype or ftype in claim_type:
        return True
    for grp in RELATED_VULN_GROUPS:
        if any(t in claim_type for t in grp) and any(t in ftype for t in grp):
            return True
    return False
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
        has_dynamic_proof = False

        swc_kb = get_swc_knowledge_base()

        # first check - does any tool actually report this vuln type at all?
        if not claim.vulnerability_type:
            return VerificationResult(
                status=VerificationStatus.REJECTED,
                confidence=0.0,
                evidence_summary="No tool found this vulnerability type",
                issues=["LLM claimed vulnerability not detected by any tool"],
            )

        claim_type = claim.vulnerability_type.lower().replace("_", "-")
        matching_findings = []
        for f in findings:
            ftype = f.vulnerability_type.lower().replace("_", "-")
            if vulnerability_types_compatible(claim_type, ftype):
                matching_findings.append(f)

        if not matching_findings:
            return VerificationResult(
                status=VerificationStatus.REJECTED,
                confidence=0.0,
                evidence_summary="No tool found this vulnerability type",
                issues=["LLM claimed vulnerability not detected by any tool"],
            )

        if swc_kb.is_loaded:
            if not swc_kb.is_known_vulnerability(claim.vulnerability_type):
                issues.append(
                    f"Vulnerability type '{claim.vulnerability_type}' not recognised in SWC registry"
                )

            if claim.exploit_scenario:
                expected_kw = swc_kb.get_known_exploit_keywords(claim.vulnerability_type)
                if expected_kw:
                    hits = sum(1 for kw in expected_kw if kw in claim.exploit_scenario.lower())
                    if hits == 0:
                        issues.append(
                            "Exploit scenario does not reference any expected SWC keywords"
                        )

            if claim.fix_recommendation:
                swc_entry = swc_kb.get_by_vuln_type(claim.vulnerability_type)
                if swc_entry and swc_entry.get("remediation"):
                    rem_lower = swc_entry["remediation"].lower()
                    fix_lower = claim.fix_recommendation.lower()
                    # rough overlap check - strip stopwords and see if >=2 words match
                    stopwords = {"the", "a", "to", "and", "of", "is", "in", "for", "with", "be", "that"}
                    rem_words = set(rem_lower.split()) - stopwords
                    fix_words = set(fix_lower.split()) - stopwords
                    if len(rem_words & fix_words) < 2:
                        issues.append(
                            "Fix recommendation does not align with SWC remediation guidance"
                        )

        tools_reporting = {f.tool for f in matching_findings}
        supporting_tools = [t.value for t in tools_reporting]

        if len(tools_reporting) < self.min_tool_agreement:
            issues.append(f"Only {len(tools_reporting)} tool(s) reported this; minimum {self.min_tool_agreement} required")

        dynamic_findings = [
            f for f in matching_findings
            if f.analysis_type in (AnalysisType.SYMBOLIC, AnalysisType.BYTECODE)
        ]
        if dynamic_findings:
            has_dynamic_proof = any(f.has_exploit_proof for f in dynamic_findings)

        if claim.is_exploitable and self.require_dynamic_proof and not has_dynamic_proof:
            return VerificationResult(
                status=VerificationStatus.REJECTED,
                confidence=0.0,
                evidence_summary="Exploitability claim requires dynamic proof",
                issues=["LLM claimed exploitable but no dynamic tool provided exploit trace"],
                supporting_tools=supporting_tools,
                has_dynamic_proof=False,
            )

        if claim.location:
            loc_parts = claim.location.lower().replace(":", " ").split()
            location_match = any(
                f.location and bool(set(loc_parts) & set(str(f.location).lower().replace(":", " ").split()))
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

        # build confidence score - starts at 0.5, adjusts based on evidence
        conf = 0.5
        conf += min(0.2, len(tools_reporting) * 0.1)
        if has_dynamic_proof:
            conf += 0.25
        if swc_kb.is_loaded and swc_kb.is_known_vulnerability(claim.vulnerability_type):
            conf += 0.05
        conf -= len(issues) * 0.1
        conf = max(0.0, min(1.0, conf))

        if not issues:
            status = VerificationStatus.VERIFIED
        elif len(issues) <= 1 and conf >= 0.5:
            status = VerificationStatus.NEEDS_REVIEW
        else:
            status = VerificationStatus.UNVERIFIED

        evidence_parts = [f"Found by {len(tools_reporting)} tool(s): {', '.join(supporting_tools)}"]
        if has_dynamic_proof:
            evidence_parts.append("Has dynamic exploit proof")

        return VerificationResult(
            status=status,
            confidence=conf,
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
        results: list[VerificationResult] = []

        for claim in summary_claims:
            expected_loss = None
            if category_expected_losses and claim.vulnerability_type:
                expected_loss = category_expected_losses.get(claim.vulnerability_type)
            results.append(self.verify_claim(claim, findings, expected_loss))

        rejected = sum(1 for r in results if r.status == VerificationStatus.REJECTED)
        unverified = sum(1 for r in results if r.status == VerificationStatus.UNVERIFIED)

        hallucination_rate = (rejected / len(results)) if results else 0.0
        unverified_rate = (unverified / len(results)) if results else 0.0

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
            "rejected_count": rejected,
            "unverified_count": unverified,
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
# pulls structured VULNERABILITY blocks out of the LLM response text
def extract_claims_from_llm_output(llm_output: str) -> list[LLMClaim]:
    import re

    claims: list[LLMClaim] = []
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

        if re.search(r'EXPLOITABLE[:\s]+(yes|true|1)', section, re.IGNORECASE):
            claim.is_exploitable = True

        loss_match = re.search(r'LOSS[_\s]?PERCENTAGE[:\s]+(\d+(?:\.\d+)?)', section, re.IGNORECASE)
        if loss_match:
            claim.loss_percentage = float(loss_match.group(1))

        claim.explanation = _extract_field("EXPLANATION", section)
        claim.description = _extract_field("DESCRIPTION", section)
        claim.exploit_scenario = _extract_field("EXPLOIT_SCENARIO", section)
        claim.technical_impact = _extract_field("TECHNICAL_IMPACT", section)
        claim.fix_recommendation = _extract_field("FIX_RECOMMENDATION", section)

        if not claim.explanation and claim.description:
            claim.explanation = claim.description

        if claim.vulnerability_type:
            claims.append(claim)

    return claims
