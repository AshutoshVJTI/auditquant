"""
Anti-Hallucination Verification Layer

Validates LLM outputs against tool evidence to prevent hallucinations.
Implements the verification gate described in the research proposal:

1. Evidence consistency check (line numbers, traces, functions)
2. Cross-tool validation (dynamic proof required for exploit claims)
3. Verifier gate that rejects unsupported summaries
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


class VerificationStatus(str, Enum):
    VERIFIED = "verified"  # Claim is supported by evidence
    UNVERIFIED = "unverified"  # Claim lacks sufficient evidence
    REJECTED = "rejected"  # Claim contradicts evidence
    NEEDS_REVIEW = "needs_review"  # Requires human review


@dataclass
class VerificationResult:
    """Result of anti-hallucination verification."""
    status: VerificationStatus
    confidence: float
    evidence_summary: str
    issues: list[str] = field(default_factory=list)
    supporting_tools: list[str] = field(default_factory=list)
    has_dynamic_proof: bool = False


@dataclass
class LLMClaim:
    """Structured claim from LLM output to verify."""
    claim_type: str  # "vulnerability", "exploitable", "loss_percentage", "remediation"
    vulnerability_type: str | None = None
    location: str | None = None
    function_name: str | None = None
    is_exploitable: bool = False
    loss_percentage: float | None = None
    explanation: str = ""


class AntiHallucinationVerifier:
    """
    Verifies LLM claims against tool evidence.
    
    Rules:
    1. If LLM claims "exploitable" but no dynamic tool produced a trace → REJECT
    2. If LLM claims a vulnerability type not found by any tool → REJECT
    3. If LLM loss % differs significantly from category baseline → FLAG
    4. If claim location doesn't match any tool finding location → FLAG
    """
    
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
        """
        Verify a single LLM claim against tool findings.
        """
        issues: list[str] = []
        supporting_tools: list[str] = []
        has_dynamic_proof = False
        
        # Find matching findings
        matching_findings = self._find_matching_findings(claim, findings)
        
        if not matching_findings:
            return VerificationResult(
                status=VerificationStatus.REJECTED,
                confidence=0.0,
                evidence_summary="No tool found this vulnerability type",
                issues=["LLM claimed vulnerability not detected by any tool"],
            )
        
        # Check tool agreement
        tools_reporting = set(f.tool for f in matching_findings)
        supporting_tools = [t.value for t in tools_reporting]
        
        if len(tools_reporting) < self.min_tool_agreement:
            issues.append(f"Only {len(tools_reporting)} tool(s) reported this; minimum {self.min_tool_agreement} required")
        
        # Check for dynamic proof if claim is about exploitability
        dynamic_findings = [
            f for f in matching_findings
            if f.analysis_type in (AnalysisType.SYMBOLIC, AnalysisType.FUZZING)
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
        
        # Check location consistency
        if claim.location:
            location_match = any(
                f.location and self._locations_match(claim.location, str(f.location))
                for f in matching_findings
            )
            if not location_match:
                issues.append("Claimed location does not match any tool finding")
        
        # Check loss percentage if provided
        if claim.loss_percentage is not None and category_expected_loss is not None:
            variance = abs(claim.loss_percentage - category_expected_loss)
            if variance > self.loss_variance_threshold:
                issues.append(
                    f"Loss % ({claim.loss_percentage}%) differs significantly from "
                    f"category baseline ({category_expected_loss}%)"
                )
        
        # Calculate confidence
        base_confidence = 0.5
        
        # Boost for multiple tools
        base_confidence += min(0.2, len(tools_reporting) * 0.1)
        
        # Boost for dynamic proof
        if has_dynamic_proof:
            base_confidence += 0.25
        
        # Reduce for issues
        base_confidence -= len(issues) * 0.1
        
        confidence = max(0.0, min(1.0, base_confidence))
        
        # Determine status
        if not issues:
            status = VerificationStatus.VERIFIED
        elif len(issues) <= 1 and confidence >= 0.5:
            status = VerificationStatus.NEEDS_REVIEW
        else:
            status = VerificationStatus.UNVERIFIED
        
        # Build evidence summary
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
        """
        Verify all claims in an LLM summary.
        
        Returns a verification report with:
        - Overall status
        - Per-claim verification results
        - Hallucination rate
        """
        results: list[VerificationResult] = []
        
        for claim in summary_claims:
            expected_loss = None
            if category_expected_losses and claim.vulnerability_type:
                expected_loss = category_expected_losses.get(claim.vulnerability_type)
            
            result = self.verify_claim(claim, findings, expected_loss)
            results.append(result)
        
        # Calculate hallucination rate
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
        """Find tool findings that match the LLM claim."""
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
        """Check if two vulnerability types are semantically related."""
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
        """Check if two location strings refer to the same code region."""
        # Simple matching - could be enhanced
        loc1_parts = loc1.lower().replace(":", " ").split()
        loc2_parts = loc2.lower().replace(":", " ").split()
        
        # Check for any common parts
        return bool(set(loc1_parts) & set(loc2_parts))


def extract_claims_from_llm_output(llm_output: str) -> list[LLMClaim]:
    """
    Parse structured claims from LLM output.
    
    Expected format (flexible):
    - VULNERABILITY: <type>
    - LOCATION: <file:line or function>
    - EXPLOITABLE: <yes/no>
    - LOSS_PERCENTAGE: <0-100>
    """
    import re
    
    claims: list[LLMClaim] = []
    
    # Split into sections if multiple vulnerabilities
    sections = re.split(r'\n(?=VULNERABILITY:|Finding \d+:|##)', llm_output)
    
    for section in sections:
        claim = LLMClaim(claim_type="vulnerability")
        
        # Extract vulnerability type
        vuln_match = re.search(r'VULNERABILITY[:\s]+([^\n]+)', section, re.IGNORECASE)
        if vuln_match:
            claim.vulnerability_type = vuln_match.group(1).strip()
        
        # Extract location
        loc_match = re.search(r'LOCATION[:\s]+([^\n]+)', section, re.IGNORECASE)
        if loc_match:
            claim.location = loc_match.group(1).strip()
        
        # Extract function name
        func_match = re.search(r'FUNCTION[:\s]+([^\n]+)', section, re.IGNORECASE)
        if func_match:
            claim.function_name = func_match.group(1).strip()
        
        # Extract exploitability
        exploit_match = re.search(r'EXPLOITABLE[:\s]+(yes|true|1)', section, re.IGNORECASE)
        if exploit_match:
            claim.is_exploitable = True
        
        # Extract loss percentage
        loss_match = re.search(r'LOSS[_\s]?PERCENTAGE[:\s]+(\d+(?:\.\d+)?)', section, re.IGNORECASE)
        if loss_match:
            claim.loss_percentage = float(loss_match.group(1))
        
        # Extract explanation
        expl_match = re.search(r'EXPLANATION[:\s]+([^\n]+(?:\n(?![A-Z_]+:)[^\n]+)*)', section, re.IGNORECASE)
        if expl_match:
            claim.explanation = expl_match.group(1).strip()
        
        if claim.vulnerability_type:
            claims.append(claim)
    
    return claims
