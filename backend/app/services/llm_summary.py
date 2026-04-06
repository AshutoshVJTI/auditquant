
import json
import logging
from dataclasses import dataclass, field
from typing import Any

from openai import OpenAI

from app.config import settings
from app.models.schemas import Finding
from app.services.anti_hallucination import LLMClaim

logger = logging.getLogger(__name__)
@dataclass
class SummaryGenerationResult:
    summary: str | None = None
    claims: list[LLMClaim] = field(default_factory=list)
    error: str | None = None
def _truncate_text(value: str, max_chars: int = 320) -> str:
    if len(value) <= max_chars:
        return value
    return value[: max_chars - 3] + "..."
def _build_findings_payload(findings: list[Finding], limit: int = 20) -> list[dict[str, Any]]:
    payload: list[dict[str, Any]] = []
    for f in findings[:limit]:
        payload.append({
            "title": f.title,
            "impact": f.impact,
            "confidence": f.confidence,
            "source": f.source,
            "location": f.location,
            "description": _truncate_text(f.description or ""),
            "vulnerability_type": f.metadata.get("vulnerability_type"),
            "is_reachable": f.metadata.get("is_reachable", False),
            "has_exploit_proof": f.metadata.get("has_exploit_proof", False),
            "cross_validated": f.metadata.get("cross_validated", False),
            "loss_percentage": f.loss_percentage,
        })
    return payload
def _strip_markdown_fences(text: str) -> str:
    t = text.strip()
    if not t.startswith("```"):
        return t
    lines = t.split("\n")
    if not lines:
        return t
    if lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip()
def _claim_from_dict(raw: dict[str, Any]) -> LLMClaim | None:
    vuln_type = (raw.get("vulnerability_type") or "").strip()
    if not vuln_type:
        return None

    loss_percentage = raw.get("loss_percentage")
    try:
        loss_percentage = float(loss_percentage) if loss_percentage is not None else None
    except (TypeError, ValueError):
        loss_percentage = None

    return LLMClaim(
        claim_type="llm_summary_claim",
        vulnerability_type=vuln_type,
        location=(raw.get("location") or None),
        function_name=(raw.get("function_name") or None),
        is_exploitable=bool(raw.get("is_exploitable", False)),
        loss_percentage=loss_percentage,
        explanation=(raw.get("explanation") or ""),
        description=(raw.get("description") or ""),
        exploit_scenario=(raw.get("exploit_scenario") or ""),
        technical_impact=(raw.get("technical_impact") or ""),
        fix_recommendation=(raw.get("fix_recommendation") or ""),
    )
def generate_summary(
    findings: list[Finding],
    defi_category: str | None,
    filename: str,
) -> SummaryGenerationResult:
    if not settings.openai_api_key:
        return SummaryGenerationResult(error="OPENAI_API_KEY not set")

    client = OpenAI(
        api_key=settings.openai_api_key,
        base_url=settings.openai_base_url or None,
    )

    findings_payload = _build_findings_payload(findings)
    user_payload = {
        "filename": filename,
        "defi_category": defi_category or "other",
        "findings": findings_payload,
    }
    payload_json = json.dumps(user_payload, ensure_ascii=True)

    md_system = (
        "You are a smart-contract audit report writer. Output ONLY GitHub-Flavored Markdown "
        "(no JSON, no XML, no preamble or postscript). Use English.\n"
        "Structure the report with these level-2 headings in order:\n"
        "## Overview\n"
        "## Risk highlights\n"
        "## Tooling and evidence\n"
        "## Recommended next steps\n"
        "Rules: Use bullet lists where helpful. Use **bold** for severity and key terms. "
        "Use `backticks` for contract, function, and file names. You may use a GFM table "
        "to compare top risks (columns: Risk, Source tool, Severity). "
        "Do not invent vulnerabilities; only discuss what appears in the findings data. "
        "Stay under 900 words."
    )
    md_user = (
        "Write the executive summary in Markdown for the following analysis.\n\n"
        f"{payload_json}"
    )

    try:
        md_response = client.chat.completions.create(
            model=settings.openai_model,
            temperature=0,
            messages=[
                {"role": "system", "content": md_system},
                {"role": "user", "content": md_user},
            ],
        )
        raw_md = md_response.choices[0].message.content or ""
        summary = _strip_markdown_fences(raw_md) or None
        if summary == "":
            summary = None
    except Exception as exc:
        logger.warning("LLM markdown summary failed: %s", exc)
        return SummaryGenerationResult(error=str(exc))

    claims: list[LLMClaim] = []
    if summary:
        claims_system = (
            "You output strict JSON only. Given audit findings and an executive summary, "
            'produce key "claims": an array of objects for verifier alignment. '
            "Each object: vulnerability_type (short slug, must match a finding type where possible), "
            "location, function_name, is_exploitable (boolean), loss_percentage (number or null), "
            "explanation, description, exploit_scenario, technical_impact, fix_recommendation. "
            "One claim per major risk mentioned in the summary; do not invent types absent from findings JSON."
        )
        claims_user = (
            f"Findings JSON:\n{payload_json}\n\n"
            f"Executive summary (markdown):\n{summary[:6000]}\n"
        )
        try:
            cr = client.chat.completions.create(
                model=settings.openai_model,
                temperature=0,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": claims_system},
                    {"role": "user", "content": claims_user},
                ],
            )
            data = json.loads(cr.choices[0].message.content or "{}")
            claims_raw = data.get("claims", [])
            if not isinstance(claims_raw, list):
                claims_raw = []
            for item in claims_raw:
                if isinstance(item, dict):
                    c = _claim_from_dict(item)
                    if c:
                        claims.append(c)
        except Exception as exc:
            logger.warning("LLM claims extraction failed (summary still returned): %s", exc)

    return SummaryGenerationResult(summary=summary, claims=claims, error=None)
