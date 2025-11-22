from __future__ import annotations

import asyncio
from dataclasses import dataclass

from openai import OpenAI


@dataclass
class LLMConfig:
    api_key: str | None
    model: str


class LLMClient:
    def __init__(self, config: LLMConfig):
        self.config = config
        self.client = OpenAI(api_key=config.api_key) if config.api_key else None

    def _require_client(self) -> OpenAI:
        if not self.client:
            raise RuntimeError("OpenAI API key not configured")
        return self.client

    def validate_vulnerability(self, finding: dict, code_context: str) -> bool:
        if not self.client:
            return True
        prompt = (
            "You are a lead smart contract auditor. "
            "Determine if the following finding is a real vulnerability or a false positive. "
            "Reply with ONLY 'YES' or 'NO'.\n\n"
            f"Finding: {finding}\n\n"
            f"Code context:\n{code_context}\n"
        )
        response = self._require_client().responses.create(
            model=self.config.model,
            input=prompt,
        )
        text = (response.output_text or "").strip().upper()
        return text.startswith("YES")

    def classify_financial_impact(self, vuln_type: str, contract_context: str) -> float | None:
        if not self.client:
            return None
        prompt = (
            "Act as a lead auditor. "
            "Vulnerability: "
            f"{vuln_type}. "
            "Context: "
            f"{contract_context}. "
            "Task: Estimate the percentage of funds at risk (0-100%). "
            "Output format: LOSS_PERCENTAGE: <number>."
        )
        response = self._require_client().responses.create(
            model=self.config.model,
            input=prompt,
        )
        text = (response.output_text or "").strip()
        for token in text.replace("%", "").split():
            if token.isdigit():
                return float(token)
        return None

    def generate_summary(self, findings: list[dict]) -> str:
        if not self.client:
            return "Summary unavailable (OpenAI API key not configured)."
        prompt = (
            "Summarize the following audit findings in 5-7 sentences. "
            "Include overall risk posture and the most critical issues.\n\n"
            f"Findings: {findings}"
        )
        response = self._require_client().responses.create(
            model=self.config.model,
            input=prompt,
        )
        return (response.output_text or "").strip()

    async def validate_vulnerability_async(self, finding: dict, code_context: str) -> bool:
        return await asyncio.to_thread(self.validate_vulnerability, finding, code_context)

    async def classify_financial_impact_async(
        self, vuln_type: str, contract_context: str
    ) -> float | None:
        return await asyncio.to_thread(self.classify_financial_impact, vuln_type, contract_context)

    async def generate_summary_async(self, findings: list[dict]) -> str:
        return await asyncio.to_thread(self.generate_summary, findings)
