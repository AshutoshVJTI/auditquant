import asyncio
from dataclasses import dataclass

from openai import OpenAI


@dataclass
class LLMConfig:
    api_key: str | None
    model: str
    base_url: str | None = None


class LLMClient:

    def __init__(self, config: LLMConfig):
        self.config = config
        if config.api_key:
            kwargs: dict = {"api_key": config.api_key}
            if config.base_url:
                kwargs["base_url"] = config.base_url
            self.client = OpenAI(**kwargs)
        else:
            self.client = None

    def _require_client(self) -> OpenAI:
        if not self.client:
            raise RuntimeError("OpenAI API key not configured")
        return self.client

    def generate_summary(self, findings: list[dict]) -> str:
        prompt = (
            "Summarize the following audit findings in 5-7 sentences. "
            "Include overall risk posture and the most critical issues.\n\n"
            f"Findings: {findings}"
        )
        response = self._require_client().chat.completions.create(
            model=self.config.model,
            messages=[
                {"role": "system", "content": "You are a senior smart contract security auditor writing concise executive summaries."},
                {"role": "user", "content": prompt},
            ],
        )
        return (response.choices[0].message.content or "").strip()

    _LLM_CALL_TIMEOUT = 60.0

    async def generate_summary_async(self, findings: list[dict]) -> str:
        return await asyncio.wait_for(
            asyncio.to_thread(self.generate_summary, findings),
            timeout=self._LLM_CALL_TIMEOUT,
        )
