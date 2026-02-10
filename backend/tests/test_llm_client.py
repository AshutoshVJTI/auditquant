from __future__ import annotations

from unittest.mock import MagicMock

from llm.client import LLMClient, LLMConfig


def _make_fake_client(output_text: str) -> MagicMock:
    """Create a mock OpenAI client that returns *output_text* for completions."""
    choice = MagicMock()
    choice.message.content = output_text

    response = MagicMock()
    response.choices = [choice]

    client = MagicMock()
    client.chat.completions.create.return_value = response
    return client


def test_generate_summary(monkeypatch):
    llm = LLMClient(LLMConfig(api_key="fake", model="gpt-test"))
    llm.client = _make_fake_client("This contract has critical reentrancy issues.")

    result = llm.generate_summary([{"title": "reentrancy"}])
    assert "reentrancy" in result.lower()


def test_generate_summary_empty_findings(monkeypatch):
    llm = LLMClient(LLMConfig(api_key="fake", model="gpt-test"))
    llm.client = _make_fake_client("No significant vulnerabilities found.")

    result = llm.generate_summary([])
    assert isinstance(result, str)
    assert len(result) > 0
