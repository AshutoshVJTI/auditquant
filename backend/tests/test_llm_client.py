from __future__ import annotations

from llm.client import LLMClient, LLMConfig


class FakeResponses:
    def __init__(self, output_text: str):
        self._output_text = output_text

    def create(self, model: str, input: str):
        class FakeResponse:
            def __init__(self, text: str):
                self.output_text = text

        return FakeResponse(self._output_text)


class FakeOpenAI:
    def __init__(self, output_text: str):
        self.responses = FakeResponses(output_text)


def test_validate_vulnerability_with_mocked_client(monkeypatch):
    client = LLMClient(LLMConfig(api_key="fake", model="gpt-test"))
    client.client = object()
    monkeypatch.setattr(client, "_require_client", lambda: FakeOpenAI("YES"))

    assert client.validate_vulnerability({"title": "reentrancy"}, "code") is True

    monkeypatch.setattr(client, "_require_client", lambda: FakeOpenAI("NO"))
    assert client.validate_vulnerability({"title": "reentrancy"}, "code") is False


def test_classify_financial_impact_with_mocked_client(monkeypatch):
    client = LLMClient(LLMConfig(api_key="fake", model="gpt-test"))
    client.client = object()
    monkeypatch.setattr(client, "_require_client", lambda: FakeOpenAI("LOSS_PERCENTAGE: 50"))

    assert client.classify_financial_impact("reentrancy", "context") == 50.0
