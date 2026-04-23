import json

from agents.llm_client import DetectorLLMClient, extract_json_object


def test_extract_json_object_handles_thinking_prefix():
    payload, meta = extract_json_object(
        "Thinking...\nThis is analysis text.\n{\"is_injection\": true, \"confidence\": 0.95}"
    )

    assert meta["llm_parse_status"] == "ok"
    assert payload == {"is_injection": True, "confidence": 0.95}


def test_groq_provider_reports_missing_api_key(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "")

    client = DetectorLLMClient(default_model="llama-3.3-70b-versatile")

    assert client.provider == "groq"
    assert client.availability_error() == "missing_api_key"


def test_groq_client_uses_chat_completion(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-key")

    class FakeResponse:
        class Choice:
            class Message:
                content = '{"is_injection": true, "confidence": 0.88}'

            message = Message()

        choices = [Choice()]

    captured = {}

    class FakeChatCompletions:
        @staticmethod
        def create(**kwargs):
            captured.update(kwargs)
            return FakeResponse()

    class FakeChat:
        completions = FakeChatCompletions()

    class FakeGroqClient:
        chat = FakeChat()

    client = DetectorLLMClient(default_model="llama-3.3-70b-versatile")
    client._groq_client = FakeGroqClient()
    response = client.complete("system prompt", "user prompt", max_tokens=33)

    assert captured["model"] == "llama-3.3-70b-versatile"
    assert captured["messages"][0]["content"] == "system prompt"
    assert captured["messages"][1]["content"] == "user prompt"
    assert captured["max_tokens"] == 33
    assert response.meta["llm_provider"] == "groq"
    assert response.meta["llm_model"] == "llama-3.3-70b-versatile"
    assert response.content == '{"is_injection": true, "confidence": 0.88}'
