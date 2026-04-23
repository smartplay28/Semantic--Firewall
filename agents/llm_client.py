import json
import os
from dataclasses import dataclass
from typing import Any

from groq import Groq


@dataclass
class LLMResponse:
    content: str
    meta: dict[str, Any]


class DetectorLLMClient:
    """Small provider wrapper for semantic detector LLM calls."""

    def __init__(self, default_model: str):
        self.groq_model = os.getenv("SEMANTIC_FIREWALL_GROQ_MODEL", default_model).strip() or default_model
        self.provider = "groq"
        groq_api_key = os.getenv("GROQ_API_KEY", "").strip()
        self._groq_client = Groq(api_key=groq_api_key) if groq_api_key else None

    @property
    def model_name(self) -> str:
        return self.groq_model

    def availability_error(self) -> str | None:
        return None if self._groq_client is not None else "missing_api_key"

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 1000,
    ) -> LLMResponse:
        return self._complete_groq(system_prompt, user_prompt, max_tokens)

    def _complete_groq(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int,
    ) -> LLMResponse:
        if self._groq_client is None:
            raise RuntimeError("GROQ_API_KEY is not configured")

        response = self._groq_client.chat.completions.create(
            model=self.groq_model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.0,
            max_tokens=max_tokens,
        )
        return LLMResponse(
            content=response.choices[0].message.content.strip(),
            meta={"llm_provider": "groq", "llm_model": self.groq_model},
        )


def extract_json_object(raw: str) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    cleaned = raw.strip()
    if cleaned.startswith("```json"):
        cleaned = cleaned.removeprefix("```json").strip()
    elif cleaned.startswith("```"):
        cleaned = cleaned.removeprefix("```").strip()
    if cleaned.endswith("```"):
        cleaned = cleaned[:-3].strip()

    try:
        payload = json.loads(cleaned)
    except json.JSONDecodeError as direct_error:
        payload = _extract_balanced_object(cleaned)
        if payload is None:
            return None, {
                "llm_parse_status": "invalid_json",
                "llm_parse_error": str(direct_error),
                "llm_raw_preview": raw[:120],
            }
    else:
        if not isinstance(payload, dict):
            return None, {
                "llm_parse_status": "invalid_shape",
                "llm_parse_error": f"Expected top-level object, got {type(payload).__name__}",
            }

    return payload, {"llm_parse_status": "ok"}


def _extract_balanced_object(text: str) -> dict[str, Any] | None:
    start = text.find("{")
    if start < 0:
        return None

    depth = 0
    in_string = False
    escape = False
    for index in range(start, len(text)):
        char = text[index]
        if in_string:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                try:
                    payload = json.loads(text[start : index + 1])
                except json.JSONDecodeError:
                    return None
                return payload if isinstance(payload, dict) else None

    return None
