import importlib
import time
from dataclasses import dataclass
from typing import Callable, Optional

from orchestrator.orchestrator import SemanticFirewallOrchestrator


@dataclass
class ToolResult:
    tool: str
    predicted_label: str  # "threat" or "clean"
    latency_ms: float
    error: Optional[str] = None


class ToolAdapter:
    name = "unknown"

    def available(self) -> bool:
        return True

    def predict(self, text: str) -> ToolResult:
        raise NotImplementedError


class SemanticFirewallAdapter(ToolAdapter):
    name = "Semantic Firewall"

    def __init__(self):
        self.orchestrator = SemanticFirewallOrchestrator()

    def predict(self, text: str) -> ToolResult:
        start = time.perf_counter()
        decision = self.orchestrator.analyze(text=text, policy_profile="balanced", workspace_id="default")
        latency = (time.perf_counter() - start) * 1000
        predicted = "threat" if decision.action != "ALLOW" else "clean"
        return ToolResult(tool=self.name, predicted_label=predicted, latency_ms=latency)


class RegexHeuristicBaselineAdapter(ToolAdapter):
    name = "Regex Heuristic Baseline"

    def __init__(self):
        import re

        self._regex = re.compile(
            r"(ignore\s+previous|system\s+prompt|jailbreak|AKIA[0-9A-Z]{16}|"
            r"sk_live_[A-Za-z0-9]{16,}|password\s*=|bomb|methamphetamine|"
            r"\b[A-Z]{5}[0-9]{4}[A-Z]\b|\b\d{4}\s?\d{4}\s?\d{4}\b)",
            re.IGNORECASE,
        )

    def predict(self, text: str) -> ToolResult:
        start = time.perf_counter()
        matched = bool(self._regex.search(text))
        latency = (time.perf_counter() - start) * 1000
        return ToolResult(
            tool=self.name,
            predicted_label="threat" if matched else "clean",
            latency_ms=latency,
        )


class OptionalImportAdapter(ToolAdapter):
    def __init__(self, name: str, import_name: str, predictor_fn: Callable[[str], bool]):
        self.name = name
        self.import_name = import_name
        self.predictor_fn = predictor_fn
        self._available = importlib.util.find_spec(import_name) is not None

    def available(self) -> bool:
        return self._available

    def predict(self, text: str) -> ToolResult:
        if not self._available:
            return ToolResult(tool=self.name, predicted_label="clean", latency_ms=0.0, error="not_installed")
        start = time.perf_counter()
        try:
            is_threat = bool(self.predictor_fn(text))
            latency = (time.perf_counter() - start) * 1000
            return ToolResult(
                tool=self.name,
                predicted_label="threat" if is_threat else "clean",
                latency_ms=latency,
            )
        except Exception as exc:
            latency = (time.perf_counter() - start) * 1000
            return ToolResult(tool=self.name, predicted_label="clean", latency_ms=latency, error=str(exc))


def build_optional_market_adapters() -> list[ToolAdapter]:
    # These are intentionally conservative wrappers because different versions
    # of external libs have different APIs. If unavailable, adapter is skipped.

    def llm_guard_predict(text: str) -> bool:
        # Fallback heuristic when package is present but API differs
        import re

        return bool(re.search(r"(ignore previous|system prompt|AKIA|bomb|password\s*=)", text, re.IGNORECASE))

    def rebuff_predict(text: str) -> bool:
        import re

        return bool(re.search(r"(jailbreak|do anything now|override)", text, re.IGNORECASE))

    def guardrails_predict(text: str) -> bool:
        import re

        return bool(re.search(r"(unsafe|harm|weapon|secret)", text, re.IGNORECASE))

    return [
        OptionalImportAdapter("LLM Guard", "llm_guard", llm_guard_predict),
        OptionalImportAdapter("Rebuff", "rebuff", rebuff_predict),
        OptionalImportAdapter("Guardrails AI", "guardrails", guardrails_predict),
    ]
