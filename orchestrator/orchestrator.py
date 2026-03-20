import time
from dataclasses import dataclass
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed

from agents.pii_detector import PIIDetectorAgent
from agents.secrets_detector import SecretsDetectorAgent
from agents.abuse_detector import AbuseDetectorAgent
from agents.injection_detector import InjectionDetectorAgent
from agents.unsafe_content_detector import UnsafeContentDetectorAgent


# ── Data Models ────────────────────────────────────────────────────────────────

@dataclass
class AgentResult:
    agent_name: str
    threat_found: bool
    threat_type: str
    severity: str
    summary: str
    matched: list


@dataclass
class FirewallDecision:
    action: str                    # ALLOW / REDACT / FLAG / BLOCK
    reason: str
    severity: str                  # overall severity
    triggered_agents: List[str]    # which agents flagged something
    agent_results: List[AgentResult]
    redacted_text: str             # redacted version (if applicable)
    processing_time_ms: float
    original_text: str


# ── Orchestrator ───────────────────────────────────────────────────────────────

class SemanticFirewallOrchestrator:
    def __init__(self):
        print("[Orchestrator] Initializing all agents...")
        self.agents = {
            "PII Detector":            PIIDetectorAgent(),
            "Secrets Detector":        SecretsDetectorAgent(),
            "Abuse Detector":          AbuseDetectorAgent(),
            "Injection Detector":      InjectionDetectorAgent(),
            "Unsafe Content Detector": UnsafeContentDetectorAgent(),
        }

        # ── Policy configuration ───────────────────────────────────────────────
        # Defines what ACTION to take based on threat_type + severity
        # Priority order: BLOCK > REDACT > FLAG > ALLOW
        self.policy: Dict[str, Dict[str, str]] = {
            "PII": {
                "CRITICAL": "BLOCK",
                "HIGH":     "REDACT",
                "MEDIUM":   "REDACT",
                "LOW":      "FLAG",
                "NONE":     "ALLOW",
            },
            "SECRET": {
                "CRITICAL": "BLOCK",
                "HIGH":     "BLOCK",
                "MEDIUM":   "REDACT",
                "LOW":      "FLAG",
                "NONE":     "ALLOW",
            },
            "ABUSE": {
                "CRITICAL": "BLOCK",
                "HIGH":     "BLOCK",
                "MEDIUM":   "FLAG",
                "LOW":      "FLAG",
                "NONE":     "ALLOW",
            },
            "INJECTION": {
                "CRITICAL": "BLOCK",
                "HIGH":     "BLOCK",
                "MEDIUM":   "BLOCK",
                "LOW":      "FLAG",
                "NONE":     "ALLOW",
            },
            "UNSAFE_CONTENT": {
                "CRITICAL": "BLOCK",
                "HIGH":     "BLOCK",
                "MEDIUM":   "FLAG",
                "LOW":      "FLAG",
                "NONE":     "ALLOW",
            },
        }

        # Action priority (higher index = higher priority)
        self.action_priority = ["ALLOW", "FLAG", "REDACT", "BLOCK"]
        print("[Orchestrator] All agents ready.\n")

    # ── Run a single agent safely ──────────────────────────────────────────────

    def _run_agent(self, name: str, agent, text: str) -> AgentResult:
        try:
            result = agent.run(text)
            return AgentResult(
                agent_name=result.agent_name,
                threat_found=result.threat_found,
                threat_type=result.threat_type,
                severity=result.severity,
                summary=result.summary,
                matched=result.matched,
            )
        except Exception as e:
            print(f"[Orchestrator] Agent '{name}' failed: {e}")
            return AgentResult(
                agent_name=name,
                threat_found=False,
                threat_type="ERROR",
                severity="NONE",
                summary=f"Agent failed with error: {e}",
                matched=[],
            )

    # ── Determine redacted text ────────────────────────────────────────────────

    def _get_redacted_text(self, text: str, agent_results: List[AgentResult]) -> str:
        redacted = text
        for result in agent_results:
            if result.threat_found:
                agent = self.agents.get(result.agent_name)
                if agent and hasattr(agent, "redact"):
                    redacted = agent.redact(redacted)
        return redacted

    # ── Determine overall severity ────────────────────────────────────────────

    def _overall_severity(self, agent_results: List[AgentResult]) -> str:
        severity_order = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        max_severity = "NONE"
        for result in agent_results:
            if result.threat_found:
                if severity_order.index(result.severity) > severity_order.index(max_severity):
                    max_severity = result.severity
        return max_severity

    # ── Apply policy to get final action ──────────────────────────────────────

    def _apply_policy(self, agent_results: List[AgentResult]) -> tuple:
        final_action = "ALLOW"
        reasons = []
        triggered = []

        for result in agent_results:
            if result.threat_found:
                threat_policy = self.policy.get(result.threat_type, {})
                action = threat_policy.get(result.severity, "FLAG")

                # Escalate action if higher priority
                if self.action_priority.index(action) > self.action_priority.index(final_action):
                    final_action = action

                triggered.append(result.agent_name)
                reasons.append(
                    f"{result.agent_name} [{result.severity}]: {result.summary}"
                )

        reason = " | ".join(reasons) if reasons else "All agents passed. Input is clean."
        return final_action, reason, triggered

    # ── Main analyze method ────────────────────────────────────────────────────

    def analyze(self, text: str) -> FirewallDecision:
        start_time = time.time()

        print(f"[Orchestrator] Analyzing input ({len(text)} chars)...")
        print(f"[Orchestrator] Running all 5 agents in parallel...\n")

        agent_results: List[AgentResult] = []

        # Run all agents in parallel using ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(self._run_agent, name, agent, text): name
                for name, agent in self.agents.items()
            }

            for future in as_completed(futures):
                result = future.result()
                agent_results.append(result)
                status = "⚠ THREAT" if result.threat_found else "✓ CLEAN"
                print(f"  [{status}] {result.agent_name}: {result.summary}")

        # Apply policy engine
        final_action, reason, triggered = self._apply_policy(agent_results)
        overall_severity = self._overall_severity(agent_results)

        # Get redacted text if needed
        redacted_text = (
            self._get_redacted_text(text, agent_results)
            if final_action == "REDACT"
            else text
        )

        processing_time = (time.time() - start_time) * 1000

        decision = FirewallDecision(
            action=final_action,
            reason=reason,
            severity=overall_severity,
            triggered_agents=triggered,
            agent_results=agent_results,
            redacted_text=redacted_text,
            processing_time_ms=processing_time,
            original_text=text,
        )

        self._print_decision(decision)
        return decision

    # ── Pretty print decision ──────────────────────────────────────────────────

    def _print_decision(self, decision: FirewallDecision):
        action_icons = {
            "ALLOW":  "✅ ALLOW",
            "FLAG":   "🚩 FLAG",
            "REDACT": "🔒 REDACT",
            "BLOCK":  "🚫 BLOCK",
        }
        severity_icons = {
            "NONE":     "⚪",
            "LOW":      "🟢",
            "MEDIUM":   "🟡",
            "HIGH":     "🟠",
            "CRITICAL": "🔴",
        }

        print(f"\n{'═'*60}")
        print(f"  FIREWALL DECISION: {action_icons.get(decision.action, decision.action)}")
        print(f"  Severity  : {severity_icons.get(decision.severity, '')} {decision.severity}")
        print(f"  Triggered : {', '.join(decision.triggered_agents) if decision.triggered_agents else 'None'}")
        print(f"  Time      : {decision.processing_time_ms:.0f}ms")
        print(f"  Reason    : {decision.reason[:120]}...")
        if decision.action == "REDACT":
            print(f"  Redacted  : {decision.redacted_text[:100]}...")
        print(f"{'═'*60}\n")