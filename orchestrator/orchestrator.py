import hashlib
import os
import re
import threading
import time
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from agents.abuse_detector import AbuseDetectorAgent
from agents.custom_rules_detector import CustomRulesDetectorAgent
from agents.injection_detector import InjectionDetectorAgent
from agents.pii_detector import PIIDetectorAgent
from agents.secrets_detector import SecretsDetectorAgent
from agents.threat_intel_detector import ThreatIntelDetectorAgent
from agents.unsafe_content_detector import UnsafeContentDetectorAgent
from orchestrator.audit_logger import AuditLogger
from orchestrator.policy_store import PolicyStore
from orchestrator.session_store import SessionStore
from orchestrator.risk_scorer import RiskScorer
from orchestrator.explainability import ExplainabilityGenerator, ExplainabilityReport
from orchestrator.alerting import AlertManager
from orchestrator.compliance import ComplianceProfileManager
from orchestrator.session_patterns import MultiTurnAttackDetector, EnhancedSessionStore


@dataclass
class AgentResult:
    agent_name: str
    threat_found: bool
    threat_type: str
    severity: str
    summary: str
    matched: list
    agent_available: bool = True
    fail_closed: bool = False


@dataclass
class FirewallDecision:
    action: str
    reason: str
    severity: str
    triggered_agents: List[str]
    agent_results: List[AgentResult]
    redacted_text: str
    processing_time_ms: float
    original_text: str
    scan_target: str = "input"
    from_cache: bool = False
    degraded: bool = False
    unavailable_agents: List[str] = field(default_factory=list)
    policy_profile: str = "balanced"
    risk_score: float = 0.0
    risk_level: str = "NONE"
    explanation: Optional[ExplainabilityReport] = None
    detected_patterns: List[dict] = field(default_factory=list)


@dataclass
class InteractionDecision:
    prompt_decision: FirewallDecision
    output_decision: FirewallDecision
    combined_action: str
    combined_severity: str
    combined_reason: str
    triggered_agents: List[str]
    interaction_alerts: List[dict] = field(default_factory=list)
    drift_detected: bool = False
    contradiction_detected: bool = False
    session_risk_score: float = 0.0


class SemanticFirewallOrchestrator:
    def __init__(self, db_path: str = "audit.db"):
        print("[Orchestrator] Initializing all agents...")
        self.agents = {
            "PII Detector": PIIDetectorAgent(),
            "Secrets Detector": SecretsDetectorAgent(),
            "Abuse Detector": AbuseDetectorAgent(),
            "Injection Detector": InjectionDetectorAgent(),
            "Unsafe Content Detector": UnsafeContentDetectorAgent(),
            "Threat Intel Detector": ThreatIntelDetectorAgent(),
            "Custom Rules Detector": CustomRulesDetectorAgent(),
        }
        self.fail_closed_agents = {
            "Injection Detector",
            "Unsafe Content Detector",
        }
        self.llm_agents = {
            "Injection Detector",
            "Unsafe Content Detector",
        }

        self.policy: Dict[str, Dict[str, str]] = {
            "PII": {
                "CRITICAL": "BLOCK",
                "HIGH": "REDACT",
                "MEDIUM": "REDACT",
                "LOW": "FLAG",
                "NONE": "ALLOW",
            },
            "SECRET": {
                "CRITICAL": "BLOCK",
                "HIGH": "BLOCK",
                "MEDIUM": "REDACT",
                "LOW": "FLAG",
                "NONE": "ALLOW",
            },
            "ABUSE": {
                "CRITICAL": "BLOCK",
                "HIGH": "BLOCK",
                "MEDIUM": "FLAG",
                "LOW": "FLAG",
                "NONE": "ALLOW",
            },
            "INJECTION": {
                "CRITICAL": "BLOCK",
                "HIGH": "BLOCK",
                "MEDIUM": "BLOCK",
                "LOW": "FLAG",
                "NONE": "ALLOW",
            },
            "UNSAFE_CONTENT": {
                "CRITICAL": "BLOCK",
                "HIGH": "BLOCK",
                "MEDIUM": "FLAG",
                "LOW": "FLAG",
                "NONE": "ALLOW",
            },
            "SYSTEM_UNAVAILABLE": {
                "CRITICAL": "BLOCK",
                "HIGH": "FLAG",
                "MEDIUM": "FLAG",
                "LOW": "FLAG",
                "NONE": "ALLOW",
            },
            "CUSTOM_RULE": {
                "CRITICAL": "BLOCK",
                "HIGH": "BLOCK",
                "MEDIUM": "REDACT",
                "LOW": "FLAG",
                "NONE": "ALLOW",
            },
            "THREAT_INTEL": {
                "CRITICAL": "BLOCK",
                "HIGH": "BLOCK",
                "MEDIUM": "FLAG",
                "LOW": "FLAG",
                "NONE": "ALLOW",
            },
        }
        self.action_priority = ["ALLOW", "FLAG", "REDACT", "BLOCK"]
        self.session_store = SessionStore()
        self.audit_logger = AuditLogger(db_path=db_path)
        self.policy_store = PolicyStore()
        self._cache: Dict[str, FirewallDecision] = {}
        self._cache_max_size = 500
        self._cache_lock = threading.Lock()
        self.llm_gate_enabled = os.getenv("SEMANTIC_FIREWALL_LLM_GATE_ENABLED", "1") != "0"
        self.agent_timeouts = {
            "default": float(os.getenv("SEMANTIC_FIREWALL_AGENT_TIMEOUT_DEFAULT_SEC", "8.0")),
            "PII Detector": float(os.getenv("SEMANTIC_FIREWALL_AGENT_TIMEOUT_PII_SEC", "6.0")),
            "Secrets Detector": float(os.getenv("SEMANTIC_FIREWALL_AGENT_TIMEOUT_SECRETS_SEC", "6.0")),
            "Abuse Detector": float(os.getenv("SEMANTIC_FIREWALL_AGENT_TIMEOUT_ABUSE_SEC", "6.0")),
            "Threat Intel Detector": float(os.getenv("SEMANTIC_FIREWALL_AGENT_TIMEOUT_THREAT_INTEL_SEC", "6.0")),
            "Custom Rules Detector": float(os.getenv("SEMANTIC_FIREWALL_AGENT_TIMEOUT_CUSTOM_RULES_SEC", "6.0")),
            "Injection Detector": float(os.getenv("SEMANTIC_FIREWALL_AGENT_TIMEOUT_INJECTION_SEC", "8.0")),
            "Unsafe Content Detector": float(os.getenv("SEMANTIC_FIREWALL_AGENT_TIMEOUT_UNSAFE_CONTENT_SEC", "8.0")),
        }

        # Initialize production feature modules
        print("[Orchestrator] Initializing production modules...")
        self.risk_scorer = RiskScorer()
        self.explainability_generator = ExplainabilityGenerator()
        self.alert_manager = AlertManager.from_env()
        self.compliance_manager = ComplianceProfileManager()
        self.multi_turn_detector = MultiTurnAttackDetector()
        self.enhanced_session_store = EnhancedSessionStore()
        print("[Orchestrator] All production modules ready.")

        print("[Orchestrator] All agents ready.\n")

    def _agent_timeout(self, name: str) -> float:
        return max(0.05, float(self.agent_timeouts.get(name, self.agent_timeouts["default"])))

    def _severity_rank(self, severity: str) -> int:
        severity_order = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        try:
            return severity_order.index(severity)
        except ValueError:
            return 0

    def _action_rank(self, action: str) -> int:
        try:
            return self.action_priority.index(action)
        except ValueError:
            return 0

    def _cache_key(
        self,
        text: str,
        scan_target: str = "input",
        policy_profile: str = "balanced",
        workspace_id: str = "default",
    ) -> str:
        return hashlib.md5(f"{scan_target}:{policy_profile}:{workspace_id}:{text.strip()}".encode()).hexdigest()

    def _get_from_cache(
        self,
        text: str,
        scan_target: str = "input",
        policy_profile: str = "balanced",
        workspace_id: str = "default",
    ) -> Optional[FirewallDecision]:
        with self._cache_lock:
            cached = self._cache.get(self._cache_key(text, scan_target, policy_profile, workspace_id))
        if not cached:
            return None

        cached_copy = deepcopy(cached)
        cached_copy.from_cache = True
        cached_copy.processing_time_ms = 0.0
        return cached_copy

    def _save_to_cache(
        self,
        text: str,
        decision: FirewallDecision,
        scan_target: str = "input",
        policy_profile: str = "balanced",
        workspace_id: str = "default",
    ):
        with self._cache_lock:
            if len(self._cache) >= self._cache_max_size:
                oldest = next(iter(self._cache))
                del self._cache[oldest]
            self._cache[self._cache_key(text, scan_target, policy_profile, workspace_id)] = decision

    def _run_agent(
        self,
        name: str,
        agent,
        text: str,
        scan_target: str = "input",
        workspace_id: str = "default",
    ) -> AgentResult:
        try:
            timeout_seconds = self._agent_timeout(name)
            executor = ThreadPoolExecutor(max_workers=1)
            try:
                future = executor.submit(self._invoke_agent, name, agent, text, scan_target, workspace_id)
                result = future.result(timeout=timeout_seconds)
            finally:
                executor.shutdown(wait=False, cancel_futures=True)
            return AgentResult(
                agent_name=result.agent_name,
                threat_found=result.threat_found,
                threat_type=result.threat_type,
                severity=result.severity,
                summary=result.summary,
                matched=result.matched,
                agent_available=True,
                fail_closed=name in self.fail_closed_agents,
            )
        except FuturesTimeoutError:
            print(f"[Orchestrator] Agent '{name}' timed out after {self._agent_timeout(name):.2f}s")
            fail_closed = name in self.fail_closed_agents
            return AgentResult(
                agent_name=name,
                threat_found=fail_closed,
                threat_type="SYSTEM_UNAVAILABLE",
                severity="HIGH" if fail_closed else "LOW",
                summary=(
                    f"Detector unavailable: {name} timed out."
                    + (" Fail-closed policy applied." if fail_closed else " Review recommended.")
                ),
                matched=[],
                agent_available=False,
                fail_closed=fail_closed,
            )
        except Exception as exc:
            print(f"[Orchestrator] Agent '{name}' failed: {exc}")
            fail_closed = name in self.fail_closed_agents
            return AgentResult(
                agent_name=name,
                threat_found=fail_closed,
                threat_type="SYSTEM_UNAVAILABLE",
                severity="HIGH" if fail_closed else "LOW",
                summary=(
                    f"Detector unavailable: {name} failed."
                    + (" Fail-closed policy applied." if fail_closed else " Review recommended.")
                ),
                matched=[],
                agent_available=False,
                fail_closed=fail_closed,
            )

    def _invoke_agent(self, name: str, agent, text: str, scan_target: str, workspace_id: str):
        if name == "Custom Rules Detector":
            return agent.run(text, scan_target=scan_target, workspace_id=workspace_id)
        if name == "Threat Intel Detector":
            return agent.run(text, scan_target=scan_target)
        return agent.run(text)

    def _run_agents_parallel(
        self,
        agent_names: List[str],
        text: str,
        scan_target: str,
        workspace_id: str,
    ) -> List[AgentResult]:
        if not agent_names:
            return []
        results: List[AgentResult] = []
        with ThreadPoolExecutor(max_workers=len(agent_names)) as executor:
            futures = {
                executor.submit(
                    self._run_agent,
                    name,
                    self.agents[name],
                    text,
                    scan_target,
                    workspace_id,
                ): name
                for name in agent_names
            }
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                status = "THREAT" if result.threat_found else "CLEAN"
                print(f"  [{status}] {result.agent_name}: {result.summary}")
        return results

    def _should_run_llm_agents(self, text: str, cheap_results: List[AgentResult]) -> bool:
        if not self.llm_gate_enabled:
            return True
        if len(text) >= 800:
            return True

        if any(result.threat_found for result in cheap_results):
            return True

        suspicious_pattern = re.search(
            r"(ignore\s+previous|system\s+prompt|jailbreak|do\s+anything\s+now|bypass|override|"
            r"password|api\s*key|token|secret|bomb|kill|harm)",
            text,
            re.IGNORECASE,
        )
        return bool(suspicious_pattern)

    def _get_redacted_text(
        self,
        text: str,
        agent_results: List[AgentResult],
        scan_target: str = "input",
        workspace_id: str = "default",
    ) -> str:
        redacted = text
        for result in agent_results:
            if result.threat_found:
                agent = self.agents.get(result.agent_name)
                if agent and hasattr(agent, "redact"):
                    if result.agent_name == "Custom Rules Detector":
                        redacted = agent.redact(redacted, scan_target=scan_target, workspace_id=workspace_id)
                    else:
                        redacted = agent.redact(redacted)
        return redacted

    def _overall_severity(self, agent_results: List[AgentResult]) -> str:
        max_severity = "NONE"
        for result in agent_results:
            if result.threat_found and self._severity_rank(result.severity) > self._severity_rank(max_severity):
                max_severity = result.severity
        return max_severity

    def _resolve_policy_action(
        self,
        threat_type: str,
        severity: str,
        policy_profile: str,
        workspace_id: str = "default",
    ) -> str:
        base_policy = self.policy.get(threat_type, {})
        action = base_policy.get(severity, "FLAG")
        profile = self.policy_store.get_preset(policy_profile, workspace_id=workspace_id)
        overrides = profile.get("action_overrides", {}).get(threat_type, {})
        return overrides.get(severity, action)

    def _apply_allowlist(
        self,
        text: str,
        agent_results: List[AgentResult],
        policy_profile: str,
        workspace_id: str = "default",
    ) -> List[AgentResult]:
        profile = self.policy_store.get_preset(policy_profile, workspace_id=workspace_id)
        patterns = profile.get("allowlist_patterns", [])
        if not patterns:
            return agent_results

        try:
            allowlist_hit = any(re.search(pattern, text, re.IGNORECASE | re.DOTALL) for pattern in patterns)
        except re.error:
            allowlist_hit = False
        if not allowlist_hit:
            return agent_results

        max_allowed_rank = self._severity_rank(profile.get("allowlist_max_severity", "LOW"))
        adjusted: List[AgentResult] = []
        for result in agent_results:
            adjusted_result = deepcopy(result)
            if adjusted_result.threat_found and self._severity_rank(adjusted_result.severity) <= max_allowed_rank:
                adjusted_result.threat_found = False
                adjusted_result.summary = f"{adjusted_result.summary} Allowlisted by profile '{policy_profile}'."
                adjusted_result.matched = []
            adjusted.append(adjusted_result)
        return adjusted

    def _apply_policy(
        self,
        agent_results: List[AgentResult],
        policy_profile: str = "balanced",
        workspace_id: str = "default",
    ) -> tuple:
        final_action = "ALLOW"
        reasons = []
        triggered = []

        for result in agent_results:
            if result.threat_found:
                action = self._resolve_policy_action(
                    result.threat_type,
                    result.severity,
                    policy_profile,
                    workspace_id=workspace_id,
                )

                if self.action_priority.index(action) > self.action_priority.index(final_action):
                    final_action = action

                triggered.append(result.agent_name)
                reasons.append(f"{result.agent_name} [{result.severity}]: {result.summary}")

        reason = " | ".join(reasons) if reasons else "All agents passed. Content is clean."
        return final_action, reason, triggered

    def _collect_matched_threats(self, agent_results: List[AgentResult]) -> dict:
        matched_threats = {}
        for result in agent_results:
            if result.threat_found and result.matched:
                matched_threats[result.agent_name] = [
                    getattr(match, "pii_type", None)
                    or getattr(match, "secret_type", None)
                    or getattr(match, "abuse_type", None)
                    or getattr(match, "injection_type", None)
                    or getattr(match, "content_type", None)
                    or getattr(match, "intel_type", None)
                    or getattr(match, "custom_type", None)
                    or "unknown"
                    for match in result.matched[:5]
                ]
        return matched_threats

    def _analyze_text(
        self,
        text: str,
        scan_target: str,
        policy_profile: str = "balanced",
        workspace_id: str = "default",
        session_id: Optional[str] = None,
    ) -> FirewallDecision:
        start_time = time.time()

        if not session_id:
            cached = self._get_from_cache(text, scan_target, policy_profile, workspace_id)
            if cached:
                print("[Orchestrator] Cache hit - skipping agent analysis")
                return cached

        print(f"[Orchestrator] Analyzing {scan_target} ({len(text)} chars)...")
        print(f"[Orchestrator] Running all {len(self.agents)} agents in parallel...\n")

        cheap_agents = [name for name in self.agents if name not in self.llm_agents]
        llm_agents = [name for name in self.agents if name in self.llm_agents]
        cheap_results = self._run_agents_parallel(cheap_agents, text, scan_target, workspace_id)
        run_llm_agents = self._should_run_llm_agents(text, cheap_results)

        agent_results: List[AgentResult] = list(cheap_results)
        if run_llm_agents:
            llm_results = self._run_agents_parallel(llm_agents, text, scan_target, workspace_id)
            agent_results.extend(llm_results)
        else:
            print("[Orchestrator] LLM gate closed - skipping expensive detectors for low-risk content.")
            for name in llm_agents:
                skipped = AgentResult(
                    agent_name=name,
                    threat_found=False,
                    threat_type="NONE",
                    severity="NONE",
                    summary="Skipped by low-risk gate.",
                    matched=[],
                    agent_available=True,
                    fail_closed=False,
                )
                agent_results.append(skipped)

        agent_results = self._apply_allowlist(text, agent_results, policy_profile, workspace_id=workspace_id)
        final_action, reason, triggered = self._apply_policy(
            agent_results,
            policy_profile=policy_profile,
            workspace_id=workspace_id,
        )
        overall_severity = self._overall_severity(agent_results)
        unavailable_agents = [result.agent_name for result in agent_results if not result.agent_available]
        degraded = bool(unavailable_agents)

        if degraded:
            degraded_reason = "Unavailable detectors: " + ", ".join(unavailable_agents)
            reason = f"{reason} | {degraded_reason}" if reason else degraded_reason

        profile = self.policy_store.get_preset(policy_profile, workspace_id=workspace_id)
        flag_threshold = float(profile.get("session_flag_threshold", self.session_store.FLAG_THRESHOLD))
        block_threshold = float(profile.get("session_block_threshold", self.session_store.BLOCK_THRESHOLD))
        session_info = None

        if scan_target == "input" and session_id:
            if self.session_store.should_block(session_id, threshold=block_threshold):
                final_action = "BLOCK"
                score = self.session_store.get_threat_score(session_id)
                reason += f" | Session BLOCKED: cumulative threat score {score:.1f} exceeded threshold"
            elif self.session_store.should_flag(session_id, threshold=flag_threshold):
                if self.action_priority.index(final_action) < self.action_priority.index("FLAG"):
                    final_action = "FLAG"
                score = self.session_store.get_threat_score(session_id)
                reason += f" | Session FLAG: cumulative threat score {score:.1f}"

            recent = self.session_store.get_recent_texts(session_id, n=3)
            if len(recent) >= 2:
                combined_text = " ".join(recent + [text])
                try:
                    already_flagged = any(
                        result.threat_found and result.threat_type == "INJECTION"
                        for result in agent_results
                    )
                    if not already_flagged:
                        combined_result = self.agents["Injection Detector"].run(combined_text)
                        if combined_result.threat_found:
                            final_action = "BLOCK"
                            triggered.append("Multi-turn Injection Detector")
                            reason += " | Multi-turn injection detected across conversation history"
                except Exception as exc:
                    print(f"[Orchestrator] Multi-turn check failed: {exc}")

            self.session_store.add_message(session_id, text, final_action, overall_severity)
            session_info = self.session_store.summary(
                session_id,
                flag_threshold=flag_threshold,
                block_threshold=block_threshold,
            )
            print(
                f"[Session {session_id}] score={session_info['cumulative_score']:.1f} "
                f"msgs={session_info['message_count']}"
            )

        # ========== PRODUCTION FEATURES: Risk Scoring, Explainability, Compliance, Multi-turn Detection ==========
        
        # 1. Calculate risk score (0-100)
        risk_breakdown = self.risk_scorer.calculate_risk_score(
            agent_results=agent_results,
            overall_severity=overall_severity,
            triggered_agents=triggered,
        )
        risk_score = risk_breakdown.overall_score
        risk_level = risk_breakdown.risk_level
        
        # 2. Generate explainability report after constructing the decision object.
        explanation = None
        
        # 3. Apply compliance profiles and adjust decision if needed
        detected_patterns = []
        try:
            compliance_profile = self.compliance_manager.get_profile(policy_profile)
            if compliance_profile and scan_target == "input":
                threshold_by_threat = {
                    "PII": compliance_profile.pii_severity_threshold,
                    "SECRET": compliance_profile.secrets_severity_threshold,
                    "ABUSE": compliance_profile.abuse_severity_threshold,
                    "INJECTION": compliance_profile.injection_severity_threshold,
                    "UNSAFE_CONTENT": compliance_profile.unsafe_content_severity_threshold,
                }
                # Check if any agent results violate compliance thresholds
                for result in agent_results:
                    if result.threat_found:
                        threat_threshold = threshold_by_threat.get(result.threat_type, "MEDIUM")
                        
                        # If compliance is stricter, potentially upgrade action
                        if self._severity_rank(result.severity) >= self._severity_rank(threat_threshold):
                            action_override = compliance_profile.action_overrides.get(result.threat_type, {}).get(result.severity)
                            if action_override and self._action_rank(action_override) > self._action_rank(final_action):
                                final_action = action_override
                                reason += f" | Compliance '{policy_profile}' escalated: {action_override}"
        except Exception as e:
            print(f"[Orchestrator] Compliance profile application failed: {e}")
        
        # 4. Detect multi-turn attack patterns if session tracking enabled
        if session_id and scan_target == "input":
            try:
                # Track this message in enhanced session store
                self.enhanced_session_store.add_message(
                    session_id=session_id,
                    text=text,
                    action=final_action,
                    threat_types=[r.threat_type for r in agent_results if r.threat_found],
                    severity=overall_severity,
                    agents_triggered=triggered,
                    risk_score=risk_score,
                )
                
                # Detect attack patterns
                patterns = self.multi_turn_detector.detect_patterns(
                    session_id=session_id,
                    session_store=self.enhanced_session_store,
                )
                
                if patterns:
                    detected_patterns = patterns
                    for pattern in patterns:
                        if pattern.get("confidence", 0) >= 0.7:  # High confidence patterns
                            # Escalate decision if critical pattern detected
                            if pattern.get("type") == "escalating_injections":
                                final_action = "BLOCK"
                                reason += " | Multi-turn escalating injection detected"
                            elif pattern.get("type") == "credential_probing":
                                final_action = "BLOCK"
                                reason += " | Multi-turn credential probing attack detected"
                            elif pattern.get("type") == "detector_evasion":
                                final_action = "BLOCK"
                                reason += " | Multi-turn detector evasion tactic detected"
                        
                        print(f"[Pattern Detected] {pattern.get('type')}: confidence={pattern.get('confidence', 0):.0%}")
            except Exception as e:
                print(f"[Orchestrator] Multi-turn pattern detection failed: {e}")
        
        # ========== END PRODUCTION FEATURES ==========

        redacted_text = (
            self._get_redacted_text(text, agent_results, scan_target, workspace_id=workspace_id)
            if final_action == "REDACT"
            else text
        )
        processing_time = (time.time() - start_time) * 1000
        audit_text = self._get_redacted_text(text, agent_results, scan_target, workspace_id=workspace_id)

        self.audit_logger.log(
            input_text=audit_text,
            action=final_action,
            severity=overall_severity,
            triggered_agents=triggered,
            reason=reason,
            processing_time_ms=processing_time,
            matched_threats=self._collect_matched_threats(agent_results),
            scan_target=scan_target,
            policy_profile=policy_profile,
            workspace_id=workspace_id,
            session_id=session_id,
        )

        decision = FirewallDecision(
            action=final_action,
            reason=reason,
            severity=overall_severity,
            triggered_agents=triggered,
            agent_results=agent_results,
            redacted_text=redacted_text,
            processing_time_ms=processing_time,
            original_text=text,
            scan_target=scan_target,
            from_cache=False,
            degraded=degraded,
            unavailable_agents=unavailable_agents,
            policy_profile=policy_profile,
            risk_score=risk_score,
            risk_level=risk_level,
            explanation=explanation,
            detected_patterns=detected_patterns,
        )

        try:
            decision.explanation = self.explainability_generator.generate_report(
                decision=decision,
                risk_score_breakdown=risk_breakdown,
                session_info=session_info,
                workspace_id=workspace_id,
                policy_name=policy_profile,
            )
        except Exception as e:
            print(f"[Orchestrator] Explainability generation failed: {e}")

        try:
            self.alert_manager.dispatch(
                {
                    "action": decision.action,
                    "severity": decision.severity,
                    "reason": decision.reason,
                    "scan_target": decision.scan_target,
                    "policy_profile": decision.policy_profile,
                    "triggered_agents": decision.triggered_agents,
                    "risk_score": decision.risk_score,
                    "risk_level": decision.risk_level,
                    "session_id": session_id,
                }
            )
        except Exception as e:
            print(f"[Orchestrator] Alert dispatch failed: {e}")

        if not session_id:
            self._save_to_cache(text, decision, scan_target, policy_profile, workspace_id)

        self._print_decision(decision)
        return decision

    def _interaction_severity_to_action(self, severity: str) -> str:
        if severity == "CRITICAL":
            return "BLOCK"
        if severity in {"HIGH", "MEDIUM"}:
            return "FLAG"
        return "ALLOW"

    def _collect_decision_labels(self, decision: FirewallDecision) -> set:
        labels = set()
        for result in decision.agent_results:
            if not result.threat_found:
                continue
            labels.add(result.threat_type)
            for match in result.matched:
                label = (
                    getattr(match, "pii_type", None)
                    or getattr(match, "secret_type", None)
                    or getattr(match, "abuse_type", None)
                    or getattr(match, "injection_type", None)
                    or getattr(match, "content_type", None)
                    or getattr(match, "intel_type", None)
                    or getattr(match, "custom_type", None)
                )
                if label:
                    labels.add(str(label).upper())
        return labels

    def _detect_contradiction_alerts(
        self,
        prompt_text: str,
        output_text: str,
        prompt_decision: FirewallDecision,
        output_decision: FirewallDecision,
    ) -> List[dict]:
        alerts: List[dict] = []
        prompt_labels = self._collect_decision_labels(prompt_decision)
        output_labels = self._collect_decision_labels(output_decision)
        new_output_labels = sorted(output_labels - prompt_labels)

        output_is_riskier = self._severity_rank(output_decision.severity) > self._severity_rank(prompt_decision.severity)
        output_action_stronger = self._action_rank(output_decision.action) > self._action_rank(prompt_decision.action)

        if new_output_labels and output_action_stronger:
            alerts.append(
                {
                    "alert_type": "output_policy_contradiction",
                    "severity": "HIGH" if self._severity_rank(output_decision.severity) >= self._severity_rank("HIGH") else "MEDIUM",
                    "summary": "The model output introduced higher-risk content categories that were not present in the prompt.",
                    "evidence": ", ".join(new_output_labels[:5]),
                }
            )

        refusal_signals = [
            r"\bI can't help with that\b",
            r"\bI cannot assist with that\b",
            r"\bI won't provide\b",
            r"\bI must refuse\b",
            r"\bI can't provide instructions\b",
        ]
        prompt_refusal = any(re.search(pattern, prompt_text, re.IGNORECASE) for pattern in refusal_signals)
        output_refusal = any(re.search(pattern, output_text, re.IGNORECASE) for pattern in refusal_signals)
        if prompt_refusal and not output_refusal and output_action_stronger:
            alerts.append(
                {
                    "alert_type": "refusal_break",
                    "severity": "HIGH",
                    "summary": "The interaction appears to move from refusal language to a riskier output, which can indicate policy drift.",
                    "evidence": output_text[:160],
                }
            )

        if output_is_riskier and output_decision.action in {"REDACT", "BLOCK"} and prompt_decision.action == "ALLOW":
            alerts.append(
                {
                    "alert_type": "safe_prompt_unsafe_output",
                    "severity": "CRITICAL" if output_decision.action == "BLOCK" else "HIGH",
                    "summary": "A relatively clean prompt produced a materially riskier output.",
                    "evidence": output_decision.reason[:200],
                }
            )

        return alerts

    def _detect_drift_alerts(
        self,
        session_id: Optional[str],
        prompt_decision: FirewallDecision,
        output_decision: FirewallDecision,
    ) -> tuple[List[dict], float]:
        if not session_id:
            return [], 0.0

        history = self.session_store.get_history(session_id)
        if not history:
            return [], 0.0

        history_scores = [self._severity_rank(item.get("severity", "NONE")) for item in history]
        previous_scores = history_scores[:-1] if len(history_scores) > 1 else []
        session_risk_score = self.session_store.get_threat_score(session_id)
        current_peak = max(
            self._severity_rank(prompt_decision.severity),
            self._severity_rank(output_decision.severity),
        )

        alerts: List[dict] = []
        if previous_scores:
            prev_avg = sum(previous_scores) / len(previous_scores)
            risky_turns = sum(score >= self._severity_rank("MEDIUM") for score in previous_scores)

            if current_peak >= prev_avg + 2:
                alerts.append(
                    {
                        "alert_type": "conversation_risk_spike",
                        "severity": "HIGH",
                        "summary": "The current interaction is notably riskier than the recent conversation baseline.",
                        "evidence": f"previous_avg={prev_avg:.2f}, current_peak={current_peak}",
                    }
                )

            if risky_turns >= 2 and self._severity_rank(output_decision.severity) >= self._severity_rank("HIGH"):
                alerts.append(
                    {
                        "alert_type": "multi_turn_drift",
                        "severity": "CRITICAL",
                        "summary": "The conversation shows sustained risky turns and the latest output escalates that pattern.",
                        "evidence": f"risky_turns={risky_turns}, session_score={session_risk_score:.1f}",
                    }
                )

        if self.session_store.should_flag(session_id):
            alerts.append(
                {
                    "alert_type": "elevated_session_risk",
                    "severity": "MEDIUM" if not self.session_store.should_block(session_id) else "HIGH",
                    "summary": "The session has accumulated elevated risk across turns.",
                    "evidence": f"session_score={session_risk_score:.1f}",
                }
            )

        deduped = []
        seen = set()
        for alert in alerts:
            key = (alert["alert_type"], alert["summary"])
            if key not in seen:
                seen.add(key)
                deduped.append(alert)
        return deduped, session_risk_score

    def analyze(
        self,
        text: str,
        session_id: Optional[str] = None,
        policy_profile: str = "balanced",
        workspace_id: str = "default",
    ) -> FirewallDecision:
        return self._analyze_text(
            text=text,
            scan_target="input",
            policy_profile=policy_profile,
            workspace_id=workspace_id,
            session_id=session_id,
        )

    def analyze_output(
        self,
        text: str,
        policy_profile: str = "balanced",
        workspace_id: str = "default",
    ) -> FirewallDecision:
        return self._analyze_text(
            text=text,
            scan_target="output",
            policy_profile=policy_profile,
            workspace_id=workspace_id,
            session_id=None,
        )

    def get_session_summary(self, session_id: str) -> dict:
        preset = self.policy_store.get_preset("balanced")
        return self.session_store.summary(
            session_id,
            flag_threshold=float(preset.get("session_flag_threshold", self.session_store.FLAG_THRESHOLD)),
            block_threshold=float(preset.get("session_block_threshold", self.session_store.BLOCK_THRESHOLD)),
        )

    def clear_session(self, session_id: str):
        self.session_store.clear(session_id)

    def list_policy_presets(self, workspace_id: Optional[str] = None) -> List[dict]:
        return self.policy_store.list_presets(workspace_id=workspace_id)

    def list_policy_drafts(self, workspace_id: Optional[str] = None) -> List[dict]:
        return self.policy_store.list_drafts(workspace_id=workspace_id)

    def save_policy_preset(self, **kwargs) -> dict:
        return self.policy_store.save_preset(**kwargs)

    def delete_policy_preset(self, name: str, workspace_id: Optional[str] = None) -> bool:
        return self.policy_store.delete_preset(name, workspace_id=workspace_id)

    def create_policy_draft_from_adjustment(self, adjustment: dict, workspace_id: str = "global") -> dict:
        return self.policy_store.create_draft_from_adjustment(adjustment, workspace_id=workspace_id)

    def request_policy_approval(self, name: str, requested_by: str, workspace_id: str = "global") -> Optional[dict]:
        return self.policy_store.request_approval(name, requested_by, workspace_id=workspace_id)

    def approve_policy_draft(self, name: str, approved_by: str, workspace_id: str = "global") -> Optional[dict]:
        return self.policy_store.approve_draft(name, approved_by, workspace_id=workspace_id)

    def promote_policy_draft(
        self,
        name: str,
        note: str = "",
        workspace_id: str = "default",
    ) -> Optional[dict]:
        promoted = self.policy_store.promote_draft(name, workspace_id=workspace_id)
        if promoted:
            self.audit_logger.log_promotion(
                item_type="policy",
                item_id=promoted["name"],
                item_name=promoted["name"],
                note=note,
                metadata={"description": promoted.get("description", "")},
                workspace_id=workspace_id,
            )
        return promoted

    def preview_policy_draft(self, name: str, workspace_id: Optional[str] = None) -> Optional[dict]:
        return self.policy_store.preview_draft_diff(name, workspace_id=workspace_id)

    def get_promotion_history(self, limit: int = 50, workspace_id: Optional[str] = None) -> List[dict]:
        return self.audit_logger.get_promotion_history(limit=limit, workspace_id=workspace_id)

    def analyze_interaction(
        self,
        prompt_text: str,
        output_text: str,
        session_id: Optional[str] = None,
        policy_profile: str = "balanced",
        workspace_id: str = "default",
    ) -> InteractionDecision:
        prompt_decision = self.analyze(
            prompt_text,
            session_id=session_id,
            policy_profile=policy_profile,
            workspace_id=workspace_id,
        )
        output_decision = self.analyze_output(
            output_text,
            policy_profile=policy_profile,
            workspace_id=workspace_id,
        )

        combined_action = max([prompt_decision.action, output_decision.action], key=self._action_rank)
        combined_severity = max([prompt_decision.severity, output_decision.severity], key=self._severity_rank)
        triggered_agents = list(dict.fromkeys(
            [f"prompt:{agent}" for agent in prompt_decision.triggered_agents]
            + [f"output:{agent}" for agent in output_decision.triggered_agents]
        ))
        interaction_alerts = self._detect_contradiction_alerts(
            prompt_text=prompt_text,
            output_text=output_text,
            prompt_decision=prompt_decision,
            output_decision=output_decision,
        )
        drift_alerts, session_risk_score = self._detect_drift_alerts(
            session_id=session_id,
            prompt_decision=prompt_decision,
            output_decision=output_decision,
        )
        interaction_alerts.extend(drift_alerts)

        for alert in interaction_alerts:
            combined_severity = max([combined_severity, alert["severity"]], key=self._severity_rank)
            combined_action = max(
                [combined_action, self._interaction_severity_to_action(alert["severity"])],
                key=self._action_rank,
            )
            triggered_agents.append(f"interaction:{alert['alert_type']}")

        combined_reason = (
            f"Prompt: {prompt_decision.reason} | "
            f"Output: {output_decision.reason}"
        )
        if interaction_alerts:
            combined_reason += " | Interaction alerts: " + "; ".join(
                f"{alert['alert_type']} [{alert['severity']}]: {alert['summary']}"
                for alert in interaction_alerts
            )

        return InteractionDecision(
            prompt_decision=prompt_decision,
            output_decision=output_decision,
            combined_action=combined_action,
            combined_severity=combined_severity,
            combined_reason=combined_reason,
            triggered_agents=list(dict.fromkeys(triggered_agents)),
            interaction_alerts=interaction_alerts,
            drift_detected=any(alert["alert_type"] in {"conversation_risk_spike", "multi_turn_drift", "elevated_session_risk"} for alert in interaction_alerts),
            contradiction_detected=any(alert["alert_type"] in {"output_policy_contradiction", "refusal_break", "safe_prompt_unsafe_output"} for alert in interaction_alerts),
            session_risk_score=session_risk_score,
        )

    def _print_decision(self, decision: FirewallDecision):
        action_icons = {
            "ALLOW": "ALLOW",
            "FLAG": "FLAG",
            "REDACT": "REDACT",
            "BLOCK": "BLOCK",
        }
        severity_icons = {
            "NONE": "NONE",
            "LOW": "LOW",
            "MEDIUM": "MEDIUM",
            "HIGH": "HIGH",
            "CRITICAL": "CRITICAL",
        }
        cache_tag = " [CACHED]" if decision.from_cache else ""
        print(f"\n{'=' * 60}")
        print(f"  FIREWALL DECISION: {action_icons.get(decision.action, decision.action)}{cache_tag}")
        print(f"  Target    : {decision.scan_target}")
        print(f"  Severity  : {severity_icons.get(decision.severity, '')} {decision.severity}")
        print(
            f"  Triggered : "
            f"{', '.join(decision.triggered_agents) if decision.triggered_agents else 'None'}"
        )
        print(f"  Time      : {decision.processing_time_ms:.0f}ms")
        print(f"  Reason    : {decision.reason[:120]}...")
        if decision.action == "REDACT":
            print(f"  Redacted  : {decision.redacted_text[:100]}...")
        print(f"{'=' * 60}\n")
