"""
Enhanced Session Memory for Multi-Turn Attack Detection

Tracks attack patterns across multiple prompts - injection/hijacking attempts
that escalate or change tactics across a conversation.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import List, Dict, Optional
from collections import deque


@dataclass
class MessageRecord:
    """Record of a single message in a session"""
    
    timestamp: str
    text: str
    action: str  # ALLOW/FLAG/REDACT/BLOCK
    severity: str  # NONE/LOW/MEDIUM/HIGH/CRITICAL
    threat_types: List[str]  # PII, SECRET, INJECTION, etc.
    agents_triggered: List[str]
    risk_score: float = 0.0
    was_blocked: bool = False


@dataclass
class AttackPattern:
    """Detected attack pattern across multiple turns"""
    
    pattern_type: str  # "escalating_injection", "credential_probing", etc.
    severity: str
    confidence: float  # 0-1
    first_detected: str  # timestamp
    last_detected: str
    occurrences: int
    evidence: List[str]  # Sample messages showing the pattern
    recommendation: str


class MultiTurnAttackDetector:
    """
    Detects attack patterns that unfold across multiple messages.
    
    Attack patterns include:
    - Escalating injection attempts (soft probes → direct attacks)
    - Credential probing (asking for different types of secrets)
    - Role override chains (building context for jailbreak)
    - Phased content attacks (starting mild, escalating)
    - Information gathering (reconnaissance before attack)
    """
    
    # Attack pattern signatures
    INJECTION_PATTERNS = [
        r"ignore.*previous",
        r"you are now",
        r"pretend.*are",
        r"act as",
        r"new instructions",
        r"forget.*rules",
        r"bypass.*safety",
        r"reveal.*system.*prompt",
        r"what.*secret.*instructions"
    ]
    
    CREDENTIAL_PATTERNS = [
        r"api.*key|api key",
        r"password|passwd|pwd",
        r"token|auth",
        r"secret|credentials?",
        r"access.*key",
        r"private.*key",
        r"database.*connection",
        r"connection.*string"
    ]
    
    SOCIAL_ENGINEERING_PATTERNS = [
        r"admin|super.*user|manager",
        r"override|privilege|elevated",
        r"urgent|emergency|critical issue",
        r"verify.*identity",
        r"confirm.*access"
    ]

    def __init__(self, session_history: Optional[deque] = None):
        """
        Initialize detector with session history.
        
        Args:
            session_history: deque of MessageRecord objects
        """
        self.session_history = session_history or deque()
        self.detected_patterns: List[AttackPattern] = []

    def detect_patterns(self, session_id: Optional[str] = None, session_store=None) -> List[dict]:
        """
        Scan session history for multi-turn attack patterns.
        
        Returns:
            List of detected pattern dictionaries.
        """
        if session_store is not None and session_id:
            session = getattr(session_store, "sessions", {}).get(session_id, {})
            self.session_history = session.get("messages", deque())

        self.detected_patterns = []
        
        if len(self.session_history) < 2:
            return []
        
        history_list = list(self.session_history)
        
        # Check for various attack patterns
        self._detect_escalating_injection(history_list)
        self._detect_credential_probing(history_list)
        self._detect_role_override_chain(history_list)
        self._detect_phased_content_attack(history_list)
        self._detect_severity_escalation(history_list)
        self._detect_agent_avoidance(history_list)
        
        return [self._to_pattern_dict(pattern) for pattern in self.detected_patterns]

    def _to_pattern_dict(self, pattern: AttackPattern) -> dict:
        pattern_type_map = {
            "escalating_injection": "escalating_injections",
        }
        normalized_type = pattern_type_map.get(pattern.pattern_type, pattern.pattern_type)
        return {
            "type": normalized_type,
            "severity": pattern.severity,
            "confidence": pattern.confidence,
            "first_detected": pattern.first_detected,
            "last_detected": pattern.last_detected,
            "occurrences": pattern.occurrences,
            "evidence": pattern.evidence,
            "recommendation": pattern.recommendation,
        }

    def _detect_escalating_injection(self, history: List[MessageRecord]):
        """Detect gradual escalation of injection attack attempts"""
        
        injection_messages = [
            (i, msg) for i, msg in enumerate(history)
            if "INJECTION" in msg.threat_types
        ]
        
        if len(injection_messages) < 2:
            return
        
        # Check if injections are escalating in severity
        severities = []
        for idx, msg in injection_messages:
            severities.append((idx, msg.severity))
        
        # Look for pattern where severity increases
        if len(severities) >= 2:
            confidence = 0.0
            
            severity_order = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            prev_score = 0
            escalation_count = 0
            
            for idx, severity in severities:
                curr_score = severity_order.get(severity, 0)
                if curr_score > prev_score:
                    escalation_count += 1
                prev_score = curr_score
            
            # High confidence if consistent escalation
            confidence = min(escalation_count / len(severities), 1.0)
            
            if escalation_count >= 2:
                first_msg = history[injection_messages[0][0]]
                last_msg = history[injection_messages[-1][0]]
                
                pattern = AttackPattern(
                    pattern_type="escalating_injection",
                    severity="HIGH",
                    confidence=confidence,
                    first_detected=first_msg.timestamp,
                    last_detected=last_msg.timestamp,
                    occurrences=len(injection_messages),
                    evidence=[msg.text[:100] for _, msg in injection_messages[:3]],
                    recommendation="BLOCK session immediately. Likely coordinated injection attack."
                )
                self.detected_patterns.append(pattern)

    def _detect_credential_probing(self, history: List[MessageRecord]):
        """
        Detect when attacker probes for different types of credentials.
        E.g., first asks for API keys, then database password, then private key.
        """
        
        import re
        
        credential_types_requested = set()
        credential_messages = []
        
        for i, msg in enumerate(history):
            for cred_type, pattern in [
                ("api_key", r"api.*key|aws.*key|stripe.*key"),
                ("password", r"password|passwd|pwd"),
                ("token", r"token|auth|bearer"),
                ("private_key", r"private.*key|rsa.*key"),
                ("db_connection", r"database|db.*connection|mongodb|postgresql"),
            ]:
                if re.search(pattern, msg.text, re.IGNORECASE):
                    if cred_type not in credential_types_requested:
                        credential_types_requested.add(cred_type)
                        credential_messages.append((i, msg, cred_type))
        
        # If attacker is probing multiple credential types, it's suspicious
        if len(credential_types_requested) >= 2:
            confidence = min(len(credential_types_requested) / 4, 1.0)  # 4 types = max confidence
            
            first_msg = credential_messages[0][1]
            last_msg = credential_messages[-1][1]
            
            pattern = AttackPattern(
                pattern_type="credential_probing",
                severity="HIGH",
                confidence=confidence,
                first_detected=first_msg.timestamp,
                last_detected=last_msg.timestamp,
                occurrences=len(credential_messages),
                evidence=[msg.text[:100] for _, msg, _ in credential_messages[:3]],
                recommendation=f"BLOCK session. Attacker probing for {', '.join(credential_types_requested)}. Rotate any exposed credentials."
            )
            self.detected_patterns.append(pattern)

    def _detect_role_override_chain(self, history: List[MessageRecord]):
        """
        Detect jailbreak attempts building up context.
        E.g., "You are an AI assistant" → "You are an unrestricted AI" → "You have no rules"
        """
        
        import re
        
        role_override_messages = []
        
        for i, msg in enumerate(history):
            # Check for role/identity override attempts
            if re.search(r"you are|act as|pretend|role.*play|imagine.*you", msg.text, re.IGNORECASE):
                # And combined with override language
                if re.search(r"no.*rules|no.*restrictions|unrestricted|ignore.*safety|bypass.*filter", msg.text, re.IGNORECASE):
                    role_override_messages.append((i, msg))
        
        # If there's a pattern of role building, it's an attack
        if len(role_override_messages) >= 2:
            confidence = len(role_override_messages) / len(history)
            confidence = min(confidence, 1.0)
            
            first_msg = role_override_messages[0][1]
            last_msg = role_override_messages[-1][1]
            
            pattern = AttackPattern(
                pattern_type="role_override_chain",
                severity="CRITICAL",
                confidence=confidence,
                first_detected=first_msg.timestamp,
                last_detected=last_msg.timestamp,
                occurrences=len(role_override_messages),
                evidence=[msg.text[:100] for _, msg in role_override_messages[:3]],
                recommendation="BLOCK session immediately. Clear jailbreak/role-override attack. Investigate user."
            )
            self.detected_patterns.append(pattern)

    def _detect_phased_content_attack(self, history: List[MessageRecord]):
        """
        Detect unsafe content attacks that escalate in phases.
        E.g., starts with mild content, then increasingly harmful.
        """
        
        unsafe_content_messages = [
            (i, msg) for i, msg in enumerate(history)
            if "UNSAFE_CONTENT" in msg.threat_types
        ]
        
        if len(unsafe_content_messages) >= 2:
            # Check if severity is increasing
            severity_scores = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            scores = [severity_scores.get(msg.severity, 0) for _, msg in unsafe_content_messages]
            
            is_escalating = all(scores[i] <= scores[i+1] for i in range(len(scores)-1))
            
            if is_escalating:
                confidence = 0.8 if len(unsafe_content_messages) >= 3 else 0.6
                
                first_msg = unsafe_content_messages[0][1]
                last_msg = unsafe_content_messages[-1][1]
                
                pattern = AttackPattern(
                    pattern_type="phased_unsafe_content",
                    severity="HIGH",
                    confidence=confidence,
                    first_detected=first_msg.timestamp,
                    last_detected=last_msg.timestamp,
                    occurrences=len(unsafe_content_messages),
                    evidence=[msg.text[:100] for _, msg in unsafe_content_messages[:3]],
                    recommendation="FLAG session. Escalating unsafe content. Monitor for policy violations."
                )
                self.detected_patterns.append(pattern)

    def _detect_severity_escalation(self, history: List[MessageRecord]):
        """
        Detect overall severity escalation across entire session.
        Any threat pattern that's getting worse over time.
        """
        
        if len(history) < 3:
            return
        
        severity_scores = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        scores = [severity_scores.get(msg.severity, 0) for msg in history]
        
        # Calculate trend
        recent_scores = scores[-5:] if len(scores) >= 5 else scores
        early_scores = scores[:3]
        
        avg_recent = sum(recent_scores) / len(recent_scores)
        avg_early = sum(early_scores) / len(early_scores)
        
        escalation_ratio = avg_recent / max(avg_early, 0.1)  # Avoid division by zero
        
        if escalation_ratio > 1.5:  # 50% escalation
            confidence = min((escalation_ratio - 1) / 3, 1.0)  # Normalize to 0-1
            
            pattern = AttackPattern(
                pattern_type="severity_escalation",
                severity="HIGH" if avg_recent >= 2 else "MEDIUM",
                confidence=confidence,
                first_detected=history[0].timestamp,
                last_detected=history[-1].timestamp,
                occurrences=len(history),
                evidence=[msg.text[:80] for msg in history[-3:]],
                recommendation="ALERT: Session showing concerning escalation pattern. Consider rate limiting."
            )
            self.detected_patterns.append(pattern)

    def _detect_agent_avoidance(self, history: List[MessageRecord]):
        """
        Detect when attacker switches tactics to avoid specific agent detection.
        E.g., stopped triggering Injection Detector, now triggering Secrets Detector.
        """
        
        if len(history) < 4:
            return
        
        # Split history into early and recent
        split_point = len(history) // 2
        early_agents = set()
        recent_agents = set()
        
        for msg in history[:split_point]:
            early_agents.update(msg.agents_triggered)
        
        for msg in history[split_point:]:
            recent_agents.update(msg.agents_triggered)
        
        # If agents triggered changed significantly, attacker may be evading
        early_unique = early_agents - recent_agents
        recent_unique = recent_agents - early_agents
        
        if len(recent_unique) >= 2 and len(early_unique) >= 1:
            confidence = 0.7
            
            pattern = AttackPattern(
                pattern_type="detector_evasion",
                severity="MEDIUM",
                confidence=confidence,
                first_detected=history[0].timestamp,
                last_detected=history[-1].timestamp,
                occurrences=len(history),
                evidence=[f"Switched from {early_unique} to {recent_unique}"],
                recommendation="Monitor closely. Attacker may be changing tactics to evade detection."
            )
            self.detected_patterns.append(pattern)


class EnhancedSessionStore:
    """
    Enhanced session store that tracks messages and detects multi-turn patterns.
    
    Extends basic session_store with attack pattern detection.
    """
    
    def __init__(self, max_message_history: int = 50):
        self.sessions: Dict[str, Dict] = {}
        self.max_history = max_message_history

    def create_session(self, session_id: str) -> Dict:
        """Create new session with tracking"""
        self.sessions[session_id] = {
            "created": datetime.now().isoformat(),
            "messages": deque(maxlen=self.max_history),
            "threat_count": 0,
            "cumulative_score": 0.0,
            "attacks_detected": []
        }
        return self.sessions[session_id]

    def add_message(
        self,
        session_id: str,
        text: str,
        action: str,
        severity: str,
        threat_types: List[str] = None,
        agents_triggered: List[str] = None,
        risk_score: float = 0.0
    ):
        """Add message to session and check for attack patterns"""
        
        if session_id not in self.sessions:
            self.create_session(session_id)
        
        session = self.sessions[session_id]
        threat_types = threat_types or []
        agents_triggered = agents_triggered or []
        
        # Create message record
        msg_record = MessageRecord(
            timestamp=datetime.now().isoformat(),
            text=text,
            action=action,
            severity=severity,
            threat_types=threat_types,
            agents_triggered=agents_triggered,
            risk_score=risk_score,
            was_blocked=action in ["BLOCK", "REDACT"]
        )
        
        session["messages"].append(msg_record)
        
        if threat_types:
            session["threat_count"] += 1
        
        # Accumulate risk score
        severity_scores = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        session["cumulative_score"] += severity_scores.get(severity, 0)
        
        # Detect multi-turn patterns
        if len(session["messages"]) >= 2:
            detector = MultiTurnAttackDetector(session["messages"])
            patterns = detector.detect_patterns()
            session["attacks_detected"] = patterns

    def get_session_patterns(self, session_id: str) -> List[dict]:
        """Get detected attack patterns for a session"""
        if session_id in self.sessions:
            return self.sessions[session_id].get("attacks_detected", [])
        return []

    def get_session_summary(self, session_id: str) -> Dict:
        """Get comprehensive session summary with patterns"""
        if session_id not in self.sessions:
            return {}
        
        session = self.sessions[session_id]
        
        return {
            "session_id": session_id,
            "created": session["created"],
            "message_count": len(session["messages"]),
            "threat_count": session["threat_count"],
            "cumulative_score": session["cumulative_score"],
            "detected_patterns": [
                {
                    "type": p.get("type", ""),
                    "severity": p.get("severity", "LOW"),
                    "confidence": p.get("confidence", 0.0),
                    "occurrences": p.get("occurrences", 0),
                    "recommendation": p.get("recommendation", ""),
                }
                for p in session.get("attacks_detected", [])
            ]
        }
