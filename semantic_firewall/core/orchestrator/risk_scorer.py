"""
Risk Scoring Module (0-100) for Semantic Firewall

Converts agent results into a continuous risk score instead of binary decisions.
"""

from dataclasses import dataclass
from typing import List, Dict, Optional
from datetime import datetime


@dataclass
class RiskScoreBreakdown:
    """Detailed breakdown of risk score components"""
    
    overall_score: float  # 0-100
    severity_score: float  # 0-100
    pattern_score: float  # confidence/likelihood
    session_history_score: float  # 0-100 based on accumulated threats
    agent_confidence: float  # average confidence across agents
    
    category_scores: Dict[str, float]  # per-agent breakdown
    risk_level: str  # CRITICAL (80-100), HIGH (60-79), MEDIUM (40-59), LOW (20-39), NONE (0-19)
    
    explanation: str  # Human-readable explanation
    recommendations: List[str]  # What to do


class RiskScorer:
    """
    Converts firewall decisions into continuous risk scores (0-100).
    
    Risk Scoring Formula:
    - Base Score: Severity level (0-40 points)
    - Confidence: Agent consensus (0-30 points)
    - Session History: Multi-turn escalation (0-20 points)
    - Pattern Severity: Matched pattern criticality (0-10 points)
    """
    
    SEVERITY_POINTS = {
        "NONE": 0,
        "LOW": 16.67,  # (0-20 range)
        "MEDIUM": 40,  # (20-40 range)
        "HIGH": 60,    # (40-80 range)
        "CRITICAL": 85  # (80-100 range)
    }
    
    AGENT_WEIGHTS = {
        "Injection Detector": 1.0,  # Most critical
        "Unsafe Content Detector": 0.95,
        "Secrets Detector": 0.9,
        "PII Detector": 0.85,
        "Abuse Detector": 0.80,
        "Custom Rules Detector": 0.75
    }
    
    RISK_LEVEL_THRESHOLDS = {
        "NONE": (0, 20),
        "LOW": (20, 40),
        "MEDIUM": (40, 60),
        "HIGH": (60, 80),
        "CRITICAL": (80, 100)
    }

    def __init__(self):
        pass

    def calculate_risk_score(
        self,
        agent_results: List,
        overall_severity: str,
        session_risk_score: Optional[float] = None,
        triggered_agents: Optional[List[str]] = None,
        text_length: int = 0
    ) -> RiskScoreBreakdown:
        """
        Calculate comprehensive risk score from agent results.
        
        Args:
            agent_results: List of AgentResult objects
            overall_severity: NONE/LOW/MEDIUM/HIGH/CRITICAL
            session_risk_score: Optional accumulated session score
            triggered_agents: List of agents that found threats
            text_length: Length of analyzed text
            
        Returns:
            RiskScoreBreakdown with score, explanation, and recommendations
        """
        
        triggered_agents = triggered_agents or []
        session_risk_score = session_risk_score or 0.0
        
        # 1. Severity Base Score (0-40 points)
        severity_score = self.SEVERITY_POINTS.get(overall_severity, 0)
        
        # 2. Agent Confidence Score (0-30 points)
        threats_found = [r for r in agent_results if r.threat_found]
        agent_confidence = self._calculate_agent_confidence(threats_found, agent_results)
        confidence_score = agent_confidence * 30
        
        # 3. Pattern Severity Score (0-20 points)
        # Higher if multiple agents triggered
        pattern_score = min(len(triggered_agents) * 5, 20)
        
        # 4. Session History Score (0-10 points)
        # Escalating threats over time
        session_score = min((session_risk_score / 10) * 10, 10)
        
        # Calculate overall score
        overall_score = severity_score + confidence_score + pattern_score + session_score
        overall_score = min(max(overall_score, 0), 100)  # Clamp to 0-100
        
        # Determine risk level
        risk_level = self._get_risk_level(overall_score)
        
        # Build category scores
        category_scores = self._build_category_scores(agent_results)
        
        # Generate explanation and recommendations
        explanation = self._generate_explanation(
            overall_score, risk_level, threats_found, 
            overall_severity, category_scores, text_length
        )
        recommendations = self._generate_recommendations(
            risk_level, overall_severity, threats_found
        )
        
        return RiskScoreBreakdown(
            overall_score=overall_score,
            severity_score=severity_score,
            pattern_score=pattern_score,
            session_history_score=session_score,
            agent_confidence=agent_confidence,
            category_scores=category_scores,
            risk_level=risk_level,
            explanation=explanation,
            recommendations=recommendations
        )

    def _calculate_agent_confidence(self, threats_found: List, all_results: List) -> float:
        """Calculate average confidence of threat detection"""
        if not threats_found:
            return 0.0
        
        total_confidence = 0.0
        for result in threats_found:
            # Get average confidence from matched items
            if hasattr(result, 'matched') and result.matched:
                confidences = [
                    getattr(m, 'confidence', 0.9) for m in result.matched
                ]
                avg = sum(confidences) / len(confidences) if confidences else 0.9
                
                # Weight by agent importance
                agent_weight = self.AGENT_WEIGHTS.get(result.agent_name, 0.7)
                total_confidence += avg * agent_weight
            else:
                # Default confidence if no matches but threat found
                agent_weight = self.AGENT_WEIGHTS.get(result.agent_name, 0.7)
                total_confidence += 0.85 * agent_weight
        
        # Normalize
        total_weight = sum(
            self.AGENT_WEIGHTS.get(r.agent_name, 0.7) 
            for r in threats_found
        )
        return total_confidence / max(total_weight, 0.1)

    def _build_category_scores(self, agent_results: List) -> Dict[str, float]:
        """Build per-category risk scores"""
        scores = {}
        for result in agent_results:
            if result.threat_found:
                severity_base = self.SEVERITY_POINTS.get(result.severity, 0)
                confidence = getattr(result, 'confidence', 0.85)
                
                # Adjust base by confidence
                adjusted_score = severity_base * (0.5 + confidence * 0.5)
                scores[result.agent_name] = min(adjusted_score, 100)
            else:
                scores[result.agent_name] = 0
        
        return scores

    def _get_risk_level(self, score: float) -> str:
        """Convert score to categorical risk level"""
        for level, (min_val, max_val) in self.RISK_LEVEL_THRESHOLDS.items():
            if min_val <= score < max_val:
                return level
        return "CRITICAL"

    def _generate_explanation(
        self,
        score: float,
        risk_level: str,
        threats_found: List,
        severity: str,
        category_scores: Dict[str, float],
        text_length: int
    ) -> str:
        """Generate human-readable risk explanation"""
        
        parts = [
            f"Risk Assessment: {risk_level} ({score:.1f}/100)\n",
            f"Severity: {severity} | Length: {text_length} chars\n"
        ]
        
        if not threats_found:
            parts.append("✓ All agents passed. No threats detected.")
            return "".join(parts)
        
        parts.append(f"✗ {len(threats_found)} agent(s) detected threats:\n")
        
        for result in threats_found:
            agent_score = category_scores.get(result.agent_name, 0)
            confidence = getattr(result, 'confidence', None)
            
            confidence_str = f"{confidence:.0%}" if confidence else "high"
            parts.append(f"\n  • {result.agent_name}: {agent_score:.1f}/100")
            parts.append(f"    Severity: {result.severity}")
            parts.append(f"    Confidence: {confidence_str}")
            parts.append(f"    Details: {result.summary[:100]}")
            
            if hasattr(result, 'matched') and result.matched:
                match_count = len(result.matched)
                parts.append(f"    Matches: {match_count}")
        
        return "".join(parts)

    def _generate_recommendations(
        self,
        risk_level: str,
        severity: str,
        threats_found: List
    ) -> List[str]:
        """Generate actionable recommendations"""
        
        recommendations = []
        
        if risk_level == "CRITICAL":
            recommendations.append("🔴 CRITICAL: Immediately block this input/output")
            recommendations.append("Alert security team - potential attack detected")
            recommendations.append("Review session history - look for coordinated threats")
        
        elif risk_level == "HIGH":
            recommendations.append("🟠 HIGH: Block or heavily redact this content")
            recommendations.append("Log for security review")
            recommendations.append("Consider blocking user session if pattern continues")
        
        elif risk_level == "MEDIUM":
            recommendations.append("🟡 MEDIUM: Flag for human review")
            recommendations.append("Consider redacting sensitive data")
            recommendations.append("Monitor for escalation patterns")
        
        elif risk_level == "LOW":
            recommendations.append("🟢 LOW: Proceed with caution")
            recommendations.append("Monitor in future interactions")
        
        # Specific threat recommendations
        if threats_found:
            threat_types = set(r.threat_type for r in threats_found)
            
            if "INJECTION" in threat_types:
                recommendations.append("→ Prompt Injection Risk: Review with human before execution")
            
            if "PII" in threat_types:
                recommendations.append("→ PII Leaked: Redact before response")
            
            if "SECRET" in threat_types:
                recommendations.append("→ Secrets Detected: Block immediately, review access logs")
            
            if "UNSAFE_CONTENT" in threat_types:
                recommendations.append("→ Unsafe Content: Block & escalate to policy team")
        
        return recommendations

    def score_to_action(self, score: float, policy_overrides: Optional[Dict] = None) -> str:
        """
        Convert risk score to action with optional policy overrides.
        
        Default thresholds:
        - 0-30: ALLOW
        - 30-60: FLAG
        - 60-85: REDACT
        - 85-100: BLOCK
        """
        
        policy = policy_overrides or {}
        allow_threshold = policy.get("allow_threshold", 30)
        flag_threshold = policy.get("flag_threshold", 60)
        redact_threshold = policy.get("redact_threshold", 85)
        
        if score < allow_threshold:
            return "ALLOW"
        elif score < flag_threshold:
            return "FLAG"
        elif score < redact_threshold:
            return "REDACT"
        else:
            return "BLOCK"
