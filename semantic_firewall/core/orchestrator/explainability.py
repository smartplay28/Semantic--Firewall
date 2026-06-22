"""
Explainability Report Generator for Semantic Firewall

Generates human-readable, detailed reports explaining firewall decisions.
"""

from dataclasses import dataclass, asdict
from datetime import datetime
from typing import List, Dict, Optional
import json


@dataclass
class ExplainabilityReport:
    """Comprehensive explainability report for a firewall decision"""
    
    timestamp: str
    overall_action: str
    risk_score: float
    severity: str
    
    # Components
    executive_summary: str
    triggered_agents: List[str]
    agent_details: List[Dict]  # Per-agent breakdown
    session_context: Optional[Dict]  # Multi-turn history
    
    # Reasoning
    decision_rationale: str
    contributing_factors: List[str]
    mitigating_factors: List[str]
    
    # Recommendations
    recommended_actions: List[str]
    confidence_level: str  # HIGH/MEDIUM/LOW
    
    # Audit trail
    metadata: Dict  # Workspace, session, policy info


class ExplainabilityGenerator:
    """
    Generates detailed, human-readable explanations for firewall decisions.
    
    Reports include:
    - Plain English summary of why content was flagged
    - Per-agent analysis with confidence scores
    - Session context and escalation patterns
    - Actionable recommendations for security team
    - Confidence levels for each conclusion
    """
    
    DECISION_TEMPLATES = {
        "ALLOW": {
            "confidence_high": "All detectors passed without finding threats.",
            "confidence_medium": "Detectors found minimal indicators, all below thresholds.",
            "confidence_low": "Borderline case - proceed with caution and monitor."
        },
        "FLAG": {
            "confidence_high": "Standard threat indicators detected. Review immediately.",
            "confidence_medium": "Potential threats detected but may be false positives. Review.",
            "confidence_low": "Ambiguous signals detected. Manual review strongly recommended."
        },
        "REDACT": {
            "confidence_high": "Sensitive data detected. Redact before serving to users.",
            "confidence_medium": "Likely sensitive content detected. Redact as precaution.",
            "confidence_low": "Possible sensitive data. Consider redacting if unsure."
        },
        "BLOCK": {
            "confidence_high": "High-confidence threat detected. Block immediately.",
            "confidence_medium": "Significant threat indicators present. Block to be safe.",
            "confidence_low": "Mixed signals suggest threat. Escalate to security team."
        }
    }
    
    THREAT_SEVERITY_NARRATIVES = {
        "CRITICAL": "This content represents a severe, immediate threat.",
        "HIGH": "This content presents a significant security risk.",
        "MEDIUM": "This content contains notable security concerns.",
        "LOW": "This content has minor security indicators.",
        "NONE": "This content appears safe."
    }
    
    AGENT_NARRATIVES = {
        "PII Detector": {
            "description": "Detects personally identifiable information (emails, IDs, cards, etc.)",
            "threat": "Data privacy violation - PII exposure can lead to identity theft"
        },
        "Secrets Detector": {
            "description": "Detects API keys, tokens, passwords, database credentials",
            "threat": "Credential exposure - attackers can hijack accounts or systems"
        },
        "Abuse Detector": {
            "description": "Detects DoS attacks, path traversal, encoding attacks",
            "threat": "System abuse - attempts to crash or compromise infrastructure"
        },
        "Injection Detector": {
            "description": "Detects prompt injection, jailbreaks, role override attacks",
            "threat": "AI model manipulation - attempts to bypass safety guidelines"
        },
        "Unsafe Content Detector": {
            "description": "Detects violence, CSAM, hate speech, self-harm",
            "threat": "Illegal/harmful content - violates laws and community standards"
        },
        "Custom Rules Detector": {
            "description": "Detects custom organizational patterns and policies",
            "threat": "Policy violation - organization-specific security rules triggered"
        }
    }

    def __init__(self):
        pass

    def generate_report(
        self,
        decision,  # FirewallDecision object
        risk_score_breakdown,  # RiskScoreBreakdown object
        session_info: Optional[Dict] = None,
        workspace_id: str = "default",
        policy_name: str = "balanced"
    ) -> ExplainabilityReport:
        """
        Generate comprehensive explainability report for a decision.
        
        Args:
            decision: FirewallDecision from orchestrator
            risk_score_breakdown: RiskScoreBreakdown from risk_scorer
            session_info: Optional session context
            workspace_id: Workspace this decision was made in
            policy_name: Policy profile used
            
        Returns:
            ExplainabilityReport with full reasoning and recommendations
        """
        
        timestamp = datetime.now().isoformat()
        triggered = decision.triggered_agents
        
        # Build executive summary
        executive_summary = self._generate_executive_summary(
            decision.action,
            decision.severity,
            risk_score_breakdown.risk_level,
            triggered
        )
        
        # Build agent details
        agent_details = self._generate_agent_details(decision.agent_results)
        
        # Build decision rationale
        decision_rationale = self._generate_decision_rationale(
            decision,
            risk_score_breakdown,
            agent_details
        )
        
        # Extract contributing factors
        contributing_factors = self._extract_contributing_factors(
            decision,
            agent_details
        )
        
        # Extract mitigating factors
        mitigating_factors = self._extract_mitigating_factors(
            decision,
            agent_details
        )
        
        # Session context
        session_context = self._extract_session_context(session_info) if session_info else None
        
        # Confidence level
        confidence = self._assess_confidence(decision, agent_details)
        
        # Recommendations
        recommendations = self._generate_recommendations(
            decision.action,
            decision.severity,
            triggered,
            confidence
        )
        
        # Metadata
        metadata = {
            "workspace": workspace_id,
            "policy": policy_name,
            "scan_target": decision.scan_target,
            "processing_time_ms": decision.processing_time_ms,
            "from_cache": decision.from_cache,
            "degraded_mode": decision.degraded
        }
        if hasattr(decision, "session_id"):
            metadata["session_id"] = decision.session_id
        
        return ExplainabilityReport(
            timestamp=timestamp,
            overall_action=decision.action,
            risk_score=risk_score_breakdown.overall_score,
            severity=decision.severity,
            executive_summary=executive_summary,
            triggered_agents=triggered,
            agent_details=agent_details,
            session_context=session_context,
            decision_rationale=decision_rationale,
            contributing_factors=contributing_factors,
            mitigating_factors=mitigating_factors,
            recommended_actions=recommendations,
            confidence_level=confidence,
            metadata=metadata
        )

    def _generate_executive_summary(
        self,
        action: str,
        severity: str,
        risk_level: str,
        triggered_agents: List[str]
    ) -> str:
        """Generate concise one-paragraph summary"""
        
        severity_desc = self.THREAT_SEVERITY_NARRATIVES.get(
            severity, "Unknown severity"
        )
        
        if action == "ALLOW":
            return f"✓ ALLOWED: All security detectors passed. {severity_desc}"
        
        agent_count = len(triggered_agents)
        agent_names = ", ".join(triggered_agents[:2])
        if agent_count > 2:
            agent_names += f" and {agent_count - 2} more"
        
        templates = {
            "BLOCK": f"✕ BLOCKED: {severity_desc} {agent_count} detector(s) flagged this: {agent_names}.",
            "FLAG": f"⚑ FLAGGED: {severity_desc} {agent_count} detector(s) raised concerns: {agent_names}.",
            "REDACT": f"⬛ REDACT: {severity_desc} Sensitive content detected by: {agent_names}."
        }
        
        return templates.get(action, f"{action}: {severity_desc}")

    def _generate_agent_details(self, agent_results: List) -> List[Dict]:
        """Generate detailed breakdown per triggered agent"""
        
        details = []
        for result in agent_results:
            if not result.threat_found:
                continue
            
            agent_name = result.agent_name
            narrative = self.AGENT_NARRATIVES.get(agent_name, {})
            
            detail = {
                "agent": agent_name,
                "severity": result.severity,
                "threat_type": result.threat_type,
                "summary": result.summary,
                "description": narrative.get("description", ""),
                "threat_implication": narrative.get("threat", ""),
                "confidence": "High" if result.severity in ["CRITICAL", "HIGH"] else "Medium" if result.severity == "MEDIUM" else "Low",
                "match_count": len(result.matched) if hasattr(result, 'matched') else 0,
                "available": result.agent_available
            }
            
            # Add sample matches
            if hasattr(result, 'matched') and result.matched:
                sample_matches = []
                for match in result.matched[:3]:
                    match_type = (
                        getattr(match, 'pii_type', None) or
                        getattr(match, 'secret_type', None) or
                        getattr(match, 'abuse_type', None) or
                        getattr(match, 'injection_type', None) or
                        getattr(match, 'content_type', None) or
                        "unknown"
                    )
                    sample_matches.append(match_type)
                
                detail["sample_matches"] = sample_matches
            
            details.append(detail)
        
        return details

    def _generate_decision_rationale(
        self,
        decision,
        risk_breakdown,
        agent_details: List[Dict]
    ) -> str:
        """Generate detailed reasoning for the decision"""
        
        parts = [f"DECISION: {decision.action}\n\n"]
        
        # Severity reasoning
        parts.append(f"Overall Severity: {decision.severity}\n")
        parts.append(f"Risk Score: {risk_breakdown.overall_score:.1f}/100 ({risk_breakdown.risk_level})\n\n")
        
        # Contributing factors explanation
        parts.append("Decision Components:\n")
        parts.append(f"  • Severity Impact: {risk_breakdown.severity_score:.1f} points\n")
        parts.append(f"  • Detector Confidence: {risk_breakdown.agent_confidence:.0%}\n")
        parts.append(f"  • Pattern Complexity: {len(decision.triggered_agents)} agents triggered\n")
        
        if risk_breakdown.session_history_score > 0:
            parts.append(f"  • Session History Risk: {risk_breakdown.session_history_score:.1f} points\n")
        
        # Per-agent reasoning
        if agent_details:
            parts.append("\nTriggered Detectors:\n")
            for detail in agent_details:
                parts.append(f"  • {detail['agent']}: {detail['threat_type']}\n")
                parts.append(f"    └─ {detail['summary'][:80]}{'...' if len(detail['summary']) > 80 else ''}\n")
        
        # Policy application
        parts.append(f"\nPolicy Applied: Using '{decision.policy_profile}' profile\n")
        parts.append(f"Recommendation: {decision.reason}\n")
        
        return "".join(parts)

    def _extract_contributing_factors(
        self,
        decision,
        agent_details: List[Dict]
    ) -> List[str]:
        """Extract key factors that led to this decision"""
        
        factors = []
        
        # Severity factors
        if decision.severity == "CRITICAL":
            factors.append(f"🔴 Critical severity level assigned")
        elif decision.severity == "HIGH":
            factors.append(f"🟠 High severity level assigned")
        elif decision.severity == "MEDIUM":
            factors.append(f"🟡 Medium severity level assigned")
        
        # Agent factors
        for detail in agent_details:
            threat = detail.get('threat_type', 'Threat')
            factors.append(f"→ {detail['agent']} detected {threat}")
        
        # Action-specific factors
        if decision.action == "BLOCK":
            factors.append("Content meets threshold for blocking")
        elif decision.action == "REDACT":
            factors.append("Sensitive content requires redaction")
        elif decision.action == "FLAG":
            factors.append("Content requires human review")
        
        return factors

    def _extract_mitigating_factors(
        self,
        decision,
        agent_details: List[Dict]
    ) -> List[str]:
        """Extract factors that prevented a harsher decision"""
        
        mitigating = []
        
        # Check for clean agents
        if not decision.triggered_agents:
            mitigating.append("✓ All detectors passed")
        
        # Check for false positive patterns
        if decision.severity in ["LOW", "NONE"]:
            mitigating.append("Low confidence - likely safe")
        
        # Policy allowlisting
        if "allowlist" in decision.reason.lower():
            mitigating.append("Content matches allowlist patterns")
        
        # Session history
        if "Multi-turn" not in decision.reason and "session" not in decision.reason.lower():
            mitigating.append("Isolated incident - no escalation pattern")
        
        return mitigating if mitigating else ["No mitigating factors present"]

    def _extract_session_context(self, session_info: Dict) -> Dict:
        """Extract relevant session history context"""
        
        if not session_info:
            return None
        
        return {
            "session_id": session_info.get("session_id", ""),
            "message_count": session_info.get("message_count", 0),
            "threat_count": session_info.get("threat_count", 0),
            "cumulative_score": session_info.get("cumulative_score", 0.0),
            "risk_status": "ELEVATED" if session_info.get("cumulative_score", 0) > 5 else "NORMAL",
            "recent_actions": session_info.get("recent_actions", [])[:5]
        }

    def _assess_confidence(self, decision, agent_details: List[Dict]) -> str:
        """Assess overall confidence in this decision"""
        
        if not decision.triggered_agents:
            return "HIGH"  # High confidence in ALLOW with no triggers
        
        # High confidence if multiple strong detectors agree
        if len(agent_details) >= 2:
            return "HIGH"
        
        # Medium if single detector with high severity
        if len(agent_details) == 1 and decision.severity in ["CRITICAL", "HIGH"]:
            return "MEDIUM"
        
        # Low if ambiguous signals
        return "LOW"

    def _generate_recommendations(
        self,
        action: str,
        severity: str,
        triggered_agents: List[str],
        confidence: str
    ) -> List[str]:
        """Generate specific, actionable recommendations"""
        
        recommendations = []
        
        # Action-based recommendations
        recommend_map = {
            "BLOCK": [
                "🔴 Immediately block this input",
                "Alert security team if pattern repeats",
                "Review user/session for suspicious activity",
                "Consider implementing temporary rate limiting"
            ],
            "REDACT": [
                "⬛ Redact sensitive data before sending to user",
                "Log redaction for audit purposes",
                "Investigate why sensitive data appeared in response",
                "Review data handling procedures"
            ],
            "FLAG": [
                "⚑ Escalate to human review queue",
                "Collect context before proceeding",
                "Monitor for pattern escalation",
                "Document decision for ML training"
            ],
            "ALLOW": [
                "✓ Allow with standard monitoring",
                "Log for baseline comparison",
                "Alert if similar content appears repeatedly"
            ]
        }
        
        recommendations.extend(recommend_map.get(action, []))
        
        # Confidence-based recommendations
        if confidence == "LOW":
            recommendations.append("⚠️ Low confidence - recommend manual review before action")
        
        # Threat-specific recommendations
        if "Secrets Detector" in triggered_agents:
            recommendations.append("🔑 Rotate exposed secrets immediately")
        
        if "Injection Detector" in triggered_agents:
            recommendations.append("💉 Block session and review for additional injection attempts")
        
        if "PII Detector" in triggered_agents:
            recommendations.append("👤 Verify user consent for PII handling")
        
        return recommendations

    def to_json(self, report: ExplainabilityReport) -> str:
        """Convert report to JSON for logging/API"""
        report_dict = asdict(report)
        return json.dumps(report_dict, indent=2, default=str)

    def to_markdown(self, report: ExplainabilityReport) -> str:
        """Convert report to markdown for readability"""
        
        lines = [
            f"# Firewall Decision Report",
            f"**Generated:** {report.timestamp}",
            f"**Decision:** `{report.overall_action}`",
            f"**Severity:** {report.severity}",
            f"**Risk Score:** {report.risk_score:.1f}/100 ({report.risk_level})",
            f"**Confidence:** {report.confidence_level}",
            "",
            "## Executive Summary",
            report.executive_summary,
            "",
            "## Decision Analysis",
            report.decision_rationale,
            "",
            "## Contributing Factors",
        ]
        
        for factor in report.contributing_factors:
            lines.append(f"  - {factor}")
        
        if report.mitigating_factors:
            lines.append("\n## Mitigating Factors")
            for factor in report.mitigating_factors:
                lines.append(f"  - {factor}")
        
        lines.append("\n## Recommendations")
        for rec in report.recommended_actions:
            lines.append(f"  - {rec}")
        
        if report.session_context:
            lines.append("\n## Session Context")
            lines.append(f"  - Messages: {report.session_context.get('message_count')}")
            lines.append(f"  - Threats Detected: {report.session_context.get('threat_count')}")
            lines.append(f"  - Risk Status: {report.session_context.get('risk_status')}")
        
        return "\n".join(lines)
