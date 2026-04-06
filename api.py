from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address
from typing import List, Optional
import uvicorn

from api_app.routes import (
    build_firewall_router,
    build_general_router,
    build_rules_policies_feedback_router,
    build_sessions_audit_router,
    build_threat_intel_router,
    build_workspaces_router,
)
from api_app.schemas import AgentResultResponse, AnalyzeResponse
from orchestrator.custom_rules import CustomRulesManager
from orchestrator.document_extractor import DocumentExtractor
from orchestrator.orchestrator import SemanticFirewallOrchestrator
from orchestrator.threat_intel import ThreatIntelFeedManager
from orchestrator.workspace_store import WorkspaceStore


# â”€â”€ App setup â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app = FastAPI(
    title="Semantic Firewall API",
    description="An agentic LLM-based semantic firewall for safe & privacy-preserving AI systems.",
    version="1.0.0",
)
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# Allow all origins (for development â€” restrict in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize orchestrator once at startup
firewall = SemanticFirewallOrchestrator()
rules_manager = CustomRulesManager()
document_extractor = DocumentExtractor()
workspace_store = WorkspaceStore()
threat_intel_manager = ThreatIntelFeedManager()

def _confidence_score(agent_result) -> Optional[float]:
    scores = [
        getattr(match, "confidence", None)
        for match in getattr(agent_result, "matched", [])
        if getattr(match, "confidence", None) is not None
    ]
    if not scores:
        return None
    return round(max(scores), 2)


def _match_label(match) -> str:
    return (
        getattr(match, "pii_type", None)
        or getattr(match, "secret_type", None)
        or getattr(match, "abuse_type", None)
        or getattr(match, "injection_type", None)
        or getattr(match, "content_type", None)
        or getattr(match, "intel_type", None)
        or getattr(match, "custom_type", None)
        or "unknown"
    )


def _build_top_findings(decision, limit: int = 8) -> List[dict]:
    findings: List[dict] = []
    for result in decision.agent_results:
        if not getattr(result, "threat_found", False):
            continue
        for match in getattr(result, "matched", [])[:3]:
            findings.append(
                {
                    "agent_name": result.agent_name,
                    "category": result.threat_type,
                    "label": _match_label(match),
                    "severity": result.severity,
                    "confidence": getattr(match, "confidence", None),
                    "evidence": (
                        getattr(match, "evidence", None)
                        or getattr(match, "value", "")
                    )[:80],
                }
            )
    findings.sort(
        key=lambda item: (
            {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}.get(item["severity"], 0),
            item["confidence"] or 0.0,
        ),
        reverse=True,
    )
    return findings[:limit]


def build_analyze_response(decision, redacted_text_override=None):
    # Convert explainability report to dict if present
    explanation_dict = None
    if hasattr(decision, 'explanation') and decision.explanation:
        from dataclasses import asdict
        try:
            explanation_dict = asdict(decision.explanation)
        except Exception as e:
            print(f"[API] Failed to serialize explainability report: {e}")
    
    return AnalyzeResponse(
        action=decision.action,
        severity=decision.severity,
        reason=decision.reason,
        scan_target=decision.scan_target,
        policy_profile=getattr(decision, "policy_profile", "balanced"),
        triggered_agents=decision.triggered_agents,
        agent_results=[
            AgentResultResponse(
                agent_name=r.agent_name,
                threat_found=r.threat_found,
                threat_type=r.threat_type,
                severity=r.severity,
                summary=r.summary,
                agent_available=r.agent_available,
                confidence_score=_confidence_score(r),
            )
            for r in decision.agent_results
        ],
        top_findings=_build_top_findings(decision),
        redacted_text=redacted_text_override,
        processing_time_ms=decision.processing_time_ms,
        original_text=decision.original_text,
        degraded=decision.degraded,
        unavailable_agents=decision.unavailable_agents,
        risk_score=getattr(decision, "risk_score", 0.0),
        risk_level=getattr(decision, "risk_level", "NONE"),
        explanation=explanation_dict,
        detected_patterns=getattr(decision, "detected_patterns", []),
    )


app.include_router(build_general_router(lambda: firewall))
app.include_router(build_firewall_router(limiter, lambda: firewall, build_analyze_response, document_extractor))
app.include_router(build_sessions_audit_router(lambda: firewall))
app.include_router(build_workspaces_router(workspace_store))
app.include_router(build_threat_intel_router(threat_intel_manager))
app.include_router(build_rules_policies_feedback_router(lambda: firewall, rules_manager))


if __name__ == "__main__":
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)







