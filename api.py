import base64
import binascii
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from slowapi import Limiter
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address
from typing import List, Optional
import time
import uvicorn

from agents.custom_rules_detector import CustomRulesDetectorAgent
from orchestrator.custom_rules import CustomRulesManager
from orchestrator.document_extractor import DocumentExtractionError, DocumentExtractor
from orchestrator.orchestrator import InteractionDecision, SemanticFirewallOrchestrator
from orchestrator.threat_intel import ThreatIntelFeedManager
from orchestrator.workspace_store import WorkspaceStore


# ── App setup ──────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Semantic Firewall API",
    description="An agentic LLM-based semantic firewall for safe & privacy-preserving AI systems.",
    version="1.0.0",
)
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# Allow all origins (for development — restrict in production)
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

# Thread safety lock for batch operations
batch_analysis_lock = Lock()


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


# ── Request / Response Models ──────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=100_000,
                      description="The text to analyze")
    session_id: Optional[str] = Field(
        None, description="Session ID for multi-turn conversation tracking"
    )
    redact_on_flag: Optional[bool] = Field(
        False, description="If True, also redact PII/secrets even on FLAG decisions"
    )
    policy_profile: str = Field("balanced", min_length=1, max_length=100)
    workspace_id: str = Field("default", min_length=1, max_length=100)


class AgentResultResponse(BaseModel):
    agent_name: str
    threat_found: bool
    threat_type: str
    severity: str
    summary: str
    agent_available: bool
    confidence_score: Optional[float]


class AnalyzeResponse(BaseModel):
    action: str
    severity: str
    reason: str
    scan_target: str
    policy_profile: str
    triggered_agents: List[str]
    agent_results: List[AgentResultResponse]
    top_findings: List[dict]
    redacted_text: Optional[str]
    processing_time_ms: float
    original_text: str
    degraded: bool
    unavailable_agents: List[str]
    risk_score: float = 0.0
    risk_level: str = "NONE"
    explanation: Optional[dict] = None
    detected_patterns: List[dict] = []


class InteractionAnalyzeResponse(BaseModel):
    combined_action: str
    combined_severity: str
    combined_reason: str
    triggered_agents: List[str]
    interaction_alerts: List[dict]
    drift_detected: bool
    contradiction_detected: bool
    session_risk_score: float
    prompt_decision: AnalyzeResponse
    output_decision: AnalyzeResponse


class DocumentAnalyzeResponse(BaseModel):
    filename: str
    extension: str
    extracted_char_count: int
    truncated: bool
    extraction_mode: str
    extraction_quality: str
    warnings: List[str]
    decision: AnalyzeResponse


class DocumentAnalyzeRequest(BaseModel):
    filename: str = Field(..., min_length=1, max_length=300)
    content_base64: str = Field(..., min_length=1)
    scan_target: str = Field("input", pattern="^(input|output)$")
    policy_profile: str = Field("balanced", min_length=1, max_length=100)
    redact_on_flag: bool = False
    workspace_id: str = Field("default", min_length=1, max_length=100)


class HealthResponse(BaseModel):
    status: str
    agents_loaded: int
    version: str


class RedactRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=100_000,
                      description="The text to redact PII and secrets from")


class RedactResponse(BaseModel):
    original_text: str
    redacted_text: str
    processing_time_ms: float


class OutputAnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=100_000,
                      description="The model output text to analyze")
    policy_profile: str = Field("balanced", min_length=1, max_length=100)
    workspace_id: str = Field("default", min_length=1, max_length=100)


class InteractionAnalyzeRequest(BaseModel):
    prompt_text: str = Field(..., min_length=1, max_length=100_000)
    output_text: str = Field(..., min_length=1, max_length=100_000)
    session_id: Optional[str] = None
    policy_profile: str = Field("balanced", min_length=1, max_length=100)
    workspace_id: str = Field("default", min_length=1, max_length=100)


class FeedbackRequest(BaseModel):
    audit_log_id: int
    feedback_type: str = Field(..., description="false_positive or false_negative")
    notes: Optional[str] = Field("", description="Optional reviewer note")


class CustomRuleRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    pattern: str = Field(..., min_length=1, max_length=500)
    description: str = Field(..., min_length=1, max_length=200)
    severity: str = Field(..., pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    threat_type: str = Field("CUSTOM_RULE", min_length=1, max_length=50)
    scope: str = Field("both", pattern="^(input|output|both)$")
    redact: bool = False
    exceptions: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    workspace_id: str = Field("global", min_length=1, max_length=100)


class RuleUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    pattern: Optional[str] = Field(None, min_length=1, max_length=500)
    description: Optional[str] = Field(None, min_length=1, max_length=200)
    severity: Optional[str] = Field(None, pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    threat_type: Optional[str] = Field(None, min_length=1, max_length=50)
    scope: Optional[str] = Field(None, pattern="^(input|output|both)$")
    redact: Optional[bool] = None
    enabled: Optional[bool] = None
    exceptions: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    workspace_id: Optional[str] = Field(None, min_length=1, max_length=100)


class RuleTestRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=100_000)
    scan_target: str = Field("both", pattern="^(input|output|both)$")
    rule: Optional[CustomRuleRequest] = None
    rule_id: Optional[str] = None


class BatchAnalyzeRequest(BaseModel):
    texts: List[str] = Field(..., min_length=1, max_length=20)
    scan_target: str = Field("input", pattern="^(input|output)$")
    policy_profile: str = Field("balanced", min_length=1, max_length=100)
    workspace_id: str = Field("default", min_length=1, max_length=100)


class SessionSummaryResponse(BaseModel):
    session_id: str
    message_count: int
    cumulative_score: float
    should_flag: bool
    should_block: bool


class ReviewStatusRequest(BaseModel):
    review_status: str = Field(..., pattern="^(pending|reviewed_true_positive|reviewed_false_positive|reviewed_false_negative|dismissed)$")
    review_assignee: str = Field("", max_length=200)
    review_notes: str = Field("", max_length=500)


class PolicyPresetRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: str = Field("", max_length=300)
    action_overrides: dict = Field(default_factory=dict)
    session_flag_threshold: float = Field(8.0, ge=0.0, le=100.0)
    session_block_threshold: float = Field(12.0, ge=0.0, le=100.0)
    allowlist_patterns: List[str] = Field(default_factory=list)
    allowlist_max_severity: str = Field("LOW", pattern="^(NONE|LOW|MEDIUM|HIGH|CRITICAL)$")
    enabled: bool = True
    workspace_id: str = Field("global", min_length=1, max_length=100)


class PromotionRequest(BaseModel):
    note: str = Field("", max_length=500)
    workspace_id: str = Field("default", min_length=1, max_length=100)


class ApprovalRequest(BaseModel):
    actor: str = Field(..., min_length=1, max_length=200)
    workspace_id: str = Field("global", min_length=1, max_length=100)


class WorkspaceRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: str = Field("", max_length=300)
    owner: str = Field("", max_length=200)


class ThreatIntelEntryRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    pattern: str = Field(..., min_length=1, max_length=1000)
    category: str = Field("INJECTION", min_length=1, max_length=100)
    severity: str = Field("HIGH", pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    scope: str = Field("both", pattern="^(input|output|both)$")
    description: str = Field("", max_length=500)
    source: str = Field("manual", max_length=200)
    tags: List[str] = Field(default_factory=list)
    enabled: bool = True


class ThreatIntelUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    pattern: Optional[str] = Field(None, min_length=1, max_length=1000)
    category: Optional[str] = Field(None, min_length=1, max_length=100)
    severity: Optional[str] = Field(None, pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    scope: Optional[str] = Field(None, pattern="^(input|output|both)$")
    description: Optional[str] = Field(None, max_length=500)
    source: Optional[str] = Field(None, max_length=200)
    tags: Optional[List[str]] = None
    enabled: Optional[bool] = None


class ThreatIntelSyncRequest(BaseModel):
    url: str = Field(..., min_length=8, max_length=1000)
    timeout_seconds: int = Field(8, ge=1, le=30)


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/", tags=["General"])
def root():
    return {
        "message": "Semantic Firewall API is running.",
        "docs": "/docs",
        "health": "/health",
        "endpoints": [
            "/analyze",
            "/analyze/output",
            "/analyze/interaction",
            "/analyze/document",
            "/redact",
            "/rules",
            "/feedback",
            "/health",
        ],
        "advanced_endpoints": [
            "/analyze/batch",
            "/rules/test",
            "/policies",
            "/review-queue",
            "/sessions/{session_id}",
        ]
    }


@app.get("/health", response_model=HealthResponse, tags=["General"])
def health_check():
    """Check if the API and all agents are running."""
    return HealthResponse(
        status="healthy",
        agents_loaded=len(firewall.agents),
        version="1.0.0"
    )


@app.post("/analyze", response_model=AnalyzeResponse, tags=["Firewall"])
@limiter.limit("30/minute")
def analyze(request: Request, body: AnalyzeRequest):
    """
    Analyze text through all 5 firewall agents in parallel.

    Returns a decision: ALLOW / FLAG / REDACT / BLOCK
    along with detailed results from each agent.
    """
    try:
        decision = firewall.analyze(
            body.text,
            session_id=body.session_id,
            policy_profile=body.policy_profile,
            workspace_id=body.workspace_id,
        )

        # If redact_on_flag is True, also redact on FLAG decisions
        redacted = decision.redacted_text
        if body.redact_on_flag and decision.action == "FLAG":
            redacted = firewall._get_redacted_text(body.text, decision.agent_results)

        return build_analyze_response(
            decision,
            redacted_text_override=redacted if (
                decision.action in ["REDACT", "BLOCK"]
                or (body.redact_on_flag and decision.action == "FLAG")
            ) else None,
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Firewall analysis failed: {str(e)}")


@app.post("/analyze/output", response_model=AnalyzeResponse, tags=["Firewall"])
def analyze_output(request: OutputAnalyzeRequest):
    """
    Analyze model output text through all 5 firewall agents in parallel.

    Useful for scanning LLM responses before returning them to end users.
    """
    try:
        decision = firewall.analyze_output(
            request.text,
            policy_profile=request.policy_profile,
            workspace_id=request.workspace_id,
        )

        return build_analyze_response(
            decision,
            redacted_text_override=decision.redacted_text if decision.action in ["REDACT", "BLOCK"] else None,
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Output firewall analysis failed: {str(e)}")


@app.post("/analyze/interaction", response_model=InteractionAnalyzeResponse, tags=["Firewall"])
@limiter.limit("20/minute")
def analyze_interaction(request: Request, body: InteractionAnalyzeRequest):
    try:
        interaction = firewall.analyze_interaction(
            prompt_text=body.prompt_text,
            output_text=body.output_text,
            session_id=body.session_id,
            policy_profile=body.policy_profile,
            workspace_id=body.workspace_id,
        )
        return InteractionAnalyzeResponse(
            combined_action=interaction.combined_action,
            combined_severity=interaction.combined_severity,
            combined_reason=interaction.combined_reason,
            triggered_agents=interaction.triggered_agents,
            interaction_alerts=interaction.interaction_alerts,
            drift_detected=interaction.drift_detected,
            contradiction_detected=interaction.contradiction_detected,
            session_risk_score=interaction.session_risk_score,
            prompt_decision=build_analyze_response(
                interaction.prompt_decision,
                redacted_text_override=(
                    interaction.prompt_decision.redacted_text
                    if interaction.prompt_decision.action in ["REDACT", "BLOCK"]
                    else None
                ),
            ),
            output_decision=build_analyze_response(
                interaction.output_decision,
                redacted_text_override=(
                    interaction.output_decision.redacted_text
                    if interaction.output_decision.action in ["REDACT", "BLOCK"]
                    else None
                ),
            ),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Interaction firewall analysis failed: {str(e)}")


@app.post("/redact", response_model=RedactResponse, tags=["Firewall"])
def redact(request: RedactRequest):
    """
    Redact all detected PII and secrets from text without blocking.
    Useful for sanitizing text before storing or displaying it.
    """
    try:
        start = time.time()

        # Run only the rule-based agents for redaction (no LLM needed)
        pii_agent     = firewall.agents["PII Detector"]
        secrets_agent = firewall.agents["Secrets Detector"]

        redacted = request.text
        redacted = pii_agent.redact(redacted)
        redacted = secrets_agent.redact(redacted)

        elapsed = (time.time() - start) * 1000

        return RedactResponse(
            original_text=request.text,
            redacted_text=redacted,
            processing_time_ms=elapsed,
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Redaction failed: {str(e)}")


@app.get("/rules", tags=["Rules"])
def list_rules(workspace_id: Optional[str] = None):
    return {"rules": rules_manager.list_rules(workspace_id=workspace_id)}


@app.get("/rules/drafts", tags=["Rules"])
def list_rule_drafts(workspace_id: Optional[str] = None):
    return {"drafts": rules_manager.list_drafts(workspace_id=workspace_id)}


@app.get("/rules/drafts/{rule_id}/preview", tags=["Rules"])
def preview_rule_draft(rule_id: str, workspace_id: Optional[str] = None):
    preview = rules_manager.preview_draft_diff(rule_id)
    if preview and workspace_id and preview["draft"].get("workspace_id", "global") not in {"global", workspace_id}:
        preview = None
    if not preview:
        raise HTTPException(status_code=404, detail="Rule draft not found")
    return preview


@app.get("/policies", tags=["Policies"])
def list_policies(workspace_id: Optional[str] = None):
    return {"presets": firewall.list_policy_presets(workspace_id=workspace_id)}


@app.get("/policies/drafts", tags=["Policies"])
def list_policy_drafts(workspace_id: Optional[str] = None):
    return {"drafts": firewall.list_policy_drafts(workspace_id=workspace_id)}


@app.get("/policies/drafts/{name}/preview", tags=["Policies"])
def preview_policy_draft(name: str, workspace_id: Optional[str] = None):
    preview = firewall.preview_policy_draft(name, workspace_id=workspace_id)
    if not preview:
        raise HTTPException(status_code=404, detail="Policy draft not found")
    return preview


@app.post("/policies", tags=["Policies"])
def save_policy(request: PolicyPresetRequest):
    try:
        preset = firewall.save_policy_preset(**request.model_dump())
        return {"preset": preset}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to save policy preset: {str(e)}")


@app.delete("/policies/{name}", tags=["Policies"])
def delete_policy(name: str, workspace_id: Optional[str] = None):
    deleted = firewall.delete_policy_preset(name, workspace_id=workspace_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Policy preset not found or cannot be deleted")
    return {"deleted": True, "name": name}


@app.post("/policies/{name}/promote", tags=["Policies"])
def promote_policy(name: str, request: PromotionRequest):
    promoted = firewall.promote_policy_draft(name, note=request.note, workspace_id=request.workspace_id)
    if not promoted:
        raise HTTPException(status_code=404, detail="Policy draft not found")
    return {"preset": promoted}


@app.post("/rules", tags=["Rules"])
def create_rule(request: CustomRuleRequest):
    try:
        rule = rules_manager.add_rule(
            name=request.name,
            pattern=request.pattern,
            description=request.description,
            severity=request.severity,
            threat_type=request.threat_type,
            scope=request.scope,
            redact=request.redact,
            exceptions=request.exceptions,
            tags=request.tags,
            workspace_id=request.workspace_id,
        )
        return {"rule": rule}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to create rule: {str(e)}")


@app.put("/rules/{rule_id}", tags=["Rules"])
def update_rule(rule_id: str, request: RuleUpdateRequest):
    updates = {key: value for key, value in request.model_dump().items() if value is not None}
    updated = rules_manager.update_rule(rule_id, **updates)
    if not updated:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"rule": updated}


@app.post("/rules/test", tags=["Rules"])
def test_rule(request: RuleTestRequest):
    try:
        if request.rule_id:
            rules = rules_manager.list_rules()
            rule = next((item for item in rules if item["id"] == request.rule_id), None)
            if not rule:
                raise HTTPException(status_code=404, detail="Rule not found")
        elif request.rule:
            rule = {
                "id": "preview",
                "name": request.rule.name,
                "pattern": request.rule.pattern,
                "description": request.rule.description,
                "severity": request.rule.severity,
                "threat_type": request.rule.threat_type,
                "scope": request.rule.scope,
                "redact": request.rule.redact,
                "enabled": True,
                "exceptions": request.rule.exceptions,
                "tags": request.rule.tags,
            }
        else:
            raise HTTPException(status_code=400, detail="Provide either rule_id or rule.")

        tester = CustomRulesDetectorAgent()
        result = tester.test_rule(rule, request.text)
        return {
            "rule_id": rule["id"],
            "rule_name": rule["name"],
            "scan_target": request.scan_target,
            **result,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to test rule: {str(e)}")


@app.delete("/rules/{rule_id}", tags=["Rules"])
def delete_rule(rule_id: str):
    deleted = rules_manager.delete_rule(rule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"deleted": True, "rule_id": rule_id}


@app.post("/feedback", tags=["Feedback"])
def submit_feedback(request: FeedbackRequest):
    feedback_type = request.feedback_type.strip().lower()
    if feedback_type not in {"false_positive", "false_negative"}:
        raise HTTPException(status_code=400, detail="feedback_type must be false_positive or false_negative")

    firewall.audit_logger.submit_feedback(
        audit_log_id=request.audit_log_id,
        feedback_type=feedback_type,
        notes=request.notes or "",
    )
    return {"submitted": True}


@app.get("/feedback/insights", tags=["Feedback"])
def feedback_insights(workspace_id: Optional[str] = None):
    try:
        return firewall.audit_logger.get_feedback_insights(workspace_id=workspace_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get feedback insights: {str(e)}")


@app.get("/feedback/adjustments", tags=["Feedback"])
def feedback_adjustments(limit: int = 8, workspace_id: Optional[str] = None):
    # Validate limit parameter
    if limit < 1 or limit > 50:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 50")
    try:
        return {
            "adjustments": firewall.audit_logger.suggest_policy_adjustments(limit=limit, workspace_id=workspace_id),
            "timeline": firewall.audit_logger.get_reviewer_timeline(workspace_id=workspace_id),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get feedback adjustments: {str(e)}")


@app.post("/feedback/adjustments/draft", tags=["Feedback"])
def create_policy_draft_from_adjustment(index: int = 0, limit: int = 8, workspace_id: str = "default"):
    if limit < 1 or limit > 50:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 50")
    if index < 0:
        raise HTTPException(status_code=400, detail="index must be >= 0")
    try:
        adjustments = firewall.audit_logger.suggest_policy_adjustments(limit=limit, workspace_id=workspace_id)
        if index >= len(adjustments):
            raise HTTPException(status_code=404, detail="Adjustment suggestion not found")
        draft = firewall.create_policy_draft_from_adjustment(adjustments[index], workspace_id=workspace_id)
        return {"draft": draft}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create policy draft: {str(e)}")


@app.get("/rules/suggestions", tags=["Rules"])
def suggest_rules(limit: int = 5, workspace_id: Optional[str] = None):
    if limit < 1 or limit > 50:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 50")
    try:
        return {"suggestions": firewall.audit_logger.suggest_rules_from_feedback(limit=limit, workspace_id=workspace_id)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get rule suggestions: {str(e)}")


@app.post("/rules/suggestions/draft", tags=["Rules"])
def create_draft_from_suggestion(index: int = 0, limit: int = 10, workspace_id: str = "default"):
    if limit < 1 or limit > 50:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 50")
    if index < 0:
        raise HTTPException(status_code=400, detail="index must be >= 0")
    try:
        suggestions = firewall.audit_logger.suggest_rules_from_feedback(limit=limit, workspace_id=workspace_id)
        if index >= len(suggestions):
            raise HTTPException(status_code=404, detail="Suggestion not found")
        draft = rules_manager.create_draft_from_suggestion(suggestions[index], workspace_id=workspace_id)
        return {"draft": draft}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create rule draft: {str(e)}")


@app.post("/rules/{rule_id}/request-approval", tags=["Rules"])
def request_rule_approval(rule_id: str, request: ApprovalRequest):
    draft = rules_manager.request_approval(rule_id, request.actor)
    if not draft:
        raise HTTPException(status_code=404, detail="Rule draft not found")
    return {"draft": draft}


@app.post("/rules/{rule_id}/approve", tags=["Rules"])
def approve_rule_draft(rule_id: str, request: ApprovalRequest):
    try:
        draft = rules_manager.approve_draft(rule_id, request.actor)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not draft:
        raise HTTPException(status_code=404, detail="Rule draft not found")
    return {"draft": draft}


@app.post("/rules/{rule_id}/promote", tags=["Rules"])
def promote_rule(rule_id: str, request: PromotionRequest):
    promoted = rules_manager.promote_draft(rule_id)
    if not promoted:
        raise HTTPException(status_code=404, detail="Rule not found")
    firewall.audit_logger.log_promotion(
        item_type="rule",
        item_id=promoted["id"],
        item_name=promoted["name"],
        note=request.note,
        metadata={"severity": promoted.get("severity"), "scope": promoted.get("scope")},
        workspace_id=request.workspace_id,
    )
    return {"rule": promoted}


@app.post("/policies/{name}/request-approval", tags=["Policies"])
def request_policy_approval(name: str, request: ApprovalRequest):
    draft = firewall.request_policy_approval(name, request.actor, workspace_id=request.workspace_id)
    if not draft:
        raise HTTPException(status_code=404, detail="Policy draft not found")
    return {"draft": draft}


@app.post("/policies/{name}/approve", tags=["Policies"])
def approve_policy_draft(name: str, request: ApprovalRequest):
    try:
        draft = firewall.approve_policy_draft(name, request.actor, workspace_id=request.workspace_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not draft:
        raise HTTPException(status_code=404, detail="Policy draft not found")
    return {"draft": draft}


@app.get("/review-queue", tags=["Feedback"])
def get_review_queue(
    limit: int = 25,
    severity: Optional[str] = None,
    scan_target: Optional[str] = None,
    workspace_id: Optional[str] = None,
):
    if limit < 1 or limit > 100:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 100")
    if severity and severity not in {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        raise HTTPException(status_code=400, detail="Invalid severity level")
    try:
        return {
            "items": firewall.audit_logger.get_review_queue(
                limit=limit,
                severity=severity,
                scan_target=scan_target,
                workspace_id=workspace_id,
            )
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get review queue: {str(e)}")


@app.get("/review-queue/analytics", tags=["Feedback"])
def get_review_queue_analytics(workspace_id: Optional[str] = None):
    try:
        return firewall.audit_logger.get_review_queue_analytics(workspace_id=workspace_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get review queue analytics: {str(e)}")


@app.post("/review-queue/{audit_log_id}", tags=["Feedback"])
def update_review_queue_item(audit_log_id: int, request: ReviewStatusRequest):
    firewall.audit_logger.set_review_status(
        audit_log_id,
        request.review_status,
        review_assignee=request.review_assignee,
        review_notes=request.review_notes,
    )
    return {
        "updated": True,
        "audit_log_id": audit_log_id,
        "review_status": request.review_status,
        "review_assignee": request.review_assignee,
    }


@app.post("/analyze/batch", tags=["Firewall"])
@limiter.limit("10/minute")
def analyze_batch(request: Request, body: BatchAnalyzeRequest):
    """
    Analyze multiple texts at once.
    Returns a list of decisions in the same order as the input.
    """
    def _analyze_one(text: str) -> dict:
        try:
            if body.scan_target == "input":
                decision = firewall.analyze(
                    text,
                    policy_profile=body.policy_profile,
                    workspace_id=body.workspace_id,
                )
            else:
                decision = firewall.analyze_output(
                    text,
                    policy_profile=body.policy_profile,
                    workspace_id=body.workspace_id,
                )
            return build_analyze_response(
                decision,
                redacted_text_override=decision.redacted_text if decision.action in ["REDACT", "BLOCK"] else None,
            ).model_dump()
        except Exception as e:
            return {"error": str(e), "original_text": text, "scan_target": body.scan_target}

    results = [None] * len(body.texts)
    max_workers = min(len(body.texts), 3)  # Reduced from 5 for safety
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_analyze_one, text): index
                for index, text in enumerate(body.texts)
            }
            for future in as_completed(futures):
                results[futures[future]] = future.result()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Batch analysis failed: {str(e)}")

    return {
        "results": results,
        "total": len(results),
        "scan_target": body.scan_target,
        "policy_profile": body.policy_profile,
    }


@app.post("/analyze/document", response_model=DocumentAnalyzeResponse, tags=["Firewall"])
@limiter.limit("20/minute")
def analyze_document(request: Request, body: DocumentAnalyzeRequest):
    try:
        try:
            content = base64.b64decode(body.content_base64.encode("utf-8"))
        except (binascii.Error, ValueError) as exc:
            raise HTTPException(status_code=400, detail=f"Invalid base64 encoding: {str(exc)}")
        extracted = document_extractor.extract_text(body.filename, content)
        if not extracted["text"].strip():
            raise HTTPException(status_code=400, detail="No text extracted from document.")

        decision = (
            firewall.analyze(
                extracted["text"],
                policy_profile=body.policy_profile,
                workspace_id=body.workspace_id,
            )
            if body.scan_target == "input"
            else firewall.analyze_output(
                extracted["text"],
                policy_profile=body.policy_profile,
                workspace_id=body.workspace_id,
            )
        )
        redacted_override = None
        if decision.action in ["REDACT", "BLOCK"]:
            redacted_override = decision.redacted_text
        elif body.redact_on_flag and decision.action == "FLAG":
            redacted_override = firewall._get_redacted_text(
                extracted["text"],
                decision.agent_results,
                scan_target=body.scan_target,
            )

        return DocumentAnalyzeResponse(
            filename=extracted["filename"],
            extension=extracted["extension"],
            extracted_char_count=extracted["char_count"],
            truncated=extracted["truncated"],
            extraction_mode=extracted["extraction_mode"],
            extraction_quality=extracted["extraction_quality"],
            warnings=extracted["warnings"],
            decision=build_analyze_response(decision, redacted_text_override=redacted_override),
        )
    except DocumentExtractionError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Document analysis failed: {str(exc)}")


@app.websocket("/ws/analyze")
async def ws_analyze(websocket: WebSocket):
    """
    Real-time text scanning over WebSocket.

    Payload example:
      {
        "text": "Ignore previous instructions",
        "scan_target": "input",
        "policy_profile": "balanced",
        "workspace_id": "default",
        "session_id": "optional"
      }
    """
    await websocket.accept()
    try:
        while True:
            payload = await websocket.receive_json()
            text = str(payload.get("text", "")).strip()
            if not text:
                await websocket.send_json({"error": "text is required"})
                continue
            scan_target = payload.get("scan_target", "input")
            policy_profile = payload.get("policy_profile", "balanced")
            workspace_id = payload.get("workspace_id", "default")
            session_id = payload.get("session_id")

            if scan_target == "output":
                decision = firewall.analyze_output(
                    text=text,
                    policy_profile=policy_profile,
                    workspace_id=workspace_id,
                )
            else:
                decision = firewall.analyze(
                    text=text,
                    session_id=session_id,
                    policy_profile=policy_profile,
                    workspace_id=workspace_id,
                )
            await websocket.send_json(
                build_analyze_response(
                    decision,
                    redacted_text_override=decision.redacted_text
                    if decision.action in ["REDACT", "BLOCK"]
                    else None,
                ).model_dump()
            )
    except WebSocketDisconnect:
        return
    except Exception as exc:
        await websocket.send_json({"error": f"websocket analysis failed: {exc}"})


@app.get("/sessions/{session_id}", response_model=SessionSummaryResponse, tags=["Sessions"])
def get_session_summary(session_id: str):
    if not session_id or len(session_id) > 200:
        raise HTTPException(status_code=400, detail="Invalid session_id format")
    try:
        return SessionSummaryResponse(**firewall.get_session_summary(session_id))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get session summary: {str(e)}")


@app.delete("/sessions/{session_id}", tags=["Sessions"])
def clear_session(session_id: str):
    firewall.clear_session(session_id)
    return {"cleared": True, "session_id": session_id}


@app.get("/promotions", tags=["Audit"])
def list_promotions(limit: int = 50, workspace_id: Optional[str] = None):
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 500")
    try:
        return {"items": firewall.get_promotion_history(limit=limit, workspace_id=workspace_id)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get promotion history: {str(e)}")


@app.get("/workspaces", tags=["Workspaces"])
def list_workspaces():
    return {"workspaces": workspace_store.list_workspaces()}


@app.get("/threat-intel", tags=["Threat Intel"])
def list_threat_intel(scan_target: Optional[str] = None, enabled_only: bool = False):
    if scan_target and scan_target not in {"input", "output", "both"}:
        raise HTTPException(status_code=400, detail="scan_target must be input, output, or both")
    normalized_target = None if scan_target in {None, "both"} else scan_target
    return {"entries": threat_intel_manager.list_entries(scan_target=normalized_target, enabled_only=enabled_only)}


@app.post("/threat-intel", tags=["Threat Intel"])
def create_threat_intel_entry(request: ThreatIntelEntryRequest):
    try:
        entry = threat_intel_manager.add_entry(**request.model_dump())
        return {"entry": entry}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to create threat intel entry: {exc}")


@app.put("/threat-intel/{entry_id}", tags=["Threat Intel"])
def update_threat_intel_entry(entry_id: str, request: ThreatIntelUpdateRequest):
    try:
        updates = {key: value for key, value in request.model_dump().items() if value is not None}
        entry = threat_intel_manager.update_entry(entry_id, **updates)
        if not entry:
            raise HTTPException(status_code=404, detail="Threat intel entry not found")
        return {"entry": entry}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to update threat intel entry: {exc}")


@app.delete("/threat-intel/{entry_id}", tags=["Threat Intel"])
def delete_threat_intel_entry(entry_id: str):
    deleted = threat_intel_manager.delete_entry(entry_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Threat intel entry not found")
    return {"deleted": True, "entry_id": entry_id}


@app.post("/threat-intel/sync", tags=["Threat Intel"])
def sync_threat_intel_feed(request: ThreatIntelSyncRequest):
    try:
        result = threat_intel_manager.sync_from_url(
            url=request.url,
            timeout=request.timeout_seconds,
        )
        return {"result": result}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Threat intel sync failed: {exc}")


@app.post("/workspaces", tags=["Workspaces"])
def save_workspace(request: WorkspaceRequest):
    try:
        workspace = workspace_store.save_workspace(
            name=request.name,
            description=request.description,
            owner=request.owner,
        )
        return {"workspace": workspace}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to save workspace: {exc}")


@app.delete("/workspaces/{name}", tags=["Workspaces"])
def delete_workspace(name: str):
    deleted = workspace_store.delete_workspace(name)
    if not deleted:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return {"deleted": True, "name": name}


# ── Run server ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
