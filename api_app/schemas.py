from typing import List, Optional

from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=100_000, description="The text to analyze")
    session_id: Optional[str] = Field(None, description="Session ID for multi-turn conversation tracking")
    redact_on_flag: Optional[bool] = Field(False, description="If True, also redact PII/secrets even on FLAG decisions")
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
    text: str = Field(..., min_length=1, max_length=100_000, description="The text to redact PII and secrets from")


class RedactResponse(BaseModel):
    original_text: str
    redacted_text: str
    processing_time_ms: float


class OutputAnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=100_000, description="The model output text to analyze")
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
    detector_thresholds: dict = Field(default_factory=dict)
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
