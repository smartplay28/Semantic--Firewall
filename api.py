from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional
import time
import uvicorn

from orchestrator.orchestrator import SemanticFirewallOrchestrator


# ── App setup ──────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Semantic Firewall API",
    description="An agentic LLM-based semantic firewall for safe & privacy-preserving AI systems.",
    version="1.0.0",
)

# Allow all origins (for development — restrict in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize orchestrator once at startup
firewall = SemanticFirewallOrchestrator()


# ── Request / Response Models ──────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=100_000,
                      description="The text to analyze")
    redact_on_flag: Optional[bool] = Field(
        False, description="If True, also redact PII/secrets even on FLAG decisions"
    )


class AgentResultResponse(BaseModel):
    agent_name: str
    threat_found: bool
    threat_type: str
    severity: str
    summary: str


class AnalyzeResponse(BaseModel):
    action: str
    severity: str
    reason: str
    triggered_agents: List[str]
    agent_results: List[AgentResultResponse]
    redacted_text: Optional[str]
    processing_time_ms: float
    original_text: str


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


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/", tags=["General"])
def root():
    return {
        "message": "Semantic Firewall API is running.",
        "docs": "/docs",
        "health": "/health",
        "endpoints": ["/analyze", "/redact", "/health"]
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
def analyze(request: AnalyzeRequest):
    """
    Analyze text through all 5 firewall agents in parallel.

    Returns a decision: ALLOW / FLAG / REDACT / BLOCK
    along with detailed results from each agent.
    """
    try:
        decision = firewall.analyze(request.text)

        # If redact_on_flag is True, also redact on FLAG decisions
        redacted = decision.redacted_text
        if request.redact_on_flag and decision.action == "FLAG":
            redacted = firewall._get_redacted_text(request.text, decision.agent_results)

        return AnalyzeResponse(
            action=decision.action,
            severity=decision.severity,
            reason=decision.reason,
            triggered_agents=decision.triggered_agents,
            agent_results=[
                AgentResultResponse(
                    agent_name=r.agent_name,
                    threat_found=r.threat_found,
                    threat_type=r.threat_type,
                    severity=r.severity,
                    summary=r.summary,
                )
                for r in decision.agent_results
            ],
            redacted_text=redacted if decision.action in ["REDACT", "BLOCK"] else None,
            processing_time_ms=decision.processing_time_ms,
            original_text=decision.original_text,
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Firewall analysis failed: {str(e)}")


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


@app.post("/analyze/batch", tags=["Firewall"])
def analyze_batch(texts: List[str]):
    """
    Analyze multiple texts at once.
    Returns a list of decisions in the same order as the input.
    """
    if len(texts) > 20:
        raise HTTPException(
            status_code=400,
            detail="Batch size limit is 20 texts per request."
        )
    if not texts:
        raise HTTPException(status_code=400, detail="texts list cannot be empty.")

    results = []
    for text in texts:
        try:
            decision = firewall.analyze(text)
            results.append({
                "action": decision.action,
                "severity": decision.severity,
                "triggered_agents": decision.triggered_agents,
                "processing_time_ms": decision.processing_time_ms,
            })
        except Exception as e:
            results.append({"error": str(e)})

    return {"results": results, "total": len(results)}


# ── Run server ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)