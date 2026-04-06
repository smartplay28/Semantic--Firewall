from fastapi import APIRouter

from api_app.schemas import HealthResponse


def build_general_router(get_firewall):
    router = APIRouter(tags=["General"])

    @router.get("/")
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
            ],
        }

    @router.get("/health", response_model=HealthResponse)
    def health_check():
        firewall = get_firewall()
        return HealthResponse(
            status="healthy",
            agents_loaded=len(firewall.agents),
            version="1.0.0",
        )

    return router

