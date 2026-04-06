from typing import Optional

from fastapi import APIRouter, HTTPException

from api_app.schemas import SessionSummaryResponse


def build_sessions_audit_router(get_firewall):
    router = APIRouter()

    @router.get("/sessions/{session_id}", response_model=SessionSummaryResponse, tags=["Sessions"])
    def get_session_summary(session_id: str):
        firewall = get_firewall()
        if not session_id or len(session_id) > 200:
            raise HTTPException(status_code=400, detail="Invalid session_id format")
        try:
            return SessionSummaryResponse(**firewall.get_session_summary(session_id))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to get session summary: {str(e)}")

    @router.delete("/sessions/{session_id}", tags=["Sessions"])
    def clear_session(session_id: str):
        firewall = get_firewall()
        firewall.clear_session(session_id)
        return {"cleared": True, "session_id": session_id}

    @router.get("/promotions", tags=["Audit"])
    def list_promotions(limit: int = 50, workspace_id: Optional[str] = None):
        firewall = get_firewall()
        if limit < 1 or limit > 500:
            raise HTTPException(status_code=400, detail="limit must be between 1 and 500")
        try:
            return {"items": firewall.get_promotion_history(limit=limit, workspace_id=workspace_id)}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to get promotion history: {str(e)}")

    return router

