from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp

from semantic_firewall.sdk import Firewall


class SemanticFirewallMiddleware(BaseHTTPMiddleware):
    """
    FastAPI/Starlette middleware wrapper.

    Adds pre-request input scanning with one line:
        app.add_middleware(SemanticFirewallMiddleware)
    """

    def __init__(
        self,
        app: ASGIApp,
        api_base_url: str | None = None,
        policy_profile: str = "balanced",
        workspace_id: str = "default",
        block_actions: tuple[str, ...] = ("BLOCK",),
    ):
        super().__init__(app)
        self.firewall = Firewall(
            api_base_url=api_base_url,
            default_policy_profile=policy_profile,
            default_workspace_id=workspace_id,
        )
        self.block_actions = set(block_actions)

    async def dispatch(self, request: Request, call_next: Callable):
        if request.method in {"POST", "PUT", "PATCH"}:
            try:
                payload = await request.json()
            except Exception:
                payload = None
            if isinstance(payload, dict):
                text = payload.get("text") or payload.get("prompt") or payload.get("prompt_text")
                if isinstance(text, str) and text.strip():
                    decision = self.firewall.analyze(text)
                    action = decision.action if hasattr(decision, "action") else decision.get("action")
                    if action in self.block_actions:
                        return JSONResponse(
                            status_code=403,
                            content={
                                "blocked": True,
                                "reason": "Semantic firewall blocked this request.",
                                "decision": action,
                            },
                        )
        return await call_next(request)

