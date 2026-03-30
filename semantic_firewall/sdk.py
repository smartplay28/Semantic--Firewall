import json
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

from orchestrator.orchestrator import SemanticFirewallOrchestrator


class Firewall:
    """
    SDK entrypoint for Semantic Firewall.

    Examples:
        fw = Firewall()  # local mode
        result = fw.analyze("Ignore previous instructions")

        fw = Firewall(api_base_url="http://localhost:8000")  # remote API mode
        result = fw.analyze("hello")
    """

    def __init__(
        self,
        api_base_url: Optional[str] = None,
        db_path: str = "audit.db",
        default_policy_profile: str = "balanced",
        default_workspace_id: str = "default",
    ):
        self.api_base_url = api_base_url.rstrip("/") if api_base_url else None
        self.default_policy_profile = default_policy_profile
        self.default_workspace_id = default_workspace_id
        self._local = None if self.api_base_url else SemanticFirewallOrchestrator(db_path=db_path)

    def _post_json(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        assert self.api_base_url is not None
        url = f"{self.api_base_url}{path}"
        request = urllib.request.Request(
            url=url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:  # nosec B310
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Firewall API error ({exc.code}): {body}") from exc

    def analyze(
        self,
        text: str,
        session_id: Optional[str] = None,
        policy_profile: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ):
        profile = policy_profile or self.default_policy_profile
        workspace = workspace_id or self.default_workspace_id
        if self._local:
            return self._local.analyze(
                text=text,
                session_id=session_id,
                policy_profile=profile,
                workspace_id=workspace,
            )
        return self._post_json(
            "/analyze",
            {
                "text": text,
                "session_id": session_id,
                "policy_profile": profile,
                "workspace_id": workspace,
            },
        )

    def analyze_output(
        self,
        text: str,
        policy_profile: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ):
        profile = policy_profile or self.default_policy_profile
        workspace = workspace_id or self.default_workspace_id
        if self._local:
            return self._local.analyze_output(
                text=text,
                policy_profile=profile,
                workspace_id=workspace,
            )
        return self._post_json(
            "/analyze/output",
            {
                "text": text,
                "policy_profile": profile,
                "workspace_id": workspace,
            },
        )

    def analyze_interaction(
        self,
        prompt_text: str,
        output_text: str,
        session_id: Optional[str] = None,
        policy_profile: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ):
        profile = policy_profile or self.default_policy_profile
        workspace = workspace_id or self.default_workspace_id
        if self._local:
            return self._local.analyze_interaction(
                prompt_text=prompt_text,
                output_text=output_text,
                session_id=session_id,
                policy_profile=profile,
                workspace_id=workspace,
            )
        return self._post_json(
            "/analyze/interaction",
            {
                "prompt_text": prompt_text,
                "output_text": output_text,
                "session_id": session_id,
                "policy_profile": profile,
                "workspace_id": workspace,
            },
        )

