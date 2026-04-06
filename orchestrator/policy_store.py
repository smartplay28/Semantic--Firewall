import json
import re
from pathlib import Path
from typing import Dict, List, Optional


class PolicyStore:
    def __init__(self, presets_path: str = "policy_presets.json"):
        self.presets_path = Path(presets_path)
        self.default_presets: Dict[str, dict] = {
            "balanced": {
                "name": "balanced",
                "description": "Default policy profile.",
                "action_overrides": {},
                "session_flag_threshold": 8.0,
                "session_block_threshold": 12.0,
                "allowlist_patterns": [],
                "allowlist_max_severity": "LOW",
                "detector_thresholds": {},
                "enabled": True,
            },
            "strict": {
                "name": "strict",
                "description": "Security-first policy profile.",
                "action_overrides": {
                    "PII": {"LOW": "REDACT"},
                    "SECRET": {"LOW": "REDACT"},
                    "UNSAFE_CONTENT": {"LOW": "FLAG", "MEDIUM": "BLOCK"},
                },
                "session_flag_threshold": 6.0,
                "session_block_threshold": 9.0,
                "allowlist_patterns": [],
                "allowlist_max_severity": "LOW",
                "detector_thresholds": {
                    "Injection Detector": {"confidence_threshold": 0.45},
                    "Unsafe Content Detector": {"confidence_threshold": 0.45},
                },
                "enabled": True,
            },
            "developer_assistant": {
                "name": "developer_assistant",
                "description": "More permissive for technical workflows.",
                "action_overrides": {
                    "ABUSE": {"LOW": "ALLOW", "MEDIUM": "FLAG"},
                    "UNSAFE_CONTENT": {"LOW": "ALLOW", "MEDIUM": "FLAG"},
                },
                "session_flag_threshold": 10.0,
                "session_block_threshold": 14.0,
                "allowlist_patterns": [],
                "allowlist_max_severity": "LOW",
                "detector_thresholds": {
                    "Injection Detector": {"confidence_threshold": 0.58},
                    "Unsafe Content Detector": {"confidence_threshold": 0.58},
                },
                "enabled": True,
            },
            "customer_support": {
                "name": "customer_support",
                "description": "Protects PII and support workflows aggressively.",
                "action_overrides": {
                    "PII": {"LOW": "REDACT", "MEDIUM": "BLOCK"},
                    "SECRET": {"LOW": "BLOCK"},
                    "INJECTION": {"LOW": "BLOCK"},
                },
                "session_flag_threshold": 7.0,
                "session_block_threshold": 10.0,
                "allowlist_patterns": [],
                "allowlist_max_severity": "LOW",
                "detector_thresholds": {
                    "Injection Detector": {"confidence_threshold": 0.48},
                    "Unsafe Content Detector": {"confidence_threshold": 0.48},
                },
                "enabled": True,
            },
            "research": {
                "name": "research",
                "description": "Allows more exploratory content with guardrails.",
                "action_overrides": {
                    "UNSAFE_CONTENT": {"LOW": "ALLOW", "MEDIUM": "FLAG"},
                    "INJECTION": {"LOW": "FLAG", "MEDIUM": "FLAG"},
                },
                "session_flag_threshold": 10.0,
                "session_block_threshold": 15.0,
                "allowlist_patterns": [],
                "allowlist_max_severity": "LOW",
                "detector_thresholds": {
                    "Injection Detector": {"confidence_threshold": 0.55},
                    "Unsafe Content Detector": {"confidence_threshold": 0.55},
                },
                "enabled": True,
            },
        }
        self._ensure_store()

    def _ensure_store(self):
        if not self.presets_path.exists():
            self.presets_path.write_text(json.dumps([], indent=2), encoding="utf-8")

    def _load_custom_presets(self) -> List[dict]:
        self._ensure_store()
        return json.loads(self.presets_path.read_text(encoding="utf-8"))

    def _save_custom_presets(self, presets: List[dict]):
        self.presets_path.write_text(json.dumps(presets, indent=2), encoding="utf-8")

    def list_presets(self, workspace_id: Optional[str] = None) -> List[dict]:
        presets = {name: dict(preset) for name, preset in self.default_presets.items()}
        for preset in self._load_custom_presets():
            preset_workspace = preset.get("workspace_id", "global")
            if workspace_id and preset_workspace not in {"global", workspace_id}:
                continue
            presets[preset["name"]] = preset
        return list(presets.values())

    def list_drafts(self, workspace_id: Optional[str] = None) -> List[dict]:
        return [
            preset for preset in self.list_presets(workspace_id=workspace_id)
            if preset.get("status") == "draft"
        ]

    def get_preset(self, name: str, workspace_id: Optional[str] = None) -> dict:
        for preset in self.list_presets(workspace_id=workspace_id):
            if preset["name"] == name:
                return preset
        return dict(self.default_presets["balanced"])

    def get_custom_preset(self, name: str, workspace_id: Optional[str] = None) -> Optional[dict]:
        for preset in self._load_custom_presets():
            if preset.get("name") == name:
                preset_workspace = preset.get("workspace_id", "global")
                if workspace_id and preset_workspace not in {"global", workspace_id}:
                    continue
                return preset
        return None

    def save_preset(
        self,
        name: str,
        description: str,
        action_overrides: Optional[Dict[str, Dict[str, str]]] = None,
        session_flag_threshold: float = 8.0,
        session_block_threshold: float = 12.0,
        allowlist_patterns: Optional[List[str]] = None,
        allowlist_max_severity: str = "LOW",
        detector_thresholds: Optional[Dict[str, Dict[str, float]]] = None,
        enabled: bool = True,
        status: str = "active",
        source: str = "manual",
        support: int = 0,
        workspace_id: str = "global",
    ) -> dict:
        normalized_name = name.strip()
        if not normalized_name:
            raise ValueError("Preset name cannot be empty.")
        normalized_patterns = [item.strip() for item in (allowlist_patterns or []) if item.strip()]
        for pattern in normalized_patterns:
            re.compile(pattern)
        preset = {
            "name": normalized_name,
            "description": description.strip(),
            "action_overrides": action_overrides or {},
            "session_flag_threshold": float(session_flag_threshold),
            "session_block_threshold": float(session_block_threshold),
            "allowlist_patterns": normalized_patterns,
            "allowlist_max_severity": allowlist_max_severity.upper(),
            "detector_thresholds": detector_thresholds or {},
            "enabled": enabled if status != "draft" else False,
            "status": status,
            "source": source,
            "support": support,
            "workspace_id": (workspace_id or "global").strip() or "global",
            "approval_status": "not_requested" if status == "draft" else "approved",
            "approval_requested_by": "",
            "approval_approved_by": "",
        }
        presets = [
            item for item in self._load_custom_presets()
            if not (item["name"] == normalized_name and item.get("workspace_id", "global") == preset["workspace_id"])
        ]
        presets.append(preset)
        self._save_custom_presets(presets)
        return preset

    def delete_preset(self, name: str, workspace_id: Optional[str] = None) -> bool:
        if name in self.default_presets:
            return False
        presets = self._load_custom_presets()
        updated = [
            item for item in presets
            if not (
                item["name"] == name
                and (workspace_id is None or item.get("workspace_id", "global") == workspace_id)
            )
        ]
        if len(updated) == len(presets):
            return False
        self._save_custom_presets(updated)
        return True

    def create_draft_from_adjustment(self, adjustment: dict, workspace_id: str = "global") -> dict:
        profile_name = adjustment.get("profile", "balanced")
        base = self.get_preset(profile_name, workspace_id=workspace_id)
        new_name = f"{profile_name}_draft_{adjustment.get('agent', 'policy').lower().replace(' ', '_')}"
        action_overrides = dict(base.get("action_overrides", {}))
        agent_key = adjustment.get("agent", "").replace(" Detector", "").upper().replace(" ", "_")
        if adjustment.get("feedback_type") == "false_negative":
            action_overrides.setdefault(agent_key, {})[adjustment.get("severity", "LOW")] = "BLOCK"
            session_flag = max(0.0, float(base.get("session_flag_threshold", 8.0)) - 1.0)
            session_block = max(session_flag + 1.0, float(base.get("session_block_threshold", 12.0)) - 1.0)
        else:
            action_overrides.setdefault(agent_key, {})[adjustment.get("severity", "LOW")] = "FLAG"
            session_flag = float(base.get("session_flag_threshold", 8.0)) + 1.0
            session_block = float(base.get("session_block_threshold", 12.0)) + 1.0

        return self.save_preset(
            name=new_name,
            description=f"Draft derived from reviewer adjustment suggestion for {adjustment.get('agent', 'policy')}.",
            action_overrides=action_overrides,
            session_flag_threshold=session_flag,
            session_block_threshold=session_block,
            allowlist_patterns=base.get("allowlist_patterns", []),
            allowlist_max_severity=base.get("allowlist_max_severity", "LOW"),
            detector_thresholds=base.get("detector_thresholds", {}),
            enabled=False,
            status="draft",
            source="feedback_adjustment",
            support=int(adjustment.get("count", 0)),
            workspace_id=workspace_id,
        )

    def promote_draft(self, name: str, workspace_id: Optional[str] = None) -> Optional[dict]:
        presets = self._load_custom_presets()
        for preset in presets:
            if preset.get("name") == name and (workspace_id is None or preset.get("workspace_id", "global") == workspace_id):
                if preset.get("status") != "draft":
                    return None
                if preset.get("approval_status") not in {"approved", "not_requested"}:
                    return None
                preset["status"] = "active"
                preset["enabled"] = True
                self._save_custom_presets(presets)
                return preset
        return None

    def request_approval(self, name: str, requested_by: str, workspace_id: Optional[str] = None) -> Optional[dict]:
        presets = self._load_custom_presets()
        for preset in presets:
            if preset.get("name") == name and preset.get("status") == "draft" and (workspace_id is None or preset.get("workspace_id", "global") == workspace_id):
                preset["approval_status"] = "pending_approval"
                preset["approval_requested_by"] = (requested_by or "").strip()
                self._save_custom_presets(presets)
                return preset
        return None

    def approve_draft(self, name: str, approved_by: str, workspace_id: Optional[str] = None) -> Optional[dict]:
        presets = self._load_custom_presets()
        approver = (approved_by or "").strip()
        for preset in presets:
            if preset.get("name") == name and preset.get("status") == "draft" and (workspace_id is None or preset.get("workspace_id", "global") == workspace_id):
                requester = (preset.get("approval_requested_by") or "").strip()
                if requester and requester == approver:
                    raise ValueError("Approver must be different from requester.")
                preset["approval_status"] = "approved"
                preset["approval_approved_by"] = approver
                self._save_custom_presets(presets)
                return preset
        return None

    def preview_draft_diff(self, name: str, workspace_id: Optional[str] = None) -> Optional[dict]:
        draft = self.get_custom_preset(name, workspace_id=workspace_id)
        if not draft or draft.get("status") != "draft":
            return None

        base_name = "balanced"
        if "_draft_" in name:
            base_name = name.split("_draft_", 1)[0]
        baseline = self.get_preset(base_name, workspace_id=workspace_id)
        fields = [
            "description",
            "action_overrides",
            "session_flag_threshold",
            "session_block_threshold",
            "allowlist_patterns",
            "allowlist_max_severity",
            "detector_thresholds",
            "enabled",
        ]
        changes = []
        for field in fields:
            before = baseline.get(field)
            after = draft.get(field)
            if before != after:
                changes.append({"field": field, "before": before, "after": after})

        return {
            "draft": draft,
            "baseline": baseline,
            "changes": changes,
            "base_profile": base_name,
        }
