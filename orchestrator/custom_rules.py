import json
import re
from pathlib import Path
from typing import Dict, List, Optional
from uuid import uuid4


class CustomRulesManager:
    def __init__(self, rules_path: str = "custom_rules.json"):
        self.rules_path = Path(rules_path)
        self._ensure_store()

    def _ensure_store(self):
        if not self.rules_path.exists():
            self.rules_path.write_text("[]", encoding="utf-8")

    def _load(self) -> List[dict]:
        self._ensure_store()
        return json.loads(self.rules_path.read_text(encoding="utf-8"))

    def _save(self, rules: List[dict]):
        self.rules_path.write_text(json.dumps(rules, indent=2), encoding="utf-8")

    def list_rules(self, workspace_id: Optional[str] = None) -> List[dict]:
        rules = self._load()
        if not workspace_id:
            return rules
        return [
            rule for rule in rules
            if rule.get("workspace_id", "global") in {"global", workspace_id}
        ]

    def list_drafts(self, workspace_id: Optional[str] = None) -> List[dict]:
        return [
            rule for rule in self.list_rules(workspace_id=workspace_id)
            if rule.get("status") == "draft"
        ]

    def get_rule(self, rule_id: str, workspace_id: Optional[str] = None) -> Optional[dict]:
        for rule in self.list_rules(workspace_id=workspace_id):
            if rule.get("id") == rule_id:
                return rule
        return None

    def get_enabled_rules(self, scan_target: str = "both", workspace_id: Optional[str] = None) -> List[dict]:
        rules = []
        for rule in self.list_rules(workspace_id=workspace_id):
            if not rule.get("enabled", True):
                continue
            if rule.get("status") == "draft":
                continue
            scope = rule.get("scope", "both")
            if scope in ("both", scan_target):
                rules.append(rule)
        return rules

    def add_rule(
        self,
        name: str,
        pattern: str,
        description: str,
        severity: str,
        threat_type: str = "CUSTOM_RULE",
        scope: str = "both",
        redact: bool = False,
        exceptions: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        status: str = "active",
        source: str = "manual",
        support: int = 0,
        workspace_id: str = "global",
    ) -> dict:
        re.compile(pattern)
        normalized_exceptions = [item.strip() for item in (exceptions or []) if item.strip()]
        rules = self._load()
        normalized_workspace = (workspace_id or "global").strip() or "global"
        for existing in rules:
            same_pattern = existing.get("pattern") == pattern
            same_workspace = existing.get("workspace_id", "global") == normalized_workspace
            if not (same_pattern and same_workspace):
                continue

            existing_status = existing.get("status", "active")
            if status == "draft":
                # Draft creation should still be possible even when an active
                # rule already exists for the same pattern (for review/approval flows).
                if existing_status == "draft":
                    return existing
                continue

            # Non-draft creation is idempotent for existing active rules.
            if existing_status != "draft":
                return existing
        rule = {
            "id": uuid4().hex,
            "name": name.strip(),
            "pattern": pattern,
            "description": description.strip(),
            "severity": severity.upper(),
            "threat_type": threat_type.upper(),
            "scope": scope,
            "redact": redact,
            "exceptions": normalized_exceptions,
            "tags": [tag.strip().lower() for tag in (tags or []) if tag.strip()],
            "enabled": status != "draft",
            "status": status,
            "source": source,
            "support": support,
            "workspace_id": normalized_workspace,
            "approval_status": "not_requested" if status == "draft" else "approved",
            "approval_requested_by": "",
            "approval_approved_by": "",
        }
        rules.append(rule)
        self._save(rules)
        return rule

    def delete_rule(self, rule_id: str) -> bool:
        rules = self._load()
        updated = [rule for rule in rules if rule.get("id") != rule_id]
        if len(updated) == len(rules):
            return False
        self._save(updated)
        return True

    def toggle_rule(self, rule_id: str, enabled: bool) -> bool:
        rules = self._load()
        changed = False
        for rule in rules:
            if rule.get("id") == rule_id:
                rule["enabled"] = enabled
                changed = True
                break
        if changed:
            self._save(rules)
        return changed

    def update_rule(self, rule_id: str, **updates) -> Optional[dict]:
        rules = self._load()
        for rule in rules:
            if rule.get("id") == rule_id:
                if "pattern" in updates:
                    re.compile(updates["pattern"])
                if "severity" in updates and updates["severity"]:
                    updates["severity"] = updates["severity"].upper()
                if "threat_type" in updates and updates["threat_type"]:
                    updates["threat_type"] = updates["threat_type"].upper()
                if "exceptions" in updates:
                    updates["exceptions"] = [
                        item.strip() for item in (updates["exceptions"] or []) if str(item).strip()
                    ]
                if "tags" in updates:
                    updates["tags"] = [
                        str(tag).strip().lower() for tag in (updates["tags"] or []) if str(tag).strip()
                    ]
                if "status" in updates and updates["status"]:
                    updates["status"] = str(updates["status"]).strip().lower()
                if "workspace_id" in updates and updates["workspace_id"]:
                    updates["workspace_id"] = str(updates["workspace_id"]).strip()
                rule.update(updates)
                self._save(rules)
                return rule
        return None

    def create_draft_from_suggestion(self, suggestion: dict, workspace_id: str = "global") -> dict:
        return self.add_rule(
            name=suggestion["name"],
            pattern=suggestion["pattern"],
            description=suggestion["description"],
            severity=suggestion["severity"],
            scope=suggestion.get("scope", "both"),
            tags=suggestion.get("tags", []),
            status="draft",
            source="feedback_suggestion",
            support=int(suggestion.get("support", 0)),
            workspace_id=workspace_id,
        )

    def promote_draft(self, rule_id: str) -> Optional[dict]:
        rules = self._load()
        for rule in rules:
            if rule.get("id") == rule_id:
                if rule.get("status") != "draft":
                    return None
                if rule.get("approval_status") not in {"approved", "not_requested"}:
                    return None
                rule["status"] = "active"
                rule["enabled"] = True
                self._save(rules)
                return rule
        return None

    def request_approval(self, rule_id: str, requested_by: str) -> Optional[dict]:
        rules = self._load()
        for rule in rules:
            if rule.get("id") == rule_id and rule.get("status") == "draft":
                rule["approval_status"] = "pending_approval"
                rule["approval_requested_by"] = (requested_by or "").strip()
                self._save(rules)
                return rule
        return None

    def approve_draft(self, rule_id: str, approved_by: str) -> Optional[dict]:
        rules = self._load()
        approver = (approved_by or "").strip()
        for rule in rules:
            if rule.get("id") == rule_id and rule.get("status") == "draft":
                requester = (rule.get("approval_requested_by") or "").strip()
                if requester and requester == approver:
                    raise ValueError("Approver must be different from requester.")
                rule["approval_status"] = "approved"
                rule["approval_approved_by"] = approver
                self._save(rules)
                return rule
        return None

    def preview_draft_diff(self, rule_id: str) -> Optional[dict]:
        draft = self.get_rule(rule_id)
        if not draft or draft.get("status") != "draft":
            return None

        comparison = next(
            (
                rule
                for rule in self._load()
                if rule.get("status") != "draft"
                and rule.get("name") == draft.get("name")
            ),
            None,
        )
        fields = [
            "pattern",
            "description",
            "severity",
            "scope",
            "redact",
            "exceptions",
            "tags",
            "enabled",
        ]
        changes = []
        for field in fields:
            before = comparison.get(field) if comparison else None
            after = draft.get(field)
            if before != after:
                changes.append({"field": field, "before": before, "after": after})

        return {
            "draft": draft,
            "baseline": comparison,
            "changes": changes,
            "is_new_rule": comparison is None,
        }
