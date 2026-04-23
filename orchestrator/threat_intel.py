import json
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
from uuid import uuid4

from orchestrator.paths import config_path


class ThreatIntelFeedManager:
    """Persistent store for threat intelligence signatures."""

    def __init__(self, feed_path: str | None = None):
        self.feed_path = Path(feed_path) if feed_path else config_path("threat_intel_feed.json")
        self._ensure_store()

    def _utc_now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _default_feed(self) -> dict:
        now = self._utc_now()
        return {
            "version": "1.0",
            "updated_at": now,
            "entries": [
                {
                    "id": "ti_ignore_prev_instructions",
                    "name": "Classic instruction override",
                    "pattern": r"\b(ignore|forget|bypass)\b.{0,40}\b(previous|system|original)\b.{0,40}\b(instructions?|rules?|prompt)\b",
                    "category": "INJECTION",
                    "severity": "HIGH",
                    "scope": "both",
                    "description": "Known prompt-injection pattern from public jailbreak corpora.",
                    "source": "seed",
                    "tags": ["jailbreak", "prompt-injection"],
                    "enabled": True,
                    "updated_at": now,
                },
                {
                    "id": "ti_model_delimiter_abuse",
                    "name": "Delimiter/token smuggling",
                    "pattern": r"(<\|im_start\|>|<\|im_end\|>|\[INST\]|\[/INST\]|<\|system\|>|<\|assistant\|>)",
                    "category": "INJECTION",
                    "severity": "HIGH",
                    "scope": "both",
                    "description": "Tokenizer/delimiter abuse frequently used in jailbreak attempts.",
                    "source": "seed",
                    "tags": ["delimiter", "prompt-injection"],
                    "enabled": True,
                    "updated_at": now,
                },
                {
                    "id": "ti_metadata_ssrf_probe",
                    "name": "Cloud metadata SSRF probe",
                    "pattern": r"https?://169\.254\.169\.254",
                    "category": "ABUSE",
                    "severity": "CRITICAL",
                    "scope": "both",
                    "description": "Common cloud instance metadata endpoint probing pattern.",
                    "source": "seed",
                    "tags": ["ssrf", "cloud-metadata"],
                    "enabled": True,
                    "updated_at": now,
                },
            ],
        }

    def _ensure_store(self):
        self.feed_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.feed_path.exists():
            self.feed_path.write_text(json.dumps(self._default_feed(), indent=2), encoding="utf-8")

    def _load(self) -> dict:
        self._ensure_store()
        data = json.loads(self.feed_path.read_text(encoding="utf-8"))
        if "entries" not in data or not isinstance(data["entries"], list):
            data = self._default_feed()
            self._save(data)
        return data

    def _save(self, data: dict):
        data["updated_at"] = self._utc_now()
        self.feed_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def list_entries(self, scan_target: Optional[str] = None, enabled_only: bool = False) -> List[dict]:
        entries = self._load().get("entries", [])
        result: List[dict] = []
        for entry in entries:
            if enabled_only and not entry.get("enabled", True):
                continue
            scope = entry.get("scope", "both")
            if scan_target and scope not in {"both", scan_target}:
                continue
            result.append(entry)
        return result

    def add_entry(
        self,
        name: str,
        pattern: str,
        category: str,
        severity: str = "HIGH",
        scope: str = "both",
        description: str = "",
        source: str = "manual",
        tags: Optional[List[str]] = None,
        enabled: bool = True,
    ) -> dict:
        re.compile(pattern)
        data = self._load()
        now = self._utc_now()
        entry = {
            "id": uuid4().hex,
            "name": name.strip(),
            "pattern": pattern,
            "category": category.strip().upper(),
            "severity": severity.strip().upper(),
            "scope": scope.strip().lower(),
            "description": description.strip(),
            "source": source.strip(),
            "tags": [tag.strip().lower() for tag in (tags or []) if tag.strip()],
            "enabled": bool(enabled),
            "updated_at": now,
        }
        data["entries"].append(entry)
        self._save(data)
        return entry

    def update_entry(self, entry_id: str, **updates) -> Optional[dict]:
        data = self._load()
        for entry in data["entries"]:
            if entry.get("id") != entry_id:
                continue
            if "pattern" in updates and updates["pattern"]:
                re.compile(updates["pattern"])
            if "category" in updates and updates["category"]:
                updates["category"] = str(updates["category"]).upper()
            if "severity" in updates and updates["severity"]:
                updates["severity"] = str(updates["severity"]).upper()
            if "scope" in updates and updates["scope"]:
                updates["scope"] = str(updates["scope"]).lower()
            if "tags" in updates and updates["tags"] is not None:
                updates["tags"] = [str(tag).strip().lower() for tag in updates["tags"] if str(tag).strip()]
            entry.update({key: value for key, value in updates.items() if value is not None})
            entry["updated_at"] = self._utc_now()
            self._save(data)
            return entry
        return None

    def delete_entry(self, entry_id: str) -> bool:
        data = self._load()
        original_count = len(data["entries"])
        data["entries"] = [entry for entry in data["entries"] if entry.get("id") != entry_id]
        if len(data["entries"]) == original_count:
            return False
        self._save(data)
        return True

    def sync_from_url(self, url: str, timeout: int = 8) -> dict:
        request = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
            payload = json.loads(response.read().decode("utf-8"))
        incoming_entries = payload.get("entries", [])
        if not isinstance(incoming_entries, list):
            raise ValueError("Threat intel payload must include an 'entries' list.")

        data = self._load()
        by_id: Dict[str, dict] = {entry.get("id"): entry for entry in data["entries"]}
        added = 0
        updated = 0
        for entry in incoming_entries:
            entry_id = entry.get("id")
            pattern = entry.get("pattern", "")
            if not entry_id or not pattern:
                continue
            re.compile(pattern)
            normalized = {
                "id": entry_id,
                "name": str(entry.get("name", entry_id)).strip(),
                "pattern": pattern,
                "category": str(entry.get("category", "INJECTION")).upper(),
                "severity": str(entry.get("severity", "HIGH")).upper(),
                "scope": str(entry.get("scope", "both")).lower(),
                "description": str(entry.get("description", "")).strip(),
                "source": str(entry.get("source", "remote-feed")).strip(),
                "tags": [str(tag).strip().lower() for tag in entry.get("tags", []) if str(tag).strip()],
                "enabled": bool(entry.get("enabled", True)),
                "updated_at": self._utc_now(),
            }
            if entry_id in by_id:
                by_id[entry_id].update(normalized)
                updated += 1
            else:
                data["entries"].append(normalized)
                by_id[entry_id] = normalized
                added += 1

        self._save(data)
        return {
            "added": added,
            "updated": updated,
            "total": len(data["entries"]),
            "source_url": url,
        }
