import json
from pathlib import Path
from typing import List, Optional

from orchestrator.paths import config_path


class WorkspaceStore:
    def __init__(self, store_path: str | None = None):
        self.store_path = Path(store_path) if store_path else config_path("workspaces.json")
        self._ensure_store()

    def _ensure_store(self):
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.store_path.exists():
            self.store_path.write_text("[]", encoding="utf-8")

    def _load(self) -> List[dict]:
        self._ensure_store()
        return json.loads(self.store_path.read_text(encoding="utf-8"))

    def _save(self, workspaces: List[dict]):
        self.store_path.write_text(json.dumps(workspaces, indent=2), encoding="utf-8")

    def list_workspaces(self) -> List[dict]:
        return sorted(self._load(), key=lambda item: item.get("name", "").lower())

    def get_workspace(self, name: str) -> Optional[dict]:
        normalized = (name or "").strip()
        for workspace in self._load():
            if workspace.get("name") == normalized:
                return workspace
        return None

    def save_workspace(self, name: str, description: str = "", owner: str = "") -> dict:
        normalized = (name or "").strip()
        if not normalized:
            raise ValueError("Workspace name cannot be empty.")
        workspaces = [item for item in self._load() if item.get("name") != normalized]
        workspace = {
            "name": normalized,
            "description": (description or "").strip(),
            "owner": (owner or "").strip(),
        }
        workspaces.append(workspace)
        self._save(workspaces)
        return workspace

    def delete_workspace(self, name: str) -> bool:
        normalized = (name or "").strip()
        workspaces = self._load()
        updated = [item for item in workspaces if item.get("name") != normalized]
        if len(updated) == len(workspaces):
            return False
        self._save(updated)
        return True
