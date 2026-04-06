from typing import Optional

from fastapi import APIRouter, HTTPException

from api_app.schemas import ThreatIntelEntryRequest, ThreatIntelSyncRequest, ThreatIntelUpdateRequest


def build_threat_intel_router(threat_intel_manager):
    router = APIRouter(tags=["Threat Intel"])

    @router.get("/threat-intel")
    def list_threat_intel(scan_target: Optional[str] = None, enabled_only: bool = False):
        if scan_target and scan_target not in {"input", "output", "both"}:
            raise HTTPException(status_code=400, detail="scan_target must be input, output, or both")
        normalized_target = None if scan_target in {None, "both"} else scan_target
        return {"entries": threat_intel_manager.list_entries(scan_target=normalized_target, enabled_only=enabled_only)}

    @router.post("/threat-intel")
    def create_threat_intel_entry(request: ThreatIntelEntryRequest):
        try:
            entry = threat_intel_manager.add_entry(**request.model_dump())
            return {"entry": entry}
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Failed to create threat intel entry: {exc}")

    @router.put("/threat-intel/{entry_id}")
    def update_threat_intel_entry(entry_id: str, request: ThreatIntelUpdateRequest):
        try:
            updates = {key: value for key, value in request.model_dump().items() if value is not None}
            entry = threat_intel_manager.update_entry(entry_id, **updates)
            if not entry:
                raise HTTPException(status_code=404, detail="Threat intel entry not found")
            return {"entry": entry}
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Failed to update threat intel entry: {exc}")

    @router.delete("/threat-intel/{entry_id}")
    def delete_threat_intel_entry(entry_id: str):
        deleted = threat_intel_manager.delete_entry(entry_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Threat intel entry not found")
        return {"deleted": True, "entry_id": entry_id}

    @router.post("/threat-intel/sync")
    def sync_threat_intel_feed(request: ThreatIntelSyncRequest):
        try:
            result = threat_intel_manager.sync_from_url(
                url=request.url,
                timeout=request.timeout_seconds,
            )
            return {"result": result}
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Threat intel sync failed: {exc}")

    return router

