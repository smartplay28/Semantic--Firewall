from fastapi import APIRouter, HTTPException

from api_app.schemas import WorkspaceRequest


def build_workspaces_router(workspace_store):
    router = APIRouter(tags=["Workspaces"])

    @router.get("/workspaces")
    def list_workspaces():
        return {"workspaces": workspace_store.list_workspaces()}

    @router.post("/workspaces")
    def save_workspace(request: WorkspaceRequest):
        try:
            workspace = workspace_store.save_workspace(
                name=request.name,
                description=request.description,
                owner=request.owner,
            )
            return {"workspace": workspace}
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Failed to save workspace: {exc}")

    @router.delete("/workspaces/{name}")
    def delete_workspace(name: str):
        deleted = workspace_store.delete_workspace(name)
        if not deleted:
            raise HTTPException(status_code=404, detail="Workspace not found")
        return {"deleted": True, "name": name}

    return router

