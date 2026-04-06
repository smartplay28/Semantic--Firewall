from typing import Optional

from fastapi import APIRouter, HTTPException

from api_app.schemas import (
    ApprovalRequest,
    CustomRuleRequest,
    FeedbackRequest,
    PolicyPresetRequest,
    PromotionRequest,
    ReviewStatusRequest,
    RuleTestRequest,
    RuleUpdateRequest,
)
from agents.custom_rules_detector import CustomRulesDetectorAgent


def build_rules_policies_feedback_router(get_firewall, rules_manager):
    router = APIRouter()

    @router.get("/rules", tags=["Rules"])
    def list_rules(workspace_id: Optional[str] = None):
        return {"rules": rules_manager.list_rules(workspace_id=workspace_id)}

    @router.get("/rules/drafts", tags=["Rules"])
    def list_rule_drafts(workspace_id: Optional[str] = None):
        return {"drafts": rules_manager.list_drafts(workspace_id=workspace_id)}

    @router.get("/rules/drafts/{rule_id}/preview", tags=["Rules"])
    def preview_rule_draft(rule_id: str, workspace_id: Optional[str] = None):
        preview = rules_manager.preview_draft_diff(rule_id)
        if preview and workspace_id and preview["draft"].get("workspace_id", "global") not in {"global", workspace_id}:
            preview = None
        if not preview:
            raise HTTPException(status_code=404, detail="Rule draft not found")
        return preview

    @router.get("/policies", tags=["Policies"])
    def list_policies(workspace_id: Optional[str] = None):
        firewall = get_firewall()
        return {"presets": firewall.list_policy_presets(workspace_id=workspace_id)}

    @router.get("/policies/drafts", tags=["Policies"])
    def list_policy_drafts(workspace_id: Optional[str] = None):
        firewall = get_firewall()
        return {"drafts": firewall.list_policy_drafts(workspace_id=workspace_id)}

    @router.get("/policies/drafts/{name}/preview", tags=["Policies"])
    def preview_policy_draft(name: str, workspace_id: Optional[str] = None):
        firewall = get_firewall()
        preview = firewall.preview_policy_draft(name, workspace_id=workspace_id)
        if not preview:
            raise HTTPException(status_code=404, detail="Policy draft not found")
        return preview

    @router.post("/policies", tags=["Policies"])
    def save_policy(request: PolicyPresetRequest):
        firewall = get_firewall()
        try:
            preset = firewall.save_policy_preset(**request.model_dump())
            return {"preset": preset}
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to save policy preset: {str(e)}")

    @router.delete("/policies/{name}", tags=["Policies"])
    def delete_policy(name: str, workspace_id: Optional[str] = None):
        firewall = get_firewall()
        deleted = firewall.delete_policy_preset(name, workspace_id=workspace_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Policy preset not found or cannot be deleted")
        return {"deleted": True, "name": name}

    @router.post("/policies/{name}/promote", tags=["Policies"])
    def promote_policy(name: str, request: PromotionRequest):
        firewall = get_firewall()
        promoted = firewall.promote_policy_draft(name, note=request.note, workspace_id=request.workspace_id)
        if not promoted:
            raise HTTPException(status_code=404, detail="Policy draft not found")
        return {"preset": promoted}

    @router.post("/rules", tags=["Rules"])
    def create_rule(request: CustomRuleRequest):
        try:
            rule = rules_manager.add_rule(
                name=request.name,
                pattern=request.pattern,
                description=request.description,
                severity=request.severity,
                threat_type=request.threat_type,
                scope=request.scope,
                redact=request.redact,
                exceptions=request.exceptions,
                tags=request.tags,
                workspace_id=request.workspace_id,
            )
            return {"rule": rule}
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to create rule: {str(e)}")

    @router.put("/rules/{rule_id}", tags=["Rules"])
    def update_rule(rule_id: str, request: RuleUpdateRequest):
        updates = {key: value for key, value in request.model_dump().items() if value is not None}
        updated = rules_manager.update_rule(rule_id, **updates)
        if not updated:
            raise HTTPException(status_code=404, detail="Rule not found")
        return {"rule": updated}

    @router.post("/rules/test", tags=["Rules"])
    def test_rule(request: RuleTestRequest):
        try:
            if request.rule_id:
                rules = rules_manager.list_rules()
                rule = next((item for item in rules if item["id"] == request.rule_id), None)
                if not rule:
                    raise HTTPException(status_code=404, detail="Rule not found")
            elif request.rule:
                rule = {
                    "id": "preview",
                    "name": request.rule.name,
                    "pattern": request.rule.pattern,
                    "description": request.rule.description,
                    "severity": request.rule.severity,
                    "threat_type": request.rule.threat_type,
                    "scope": request.rule.scope,
                    "redact": request.rule.redact,
                    "enabled": True,
                    "exceptions": request.rule.exceptions,
                    "tags": request.rule.tags,
                }
            else:
                raise HTTPException(status_code=400, detail="Provide either rule_id or rule.")

            tester = CustomRulesDetectorAgent()
            result = tester.test_rule(rule, request.text)
            return {
                "rule_id": rule["id"],
                "rule_name": rule["name"],
                "scan_target": request.scan_target,
                **result,
            }
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to test rule: {str(e)}")

    @router.delete("/rules/{rule_id}", tags=["Rules"])
    def delete_rule(rule_id: str):
        deleted = rules_manager.delete_rule(rule_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Rule not found")
        return {"deleted": True, "rule_id": rule_id}

    @router.post("/feedback", tags=["Feedback"])
    def submit_feedback(request: FeedbackRequest):
        firewall = get_firewall()
        feedback_type = request.feedback_type.strip().lower()
        if feedback_type not in {"false_positive", "false_negative"}:
            raise HTTPException(status_code=400, detail="feedback_type must be false_positive or false_negative")

        firewall.audit_logger.submit_feedback(
            audit_log_id=request.audit_log_id,
            feedback_type=feedback_type,
            notes=request.notes or "",
        )
        return {"submitted": True}

    @router.get("/feedback/insights", tags=["Feedback"])
    def feedback_insights(workspace_id: Optional[str] = None):
        firewall = get_firewall()
        try:
            return firewall.audit_logger.get_feedback_insights(workspace_id=workspace_id)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to get feedback insights: {str(e)}")

    @router.get("/feedback/adjustments", tags=["Feedback"])
    def feedback_adjustments(limit: int = 8, workspace_id: Optional[str] = None):
        firewall = get_firewall()
        if limit < 1 or limit > 50:
            raise HTTPException(status_code=400, detail="limit must be between 1 and 50")
        try:
            return {
                "adjustments": firewall.audit_logger.suggest_policy_adjustments(limit=limit, workspace_id=workspace_id),
                "timeline": firewall.audit_logger.get_reviewer_timeline(workspace_id=workspace_id),
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to get feedback adjustments: {str(e)}")

    @router.post("/feedback/adjustments/draft", tags=["Feedback"])
    def create_policy_draft_from_adjustment(index: int = 0, limit: int = 8, workspace_id: str = "default"):
        firewall = get_firewall()
        if limit < 1 or limit > 50:
            raise HTTPException(status_code=400, detail="limit must be between 1 and 50")
        if index < 0:
            raise HTTPException(status_code=400, detail="index must be >= 0")
        try:
            adjustments = firewall.audit_logger.suggest_policy_adjustments(limit=limit, workspace_id=workspace_id)
            if index >= len(adjustments):
                raise HTTPException(status_code=404, detail="Adjustment suggestion not found")
            draft = firewall.create_policy_draft_from_adjustment(adjustments[index], workspace_id=workspace_id)
            return {"draft": draft}
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to create policy draft: {str(e)}")

    @router.get("/rules/suggestions", tags=["Rules"])
    def suggest_rules(limit: int = 5, workspace_id: Optional[str] = None):
        firewall = get_firewall()
        if limit < 1 or limit > 50:
            raise HTTPException(status_code=400, detail="limit must be between 1 and 50")
        try:
            return {"suggestions": firewall.audit_logger.suggest_rules_from_feedback(limit=limit, workspace_id=workspace_id)}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to get rule suggestions: {str(e)}")

    @router.post("/rules/suggestions/draft", tags=["Rules"])
    def create_draft_from_suggestion(index: int = 0, limit: int = 10, workspace_id: str = "default"):
        firewall = get_firewall()
        if limit < 1 or limit > 50:
            raise HTTPException(status_code=400, detail="limit must be between 1 and 50")
        if index < 0:
            raise HTTPException(status_code=400, detail="index must be >= 0")
        try:
            suggestions = firewall.audit_logger.suggest_rules_from_feedback(limit=limit, workspace_id=workspace_id)
            if index >= len(suggestions):
                raise HTTPException(status_code=404, detail="Suggestion not found")
            draft = rules_manager.create_draft_from_suggestion(suggestions[index], workspace_id=workspace_id)
            return {"draft": draft}
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to create rule draft: {str(e)}")

    @router.post("/rules/{rule_id}/request-approval", tags=["Rules"])
    def request_rule_approval(rule_id: str, request: ApprovalRequest):
        draft = rules_manager.request_approval(rule_id, request.actor)
        if not draft:
            raise HTTPException(status_code=404, detail="Rule draft not found")
        return {"draft": draft}

    @router.post("/rules/{rule_id}/approve", tags=["Rules"])
    def approve_rule_draft(rule_id: str, request: ApprovalRequest):
        try:
            draft = rules_manager.approve_draft(rule_id, request.actor)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        if not draft:
            raise HTTPException(status_code=404, detail="Rule draft not found")
        return {"draft": draft}

    @router.post("/rules/{rule_id}/promote", tags=["Rules"])
    def promote_rule(rule_id: str, request: PromotionRequest):
        firewall = get_firewall()
        promoted = rules_manager.promote_draft(rule_id)
        if not promoted:
            raise HTTPException(status_code=404, detail="Rule not found")
        firewall.audit_logger.log_promotion(
            item_type="rule",
            item_id=promoted["id"],
            item_name=promoted["name"],
            note=request.note,
            metadata={"severity": promoted.get("severity"), "scope": promoted.get("scope")},
            workspace_id=request.workspace_id,
        )
        return {"rule": promoted}

    @router.post("/policies/{name}/request-approval", tags=["Policies"])
    def request_policy_approval(name: str, request: ApprovalRequest):
        firewall = get_firewall()
        draft = firewall.request_policy_approval(name, request.actor, workspace_id=request.workspace_id)
        if not draft:
            raise HTTPException(status_code=404, detail="Policy draft not found")
        return {"draft": draft}

    @router.post("/policies/{name}/approve", tags=["Policies"])
    def approve_policy_draft(name: str, request: ApprovalRequest):
        firewall = get_firewall()
        try:
            draft = firewall.approve_policy_draft(name, request.actor, workspace_id=request.workspace_id)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        if not draft:
            raise HTTPException(status_code=404, detail="Policy draft not found")
        return {"draft": draft}

    @router.get("/review-queue", tags=["Feedback"])
    def get_review_queue(
        limit: int = 25,
        severity: Optional[str] = None,
        scan_target: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ):
        firewall = get_firewall()
        if limit < 1 or limit > 100:
            raise HTTPException(status_code=400, detail="limit must be between 1 and 100")
        if severity and severity not in {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise HTTPException(status_code=400, detail="Invalid severity level")
        try:
            return {
                "items": firewall.audit_logger.get_review_queue(
                    limit=limit,
                    severity=severity,
                    scan_target=scan_target,
                    workspace_id=workspace_id,
                )
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to get review queue: {str(e)}")

    @router.get("/review-queue/analytics", tags=["Feedback"])
    def get_review_queue_analytics(workspace_id: Optional[str] = None):
        firewall = get_firewall()
        try:
            return firewall.audit_logger.get_review_queue_analytics(workspace_id=workspace_id)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to get review queue analytics: {str(e)}")

    @router.post("/review-queue/{audit_log_id}", tags=["Feedback"])
    def update_review_queue_item(audit_log_id: int, request: ReviewStatusRequest):
        firewall = get_firewall()
        firewall.audit_logger.set_review_status(
            audit_log_id,
            request.review_status,
            review_assignee=request.review_assignee,
            review_notes=request.review_notes,
        )
        return {
            "updated": True,
            "audit_log_id": audit_log_id,
            "review_status": request.review_status,
            "review_assignee": request.review_assignee,
        }

    return router

