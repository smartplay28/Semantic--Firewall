import base64
import binascii
from concurrent.futures import ThreadPoolExecutor, as_completed

from fastapi import APIRouter, HTTPException, Request, WebSocket, WebSocketDisconnect

from api_app.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    BatchAnalyzeRequest,
    DocumentAnalyzeRequest,
    DocumentAnalyzeResponse,
    InteractionAnalyzeRequest,
    InteractionAnalyzeResponse,
    OutputAnalyzeRequest,
    RedactRequest,
    RedactResponse,
)
from orchestrator.document_extractor import DocumentExtractionError


def build_firewall_router(limiter, get_firewall, build_analyze_response, document_extractor):
    router = APIRouter(tags=["Firewall"])

    @router.post("/analyze", response_model=AnalyzeResponse)
    @limiter.limit("30/minute")
    def analyze(request: Request, body: AnalyzeRequest):
        firewall = get_firewall()
        try:
            decision = firewall.analyze(
                body.text,
                session_id=body.session_id,
                policy_profile=body.policy_profile,
                workspace_id=body.workspace_id,
            )

            redacted = decision.redacted_text
            if body.redact_on_flag and decision.action == "FLAG":
                redacted = firewall._get_redacted_text(body.text, decision.agent_results)

            return build_analyze_response(
                decision,
                redacted_text_override=redacted if (
                    decision.action in ["REDACT", "BLOCK"]
                    or (body.redact_on_flag and decision.action == "FLAG")
                ) else None,
            )

        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Firewall analysis failed: {str(e)}")

    @router.post("/analyze/output", response_model=AnalyzeResponse)
    def analyze_output(request: OutputAnalyzeRequest):
        firewall = get_firewall()
        try:
            decision = firewall.analyze_output(
                request.text,
                policy_profile=request.policy_profile,
                workspace_id=request.workspace_id,
            )

            return build_analyze_response(
                decision,
                redacted_text_override=decision.redacted_text if decision.action in ["REDACT", "BLOCK"] else None,
            )

        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Output firewall analysis failed: {str(e)}")

    @router.post("/analyze/interaction", response_model=InteractionAnalyzeResponse)
    @limiter.limit("20/minute")
    def analyze_interaction(request: Request, body: InteractionAnalyzeRequest):
        firewall = get_firewall()
        try:
            interaction = firewall.analyze_interaction(
                prompt_text=body.prompt_text,
                output_text=body.output_text,
                session_id=body.session_id,
                policy_profile=body.policy_profile,
                workspace_id=body.workspace_id,
            )
            return InteractionAnalyzeResponse(
                combined_action=interaction.combined_action,
                combined_severity=interaction.combined_severity,
                combined_reason=interaction.combined_reason,
                triggered_agents=interaction.triggered_agents,
                interaction_alerts=interaction.interaction_alerts,
                drift_detected=interaction.drift_detected,
                contradiction_detected=interaction.contradiction_detected,
                session_risk_score=interaction.session_risk_score,
                prompt_decision=build_analyze_response(
                    interaction.prompt_decision,
                    redacted_text_override=(
                        interaction.prompt_decision.redacted_text
                        if interaction.prompt_decision.action in ["REDACT", "BLOCK"]
                        else None
                    ),
                ),
                output_decision=build_analyze_response(
                    interaction.output_decision,
                    redacted_text_override=(
                        interaction.output_decision.redacted_text
                        if interaction.output_decision.action in ["REDACT", "BLOCK"]
                        else None
                    ),
                ),
            )
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Interaction firewall analysis failed: {str(e)}")

    @router.post("/redact", response_model=RedactResponse)
    def redact(request: RedactRequest):
        firewall = get_firewall()
        try:
            import time

            start = time.time()
            pii_agent = firewall.agents["PII Detector"]
            secrets_agent = firewall.agents["Secrets Detector"]

            redacted = request.text
            redacted = pii_agent.redact(redacted)
            redacted = secrets_agent.redact(redacted)

            elapsed = (time.time() - start) * 1000

            return RedactResponse(
                original_text=request.text,
                redacted_text=redacted,
                processing_time_ms=elapsed,
            )

        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Redaction failed: {str(e)}")

    @router.post("/analyze/batch")
    @limiter.limit("10/minute")
    def analyze_batch(request: Request, body: BatchAnalyzeRequest):
        firewall = get_firewall()

        def _analyze_one(text: str) -> dict:
            try:
                if body.scan_target == "input":
                    decision = firewall.analyze(
                        text,
                        policy_profile=body.policy_profile,
                        workspace_id=body.workspace_id,
                    )
                else:
                    decision = firewall.analyze_output(
                        text,
                        policy_profile=body.policy_profile,
                        workspace_id=body.workspace_id,
                    )
                return build_analyze_response(
                    decision,
                    redacted_text_override=decision.redacted_text if decision.action in ["REDACT", "BLOCK"] else None,
                ).model_dump()
            except Exception as e:
                return {"error": str(e), "original_text": text, "scan_target": body.scan_target}

        results = [None] * len(body.texts)
        max_workers = min(len(body.texts), 3)
        try:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(_analyze_one, text): index
                    for index, text in enumerate(body.texts)
                }
                for future in as_completed(futures):
                    results[futures[future]] = future.result()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Batch analysis failed: {str(e)}")

        return {
            "results": results,
            "total": len(results),
            "scan_target": body.scan_target,
            "policy_profile": body.policy_profile,
        }

    @router.post("/analyze/document", response_model=DocumentAnalyzeResponse)
    @limiter.limit("20/minute")
    def analyze_document(request: Request, body: DocumentAnalyzeRequest):
        firewall = get_firewall()
        try:
            try:
                content = base64.b64decode(body.content_base64.encode("utf-8"))
            except (binascii.Error, ValueError) as exc:
                raise HTTPException(status_code=400, detail=f"Invalid base64 encoding: {str(exc)}")
            extracted = document_extractor.extract_text(body.filename, content)
            if not extracted["text"].strip():
                raise HTTPException(status_code=400, detail="No text extracted from document.")

            decision = (
                firewall.analyze(
                    extracted["text"],
                    policy_profile=body.policy_profile,
                    workspace_id=body.workspace_id,
                )
                if body.scan_target == "input"
                else firewall.analyze_output(
                    extracted["text"],
                    policy_profile=body.policy_profile,
                    workspace_id=body.workspace_id,
                )
            )
            redacted_override = None
            if decision.action in ["REDACT", "BLOCK"]:
                redacted_override = decision.redacted_text
            elif body.redact_on_flag and decision.action == "FLAG":
                redacted_override = firewall._get_redacted_text(
                    extracted["text"],
                    decision.agent_results,
                    scan_target=body.scan_target,
                )

            return DocumentAnalyzeResponse(
                filename=extracted["filename"],
                extension=extracted["extension"],
                extracted_char_count=extracted["char_count"],
                truncated=extracted["truncated"],
                extraction_mode=extracted["extraction_mode"],
                extraction_quality=extracted["extraction_quality"],
                warnings=extracted["warnings"],
                decision=build_analyze_response(decision, redacted_text_override=redacted_override),
            )
        except DocumentExtractionError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Document analysis failed: {str(exc)}")

    @router.websocket("/ws/analyze")
    async def ws_analyze(websocket: WebSocket):
        firewall = get_firewall()
        await websocket.accept()
        try:
            while True:
                payload = await websocket.receive_json()
                text = str(payload.get("text", "")).strip()
                if not text:
                    await websocket.send_json({"error": "text is required"})
                    continue
                scan_target = payload.get("scan_target", "input")
                policy_profile = payload.get("policy_profile", "balanced")
                workspace_id = payload.get("workspace_id", "default")
                session_id = payload.get("session_id")

                if scan_target == "output":
                    decision = firewall.analyze_output(
                        text=text,
                        policy_profile=policy_profile,
                        workspace_id=workspace_id,
                    )
                else:
                    decision = firewall.analyze(
                        text=text,
                        session_id=session_id,
                        policy_profile=policy_profile,
                        workspace_id=workspace_id,
                    )
                await websocket.send_json(
                    build_analyze_response(
                        decision,
                        redacted_text_override=decision.redacted_text
                        if decision.action in ["REDACT", "BLOCK"]
                        else None,
                    ).model_dump()
                )
        except WebSocketDisconnect:
            return
        except Exception as exc:
            await websocket.send_json({"error": f"websocket analysis failed: {exc}"})

    return router

