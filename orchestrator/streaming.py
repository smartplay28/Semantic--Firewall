import asyncio
from typing import AsyncGenerator, Optional
from orchestrator.orchestrator import SemanticFirewallOrchestrator

class StreamingFirewallProxy:
    def __init__(self, orchestrator: SemanticFirewallOrchestrator, chunk_size: int = 150):
        """
        A proxy that intercepts a streaming LLM response and scans it in chunks.
        chunk_size: Number of characters to accumulate before running a fast scan.
        """
        self.orchestrator = orchestrator
        self.chunk_size = chunk_size

    async def proxy_stream(
        self, 
        stream: AsyncGenerator[str, None], 
        scan_target: str = "output",
        policy_profile: str = "balanced",
        workspace_id: str = "default",
        session_id: Optional[str] = None
    ) -> AsyncGenerator[str, None]:
        """
        Consumes an async stream of tokens (e.g. from an LLM).
        Yields them to the user if they are safe.
        Interrupts the stream and yields a violation message if unsafe content is detected.
        """
        buffer = ""
        total_text = ""
        
        # Get the fast (cheap) agents that can run quickly without LLM overhead
        cheap_agents = [name for name in self.orchestrator.agents if name not in self.orchestrator.llm_agents]
        detector_overrides = self.orchestrator._detector_threshold_overrides(policy_profile, workspace_id)

        try:
            async for token in stream:
                buffer += token
                total_text += token

                # If we've accumulated enough characters, run a fast scan
                if len(buffer) >= self.chunk_size:
                    # Run the fast regex/heuristics on the accumulated text so far
                    # (We use total_text so the regex has context, not just the tiny buffer)
                    cheap_results = self.orchestrator._run_agents_parallel(
                        cheap_agents,
                        total_text,
                        scan_target,
                        workspace_id,
                        detector_threshold_overrides=detector_overrides,
                    )
                    
                    # Check if any fast agent flagged the text
                    if any(result.threat_found for result in cheap_results):
                        # Determine policy action
                        final_action, reason, triggered = self.orchestrator._apply_policy(
                            cheap_results, policy_profile, workspace_id
                        )
                        
                        if final_action in ["BLOCK", "REDACT"]:
                            yield f"\n\n[FIREWALL INTERVENTION] Stream terminated mid-generation. Reason: {reason}"
                            return # Stop yielding the stream completely

                    # If safe, yield the buffer and clear it
                    yield buffer
                    buffer = ""

            # Yield any remaining text in the buffer
            if buffer:
                yield buffer

            # (Optional) Once the stream is done, run a final deep scan on the entire text using LLM agents
            # This allows the firewall to catch complex attacks after the fact and log them.
            final_decision = self.orchestrator._analyze_text(
                total_text, scan_target, policy_profile, workspace_id, session_id
            )
            
            if final_decision.action in ["BLOCK", "REDACT"]:
                # The text was already streamed, but the deep LLM scan found something bad!
                yield f"\n\n[FIREWALL INTERVENTION - RETROSPECTIVE] The previous text was determined to be unsafe after a full context scan: {final_decision.reason}"

        except Exception as e:
            yield f"\n\n[FIREWALL ERROR] Stream proxy failed: {str(e)}"

