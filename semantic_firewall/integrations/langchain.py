from typing import Any, Optional

from semantic_firewall.sdk import Firewall


class LangChainFirewall:
    """
    One-line LangChain-style wrapper.

    Example:
        chain = LangChainFirewall(llm=ChatOpenAI(), firewall=Firewall())
        response = chain.invoke("hello")
    """

    def __init__(
        self,
        llm: Any,
        firewall: Optional[Firewall] = None,
        policy_profile: str = "balanced",
        workspace_id: str = "default",
        block_actions: tuple[str, ...] = ("BLOCK",),
    ):
        self.llm = llm
        self.firewall = firewall or Firewall(
            default_policy_profile=policy_profile,
            default_workspace_id=workspace_id,
        )
        self.block_actions = set(block_actions)

    def invoke(self, prompt: str, **kwargs):
        prompt_decision = self.firewall.analyze(prompt)
        prompt_action = (
            prompt_decision.action
            if hasattr(prompt_decision, "action")
            else prompt_decision.get("action")
        )
        if prompt_action in self.block_actions:
            raise ValueError(f"Prompt blocked by semantic firewall ({prompt_action}).")

        if hasattr(self.llm, "invoke"):
            output = self.llm.invoke(prompt, **kwargs)
        elif callable(self.llm):
            output = self.llm(prompt, **kwargs)
        else:
            raise TypeError("Provided llm must be callable or implement .invoke().")

        output_text = getattr(output, "content", None)
        if output_text is None:
            output_text = str(output)

        output_decision = self.firewall.analyze_output(output_text)
        output_action = (
            output_decision.action
            if hasattr(output_decision, "action")
            else output_decision.get("action")
        )
        if output_action in self.block_actions:
            raise ValueError(f"Output blocked by semantic firewall ({output_action}).")
        return output

