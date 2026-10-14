from semantic_firewall.core.orchestrator.explainability import ExplainabilityGenerator, ExplainabilityReport


def test_to_markdown_renders_a_report():
    report = ExplainabilityReport(
        timestamp="2026-10-06T00:00:00",
        overall_action="BLOCK",
        risk_score=91.5,
        severity="CRITICAL",
        executive_summary="Blocked.",
        triggered_agents=["Injection Detector"],
        agent_details=[],
        session_context=None,
        decision_rationale="Injection detected.",
        contributing_factors=["instruction override"],
        mitigating_factors=[],
        recommended_actions=["Review the prompt."],
        confidence_level="HIGH",
        metadata={},
    )
    text = ExplainabilityGenerator().to_markdown(report)
    assert "**Decision:** `BLOCK`" in text
    assert "**Risk Score:** 91.5/100" in text
