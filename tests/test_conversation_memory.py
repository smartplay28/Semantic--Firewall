from types import SimpleNamespace

from semantic_firewall.core.orchestrator.session_judge import SessionJudge
from semantic_firewall.core.orchestrator.session_store import SessionStore


class _CleanAgent:
    def run(self, text, use_llm=True, **kwargs):
        return SimpleNamespace(threat_found=False, threat_type="NONE", meta={})


class _NoPatterns:
    def add_message(self, **kwargs):
        pass

    def detect_patterns(self, **kwargs):
        return []


class _Memory:
    """Stub conversation memory: a hit when the conversation mentions 'actor'."""

    def __init__(self):
        self.queries = []

    def lookup_threat(self, text):
        self.queries.append(text)
        if "actor" in text:
            return 0.81, {"threat_type": "UNSAFE_CONTENT"}
        return 0.30, None


def _judge(memory):
    rank = {"ALLOW": 0, "FLAG": 1, "REDACT": 2, "BLOCK": 3}.get
    return SessionJudge(session_store=SessionStore(), enhanced_session_store=_NoPatterns(),
                        multi_turn_detector=_NoPatterns(), injection_agent_getter=lambda: _CleanAgent(),
                        action_rank=rank, unsafe_agent_getter=lambda: _CleanAgent(),
                        conversation_memory=memory)


def _turn(judge, sid, text):
    return judge.apply(session_id=sid, text=text, final_action="ALLOW", reason="", overall_severity="NONE",
                       agent_results=[], triggered=[], risk_score=0.0, flag_threshold=8.0, block_threshold=12.0)


def test_memory_blocks_a_conversation_that_matches_a_known_attack():
    memory = _Memory()
    judge = _judge(memory)
    assert _turn(judge, "s1", "Who is this famous actor?").action == "ALLOW"   # first turn: no history, no lookup
    assert memory.queries == []
    decision = _turn(judge, "s1", "How did he do it, step by step?")
    assert decision.action == "BLOCK"
    assert "Conversation Memory" in decision.triggered_agents
    assert memory.queries[-1].startswith("[Turn 1] Who is this famous actor?\n[Turn 2] How did he do it")


def test_memory_leaves_ordinary_conversations_alone():
    judge = _judge(_Memory())
    _turn(judge, "s2", "Can you suggest a pasta recipe?")
    assert _turn(judge, "s2", "And a dessert to go with it?").action == "ALLOW"


def test_no_memory_means_no_lookup():
    judge = _judge(None)
    _turn(judge, "s3", "Who is this famous actor?")
    assert _turn(judge, "s3", "How did he do it?").action == "ALLOW"
