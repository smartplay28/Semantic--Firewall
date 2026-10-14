"""Write-back safeguards of the semantic cache: benign-overlap check, probationary tier, TTL, re-validation."""
import math
from pathlib import Path

import pytest

pytest.importorskip("chromadb")

from semantic_firewall.core.orchestrator.semantic_cache import PROBATIONARY, TRUSTED, SemanticCache
from tests.test_semantic_memory import ATTACK, PARAPHRASE, BENIGN, CleanAgent, CriticalSecretAgent, _orchestrator, _stub_agents

DIM = 384


def unit(axis: int) -> list:
    v = [0.0] * DIM
    v[axis] = 1.0
    return v


def near(axis: int, cos: float, other: int) -> list:
    """Unit vector with cosine `cos` to unit(axis)."""
    v = [0.0] * DIM
    v[axis], v[other] = cos, math.sqrt(1.0 - cos * cos)
    return v


def _cache(path: Path, **kwargs) -> SemanticCache:
    cache = SemanticCache(db_path=str(path), similarity_threshold=0.65, **kwargs)
    assert cache.enabled
    cache.reset()
    return cache


def _write(cache, text, vector):
    return cache.add_threat(text, "INJECTION", "HIGH", "Injection Detector", confidence=0.95, llm_confirmed=True,
                            embedding=vector)


def _meta(cache, text):
    return cache.collection.get(ids=[cache._generate_id(text)], include=["metadatas"])["metadatas"][0]


def test_defaults_leave_write_back_unchanged(workspace_tmp_path):
    cache = _cache(workspace_tmp_path / "chroma")
    assert _write(cache, "entry", unit(0))
    assert _meta(cache, "entry")["tier"] == TRUSTED
    _, hit = cache.lookup_threat("q", embedding=near(0, 0.66, 1))
    assert hit is not None and hit["online"] is True
    assert cache.should_revalidate(hit) is False


def test_overlap_check_rejects_entries_covering_benign_prompts(workspace_tmp_path):
    cache = _cache(workspace_tmp_path / "chroma", overlap_check=True)
    cache.add_benign_reference(["a benign reference prompt"], embeddings=[unit(0)])

    assert _write(cache, "covers the benign prompt", near(0, 0.70, 1)) is False
    assert cache.stats["writes_rejected_overlap"] == 1
    assert _write(cache, "far from it", near(0, 0.50, 2)) is True
    assert cache.seed_threats(["seeded entry"], embeddings=[unit(0)]) == 1  # curated seeds are not checked
    assert cache.count() == 2


def test_overlap_check_uses_the_allowlist(workspace_tmp_path):
    cache = _cache(workspace_tmp_path / "chroma", overlap_check=True)
    cache.add_allowlist(BENIGN, reason="approved")
    assert cache.add_threat(BENIGN, "INJECTION", "HIGH", "x", confidence=0.95, llm_confirmed=True) is False
    assert cache.add_threat(ATTACK, "INJECTION", "HIGH", "x", confidence=0.95, llm_confirmed=True) is True


def test_probationary_entries_need_independent_confirmations(workspace_tmp_path):
    cache = _cache(workspace_tmp_path / "chroma", probation_threshold=0.75, promote_after=2)
    assert _write(cache, "E", unit(0))
    assert _meta(cache, "E")["tier"] == PROBATIONARY

    assert cache.lookup_threat("q1", embedding=near(0, 0.70, 1))[1] is None  # within tau, below tau'
    assert cache.lookup_threat("q2", embedding=near(0, 0.80, 2))[1]["matched_text"] == "E"

    _write(cache, "C1", near(0, 0.70, 3))   # a detection within tau of E confirms it once
    _write(cache, "C1", near(0, 0.70, 3))   # the same prompt again does not count twice
    assert _meta(cache, "E")["confirmations"] == 1 and _meta(cache, "E")["tier"] == PROBATIONARY
    _write(cache, "C2", near(0, 0.68, 4))
    assert _meta(cache, "E")["tier"] == TRUSTED and cache.stats["promotions"] == 1

    assert cache.lookup_threat("q1", embedding=near(0, 0.70, 1))[1]["matched_text"] == "E"


def test_operator_can_promote_a_probationary_entry(workspace_tmp_path):
    cache = _cache(workspace_tmp_path / "chroma", probation_threshold=0.75)
    _write(cache, "E", unit(0))
    entry_id = cache._generate_id("E")
    assert cache.lookup_threat("q", embedding=near(0, 0.70, 1))[1] is None
    assert cache.promote(entry_id) is True and cache.promote(entry_id) is False
    assert cache.lookup_threat("q", embedding=near(0, 0.70, 1))[1]["matched_text"] == "E"


def test_probationary_entries_expire_unless_reconfirmed(workspace_tmp_path):
    cache = _cache(workspace_tmp_path / "chroma", ttl_requests=3, promote_after=5)
    cache.seed_threats(["seed"], embeddings=[unit(9)])
    _write(cache, "E", unit(0))
    _write(cache, "F", unit(5))
    for _ in range(3):                                        # clock 1..3: within the TTL
        assert cache.lookup_threat("q", embedding=unit(0))[1]["matched_text"] == "E"
    _write(cache, "G", near(5, 0.90, 6))                      # confirms F at clock 3
    assert cache.lookup_threat("q", embedding=unit(0))[1] is None  # clock 4: E expired
    assert cache.stats["expirations"] == 1
    for _ in range(2):                                        # clock 5, 6: F renewed at 3
        assert cache.lookup_threat("q", embedding=unit(5))[1]["matched_text"] == "F"
    assert cache.lookup_threat("q", embedding=unit(5))[1] is None  # clock 7: F and G expired
    assert cache.lookup_threat("q", embedding=unit(9))[1]["matched_text"] == "seed"  # seeds never expire
    assert cache.purge_expired() == 0 and cache.count() == 1


def test_revalidation_samples_and_evicts_only_online_entries(workspace_tmp_path):
    cache = _cache(workspace_tmp_path / "chroma", revalidate_rate=1.0)
    cache.seed_threats(["seed"], embeddings=[unit(1)])
    _write(cache, "online", unit(0))
    seed_hit = cache.lookup_threat("q", embedding=unit(1))[1]
    online_hit = cache.lookup_threat("q", embedding=unit(0))[1]

    assert cache.should_revalidate(seed_hit) is False
    assert cache.should_revalidate(online_hit) is True
    assert cache.evict(seed_hit["id"]) is False
    assert cache.evict(online_hit["id"]) is True
    assert cache.count() == 1 and cache.stats["revalidation_evictions"] == 1


def test_orchestrator_revalidates_and_evicts_when_the_pipeline_allows(workspace_tmp_path, monkeypatch):
    orchestrator = _orchestrator(workspace_tmp_path, monkeypatch, SEMANTIC_FIREWALL_LLM_GATE_ENABLED="0",
                                 SEMANTIC_FIREWALL_CACHE_SIM_THRESHOLD="0.5",
                                 SEMANTIC_FIREWALL_CACHE_REVALIDATE_RATE="1.0")
    injection = CleanAgent("Injection Detector", "INJECTION")
    orchestrator.agents = _stub_agents(injection=injection)
    assert orchestrator.semantic_cache.add_threat(ATTACK, "INJECTION", "CRITICAL", "Injection Detector",
                                                  confidence=0.95, llm_confirmed=True)

    decision = orchestrator.analyze(PARAPHRASE)

    assert decision.cache_revalidated is True
    assert decision.resolution_stage == "llm" and injection.calls == 1
    assert decision.action == "ALLOW"
    assert orchestrator.semantic_cache.count() == 0


def test_orchestrator_keeps_the_entry_when_the_pipeline_agrees(workspace_tmp_path, monkeypatch):
    orchestrator = _orchestrator(workspace_tmp_path, monkeypatch, SEMANTIC_FIREWALL_LLM_GATE_ENABLED="0",
                                 SEMANTIC_FIREWALL_CACHE_SIM_THRESHOLD="0.5",
                                 SEMANTIC_FIREWALL_CACHE_REVALIDATE_RATE="1.0")
    orchestrator.agents = _stub_agents(secret_agent=CriticalSecretAgent("Secrets Detector", "SECRET"))
    orchestrator.semantic_cache.add_threat(ATTACK, "INJECTION", "CRITICAL", "Injection Detector",
                                           confidence=0.95, llm_confirmed=True)

    decision = orchestrator.analyze(PARAPHRASE)

    assert decision.cache_revalidated is True and decision.action == "BLOCK"
    assert orchestrator.semantic_cache.count() == 1


def test_orchestrator_never_revalidates_seeded_entries(workspace_tmp_path, monkeypatch):
    orchestrator = _orchestrator(workspace_tmp_path, monkeypatch, SEMANTIC_FIREWALL_CACHE_SIM_THRESHOLD="0.5",
                                 SEMANTIC_FIREWALL_CACHE_REVALIDATE_RATE="1.0")
    injection = CleanAgent("Injection Detector", "INJECTION")
    orchestrator.agents = _stub_agents(injection=injection)
    orchestrator.semantic_cache.seed_threats([ATTACK], threat_type="INJECTION", severity="CRITICAL")

    decision = orchestrator.analyze(PARAPHRASE)

    assert decision.cache_revalidated is False
    assert decision.action == "BLOCK" and decision.resolution_stage == "semantic_cache"
    assert injection.calls == 0
