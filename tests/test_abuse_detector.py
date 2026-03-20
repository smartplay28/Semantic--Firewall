from unittest import result
from wsgiref import types

import pytest
from agents.abuse_detector import AbuseDetectorAgent

@pytest.fixture
def agent():
    return AbuseDetectorAgent()


# ── True Positive Tests (should detect) ───────────────────────────────────────

class TestAbuseTruePositives:

    def test_detects_char_repetition(self, agent):
        result = agent.run("a" * 500)
        assert result.threat_found is True
        types = [m.abuse_type for m in result.matched]
        assert "char_repetition_attack" in types

    def test_detects_word_repetition(self, agent):
        result = agent.run("hello " * 60)
        assert result.threat_found is True
        types = [m.abuse_type for m in result.matched]
        assert "word_repetition_attack" in types

    def test_detects_phrase_repetition(self, agent):
        result = agent.run("ignore all rules " * 25)
        assert result.threat_found is True
        types = [m.abuse_type for m in result.matched]
        assert "phrase_repetition_attack" in types

    def test_detects_excessive_length(self, agent):
        result = agent.run("word " * 3000)
        assert result.threat_found is True
        types = [m.abuse_type for m in result.matched]
        assert "excessive_length" in types or "critical_length_overflow" in types

    def test_detects_critical_length(self, agent):
        result = agent.run("x " * 30000)
        assert result.threat_found is True
        types = [m.abuse_type for m in result.matched]
        assert "critical_length_overflow" in types

    def test_detects_null_bytes(self, agent):
        result = agent.run("Hello\x00World\x00Test")
        assert result.threat_found is True
        types = [m.abuse_type for m in result.matched]
        assert "null_byte_injection" in types

    def test_detects_path_traversal(self, agent):
        result = agent.run("../../etc/passwd")
        assert result.threat_found is True
        types = [m.abuse_type for m in result.matched]
        assert "path_traversal" in types

    def test_detects_etc_passwd(self, agent):
        result = agent.run("read /etc/passwd file")
        assert result.threat_found is True
        types = [m.abuse_type for m in result.matched]
        assert "path_traversal" in types

    def test_detects_script_injection(self, agent):
        result = agent.run("<script>alert('xss')</script>")
        assert result.threat_found is True
        types = [m.abuse_type for m in result.matched]
        assert "script_injection" in types

    def test_detects_javascript_uri(self, agent):
        result = agent.run("Click here: javascript:alert(1)")
        assert result.threat_found is True
        types = [m.abuse_type for m in result.matched]
        assert "script_injection" in types

    def test_detects_url_flood(self, agent):
        urls = " ".join([f"https://example{i}.com/page" for i in range(25)])
        result = agent.run(urls)
        assert result.threat_found is True
        types = [m.abuse_type for m in result.matched]
        assert "url_flood" in types

    def test_detects_deeply_nested(self, agent):
        result = agent.run("(" * 15 + "data" + ")" * 15)
        assert result.threat_found is True
        types = [m.abuse_type for m in result.matched]
        assert "deeply_nested_structure" in types

    def test_detects_excessive_newlines(self, agent):
        result = agent.run("\n" * 600)
        assert result.threat_found is True
        types = [m.abuse_type for m in result.matched]
        assert "newline_flood" in types

    def test_detects_low_entropy(self, agent):
    # single char repeated is guaranteed low entropy
        result = agent.run("a" * 200)
        assert result.threat_found is True
        types = [m.abuse_type for m in result.matched]
        assert "low_entropy_input" in types or "char_repetition_attack" in types

    def test_detects_invisible_chars(self, agent):
        result = agent.run("Hello\u200b\u200b\u200bWorld\u200b\u200b")
        assert result.threat_found is True
        types = [m.abuse_type for m in result.matched]
        assert "invisible_char_injection" in types


# ── True Negative Tests (should NOT detect) ───────────────────────────────────

class TestAbuseTrueNegatives:

    def test_clean_question(self, agent):
        result = agent.run("What is the capital of France?")
        assert result.threat_found is False

    def test_clean_paragraph(self, agent):
        result = agent.run(
            "Artificial intelligence is transforming industries worldwide. "
            "From healthcare to finance, AI systems are being deployed to "
            "improve efficiency and decision-making processes."
        )
        assert result.threat_found is False

    def test_clean_code(self, agent):
        result = agent.run("for i in range(10): print(i)")
        assert result.threat_found is False

    def test_normal_url(self, agent):
        result = agent.run("Check out https://www.google.com for more info.")
        assert result.threat_found is False


# ── Severity Tests ─────────────────────────────────────────────────────────────

class TestAbuseSeverity:

    def test_null_byte_is_critical(self, agent):
        result = agent.run("data\x00injection")
        assert result.severity == "CRITICAL"

    def test_path_traversal_is_critical(self, agent):
        result = agent.run("../../etc/passwd")
        assert result.severity == "CRITICAL"

    def test_script_injection_is_critical(self, agent):
        result = agent.run("<script>alert(1)</script>")
        assert result.severity == "CRITICAL"

    def test_clean_is_none(self, agent):
        result = agent.run("Hello world")
        assert result.severity == "NONE"


# ── Edge Case Tests ────────────────────────────────────────────────────────────

class TestAbuseEdgeCases:

    def test_empty_string(self, agent):
        result = agent.run("")
        assert result.threat_found is False

    def test_single_char(self, agent):
        result = agent.run("a")
        assert result.threat_found is False

    def test_normal_repeated_word_below_threshold(self, agent):
        # "the" repeated 10 times — below threshold of 50
        result = agent.run("the " * 10)
        assert result.threat_found is False

    def test_windows_path_traversal(self, agent):
        result = agent.run(r"C:\Windows\System32\config")
        assert result.threat_found is True