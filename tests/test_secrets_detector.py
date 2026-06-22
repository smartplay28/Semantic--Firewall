from unittest import result

import pytest
from semantic_firewall.core.agents.secrets_detector import SecretsDetectorAgent

@pytest.fixture
def agent():
    return SecretsDetectorAgent()


# â”€â”€ True Positive Tests (should detect) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestSecretsTruePositives:

    def test_detects_aws_access_key(self, agent):
        result = agent.run("AWS key: AKIAIOSFODNN7EXAMPLE")
        assert result.threat_found is True
        types = [m.secret_type for m in result.matched]
        assert "aws_access_key" in types

    def test_detects_github_personal_token(self, agent):
        result = agent.run("ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890ab")
        assert result.threat_found is True

    def test_detects_github_oauth_token(self, agent):
        result = agent.run("gho_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890ab")
        assert result.threat_found is True

    def test_detects_stripe_live_key(self, agent):
        result = agent.run("stripe key: sk_live_abcdefghijklmnopqrstuvwx")
        assert result.threat_found is True
        types = [m.secret_type for m in result.matched]
        assert "stripe_secret_key" in types

    def test_detects_stripe_test_key(self, agent):
        result = agent.run("sk_test_abcdefghijklmnopqrstuvwx")
        assert result.threat_found is True
        types = [m.secret_type for m in result.matched]
        assert "stripe_test_key" in types

    def test_detects_sendgrid_key(self, agent):
        result = agent.run("SG.aBcDeFgHiJkLmNoPqRsTuVw.XyZ1234567890abcdefghijklmnopqrstuvwxyz1234567")
        assert result.threat_found is True

    def test_detects_openai_key(self, agent):
        result = agent.run("sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcdefghij12")
        assert result.threat_found is True
        types = [m.secret_type for m in result.matched]
        assert "openai_api_key" in types

    def test_detects_slack_token(self, agent):
        result = agent.run("xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx")
        assert result.threat_found is True
        types = [m.secret_type for m in result.matched]
        assert "slack_token" in types

    def test_detects_slack_webhook(self, agent):
        result = agent.run("https://hooks.slack.com/services/T12345678/B12345678/abcdefghijklmnop")
        assert result.threat_found is True
        types = [m.secret_type for m in result.matched]
        assert "slack_webhook" in types

    def test_detects_rsa_private_key(self, agent):
        result = agent.run("-----BEGIN RSA PRIVATE KEY-----")
        assert result.threat_found is True
        types = [m.secret_type for m in result.matched]
        assert "rsa_private_key" in types

    def test_detects_mongodb_uri(self, agent):
        result = agent.run("mongodb://admin:password123@cluster0.mongodb.net/mydb")
        assert result.threat_found is True

    def test_detects_postgres_uri(self, agent):
        result = agent.run("postgresql://user:pass@db.example.com:5432/mydb")
        assert result.threat_found is True
        types = [m.secret_type for m in result.matched]
        assert "postgres_uri" in types

    def test_detects_hardcoded_password(self, agent):
        result = agent.run("password = 'SuperSecret123'")
        assert result.threat_found is True
        types = [m.secret_type for m in result.matched]
        assert "generic_password_assignment" in types

    def test_detects_jwt(self, agent):
        result = agent.run("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP")
        assert result.threat_found is True
        types = [m.secret_type for m in result.matched]
        assert "jwt_token" in types

    def test_detects_npm_token(self, agent):
        result = agent.run("npm_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890ab")
        assert result.threat_found is True

    def test_detects_bearer_token(self, agent):
        result = agent.run("Authorization: Bearer eyJhbGciOiJSUzI1NiJ9abcdefghijklm")
        assert result.threat_found is True
        types = [m.secret_type for m in result.matched]
        assert "bearer_token" in types


# â”€â”€ True Negative Tests (should NOT detect) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestSecretsTrueNegatives:

    def test_clean_question(self, agent):
        result = agent.run("What is the best way to learn Python?")
        assert result.threat_found is False

    def test_clean_greeting(self, agent):
        result = agent.run("Hello! How can I help you today?")
        assert result.threat_found is False

    def test_clean_code_no_secrets(self, agent):
        result = agent.run("def connect(): return db.connect(host='localhost')")
        assert result.threat_found is False


# â”€â”€ Severity Tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestSecretsSeverity:

    def test_aws_key_is_critical(self, agent):
        result = agent.run("AKIAIOSFODNN7EXAMPLE")
        assert result.severity == "CRITICAL"

    def test_rsa_private_key_is_critical(self, agent):
        result = agent.run("-----BEGIN RSA PRIVATE KEY-----")
        assert result.severity == "CRITICAL"

    def test_stripe_test_key_is_medium(self, agent):
        result = agent.run("sk_test_abcdefghijklmnopqrstuvwx")
        assert result.severity == "MEDIUM"

    def test_clean_is_none(self, agent):
        result = agent.run("Hello world")
        assert result.severity == "NONE"


# â”€â”€ Redact Tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestSecretsRedact:

    def test_redacts_aws_key(self, agent):
        redacted = agent.redact("Key: AKIAIOSFODNN7EXAMPLE")
        assert "AKIAIOSFODNN7EXAMPLE" not in redacted
        assert "[AWS_ACCESS_KEY]" in redacted

    def test_redacts_password(self, agent):
        redacted = agent.redact("password = 'mysecret123'")
        assert "mysecret123" not in redacted

    def test_clean_text_unchanged(self, agent):
        text = "The weather is nice today."
        redacted = agent.redact(text)
        assert "[AWS_ACCESS_KEY]" not in redacted


class TestSecretsConfidence:

    def test_aws_key_confidence_is_present(self, agent):
        result = agent.run("AWS key: AKIAIOSFODNN7EXAMPLE")
        aws_match = next(match for match in result.matched if match.secret_type == "aws_access_key")
        assert 0.9 <= aws_match.confidence <= 1.0


# â”€â”€ Edge Case Tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestSecretsEdgeCases:

    def test_empty_string(self, agent):
        result = agent.run("")
        assert result.threat_found is False

    def test_partial_key_no_match(self, agent):
        result = agent.run("AKIA123")  # too short to match AWS key
        assert result.threat_found is False

    def test_multiple_secrets(self, agent):
        result = agent.run(
            "AWS: AKIAIOSFODNN7EXAMPLE\n"
            "GitHub: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890ab"
        )
        assert result.threat_found is True
        assert len(result.matched) >= 2

