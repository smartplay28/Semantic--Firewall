import re
from dataclasses import dataclass
from typing import List, Dict


@dataclass
class SecretMatch:
    secret_type: str
    value: str
    description: str


@dataclass
class DetectionResult:
    agent_name: str
    threat_found: bool
    threat_type: str
    matched: List[SecretMatch]
    severity: str  # NONE / LOW / MEDIUM / HIGH / CRITICAL
    summary: str


class SecretsDetectorAgent:
    def __init__(self):
        self.name = "Secrets Detector"

        # Each entry: secret_type -> (pattern, description, severity_weight)
        # severity_weight: 1=low, 2=medium, 3=high, 4=critical
        self.patterns: Dict[str, tuple] = {

            # ── Cloud Providers ───────────────────────────────────────────────
            "aws_access_key": (
                r'\bAKIA[0-9A-Z]{16}\b',
                "AWS Access Key ID",
                4
            ),
            "aws_secret_key": (
                r'\b[0-9a-zA-Z/+]{40}\b(?=.*(?:aws|secret|key))',
                "AWS Secret Access Key (contextual)",
                4
            ),
            "aws_session_token": (
                r'\bFQoGZXIvYXdzE[0-9A-Za-z/+=]{100,}',
                "AWS Session Token",
                4
            ),
            "aws_mfa_device": (
                r'arn:aws:iam::\d{12}:mfa/[a-zA-Z0-9_+=,.@-]+',
                "AWS MFA Device ARN",
                3
            ),
            "gcp_api_key": (
                r'\bAIza[0-9A-Za-z\-_]{35}\b',
                "Google Cloud Platform API Key",
                4
            ),
            "gcp_oauth_client": (
                r'\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b',
                "GCP OAuth2 Client ID",
                3
            ),
            "gcp_service_account": (
                r'"type"\s*:\s*"service_account"',
                "GCP Service Account JSON key",
                4
            ),
            "azure_subscription": (
                r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b(?=.*(?:azure|subscription|tenant))',
                "Azure Subscription/Tenant ID (contextual)",
                3
            ),
            "azure_storage_key": (
                r'\b[A-Za-z0-9+/]{86}==\b',
                "Azure Storage Account Key",
                4
            ),
            "azure_connection_string": (
                r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+',
                "Azure Storage Connection String",
                4
            ),

            # ── Source Control & CI/CD ────────────────────────────────────────
            "github_personal_token": (
                r'\bghp_[0-9a-zA-Z]{36,}\b',
                "GitHub Personal Access Token",
                4
            ),
            "github_oauth_token": (
                r'\bgho_[0-9a-zA-Z]{36,}\b',
                "GitHub OAuth Token",
                4
            ),
            "github_app_token": (
                r'\bghs_[0-9a-zA-Z]{36}\b',
                "GitHub App Token",
                4
            ),
            "github_refresh_token": (
                r'\bghr_[0-9a-zA-Z]{76}\b',
                "GitHub Refresh Token",
                4
            ),
            "gitlab_token": (
                r'\bglpat-[0-9a-zA-Z\-_]{20}\b',
                "GitLab Personal Access Token",
                4
            ),
            "bitbucket_token": (
                r'\bATBB[0-9a-zA-Z]{32}\b',
                "Bitbucket Access Token",
                4
            ),
            "circleci_token": (
                r'\bcircle-token\s*[=:]\s*[0-9a-fA-F]{40}\b',
                "CircleCI API Token",
                3
            ),
            "travis_ci_token": (
                r'\btravis[_\-]?ci[_\-]?token\s*[=:]\s*[0-9a-zA-Z]{22}\b',
                "Travis CI Token (contextual)",
                3
            ),

            # ── Payment Gateways ──────────────────────────────────────────────
            "stripe_secret_key": (
                r'\bsk_live_[0-9a-zA-Z]{24,}\b',
                "Stripe Live Secret Key",
                4
            ),
            "stripe_restricted_key": (
                r'\brk_live_[0-9a-zA-Z]{24,}\b',
                "Stripe Restricted Live Key",
                4
            ),
            "stripe_test_key": (
                r'\bsk_test_[0-9a-zA-Z]{24,}\b',
                "Stripe Test Secret Key",
                2
            ),
            "stripe_publishable_key": (
                r'\bpk_live_[0-9a-zA-Z]{24,}\b',
                "Stripe Live Publishable Key",
                2
            ),
            "razorpay_key": (
                r'\brzp_live_[0-9a-zA-Z]{14}\b',
                "Razorpay Live Key",
                4
            ),
            "razorpay_test_key": (
                r'\brzp_test_[0-9a-zA-Z]{14}\b',
                "Razorpay Test Key",
                2
            ),
            "paypal_client_secret": (
                r'\bpaypal[_\-]?(client[_\-]?)?secret\s*[=:]\s*[0-9a-zA-Z\-_]{32,}\b',
                "PayPal Client Secret (contextual)",
                4
            ),
            "braintree_token": (
                r'\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b',
                "Braintree Production Token",
                4
            ),

            # ── Communication APIs ────────────────────────────────────────────
            "twilio_account_sid": (
                r'\bAC[0-9a-fA-F]{32}\b',
                "Twilio Account SID",
                3
            ),
            "twilio_auth_token": (
                r'\btwilio[_\-]?auth[_\-]?token\s*[=:]\s*[0-9a-fA-F]{32}\b',
                "Twilio Auth Token (contextual)",
                4
            ),
            "sendgrid_api_key": (
                r'\bSG\.[0-9A-Za-z\-_]{20,}\.[0-9A-Za-z\-_]{40,}\b',
                "SendGrid API Key",
                3
            ),
            "mailgun_api_key": (
                r'\bkey-[0-9a-zA-Z]{32}\b',
                "Mailgun API Key",
                3
            ),
            "mailchimp_api_key": (
                r'\b[0-9a-f]{32}-us[0-9]{1,2}\b',
                "Mailchimp API Key",
                3
            ),
            "vonage_api_key": (
                r'\bvonage[_\-]?api[_\-]?key\s*[=:]\s*[0-9a-zA-Z]{8}\b',
                "Vonage/Nexmo API Key (contextual)",
                3
            ),

            # ── AI / ML APIs ──────────────────────────────────────────────────
            "openai_api_key": (
                r'\bsk-[0-9a-zA-Z]{48}\b',
                "OpenAI API Key",
                4
            ),
            "openai_org_id": (
                r'\borg-[0-9a-zA-Z]{24}\b',
                "OpenAI Organization ID",
                2
            ),
            "anthropic_api_key": (
                r'\bsk-ant-[0-9a-zA-Z\-_]{93}\b',
                "Anthropic API Key",
                4
            ),
            "huggingface_token": (
                r'\bhf_[0-9a-zA-Z]{34}\b',
                "HuggingFace API Token",
                3
            ),
            "cohere_api_key": (
                r'\b[0-9a-zA-Z]{40}\b(?=.*cohere)',
                "Cohere API Key (contextual)",
                3
            ),

            # ── Database Connection Strings ───────────────────────────────────
            "mysql_uri": (
                r'mysql(\+\w+)?://[^:]+:[^@]+@[^\s/]+',
                "MySQL connection string with credentials",
                4
            ),
            "postgres_uri": (
                r'postgres(?:ql)?://[^:]+:[^@]+@[^\s/]+',
                "PostgreSQL connection string with credentials",
                4
            ),
            "mongodb_uri": (
                r'mongodb(\+srv)?://\S+:\S+@\S+',
                "MongoDB connection string with credentials",
                4
            ),
            "redis_uri": (
                r'redis://:[^@]+@[^\s/]+',
                "Redis connection string with password",
                3
            ),
            "mssql_uri": (
                r'(?:mssql|sqlserver)://[^:]+:[^@]+@[^\s/]+',
                "MSSQL connection string with credentials",
                4
            ),
            "elasticsearch_uri": (
                r'https?://[^:]+:[^@]+@[^\s/]*(?:elastic|es)[^\s/]*',
                "Elasticsearch connection string with credentials",
                3
            ),

            # ── Cryptographic Keys & Certificates ────────────────────────────
            "rsa_private_key": (
                r'-----BEGIN RSA PRIVATE KEY-----',
                "RSA Private Key",
                4
            ),
            "ec_private_key": (
                r'-----BEGIN EC PRIVATE KEY-----',
                "EC Private Key",
                4
            ),
            "private_key_generic": (
                r'-----BEGIN PRIVATE KEY-----',
                "Generic Private Key (PKCS#8)",
                4
            ),
            "openssh_private_key": (
                r'-----BEGIN OPENSSH PRIVATE KEY-----',
                "OpenSSH Private Key",
                4
            ),
            "pgp_private_key": (
                r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
                "PGP Private Key Block",
                4
            ),
            "certificate": (
                r'-----BEGIN CERTIFICATE-----',
                "X.509 Certificate",
                2
            ),

            # ── Social / OAuth Tokens ─────────────────────────────────────────
            "slack_token": (
                r'\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24,}\b',
                "Slack API Token",
                4
            ),
            "slack_webhook": (
                r'https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9a-zA-Z]+',
                "Slack Incoming Webhook URL",
                3
            ),
            "discord_token": (
                r'\b[MN][a-zA-Z0-9_\-]{23}\.[a-zA-Z0-9_\-]{6}\.[a-zA-Z0-9_\-]{27}\b',
                "Discord Bot Token",
                4
            ),
            "discord_webhook": (
                r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[0-9a-zA-Z_\-]+',
                "Discord Webhook URL",
                3
            ),
            "twitter_bearer_token": (
                r'\bAAAAAAAAAAAAAAAAAAAAA[0-9a-zA-Z%]{50,}\b',
                "Twitter/X Bearer Token",
                3
            ),
            "facebook_access_token": (
                r'\bEAA[0-9a-zA-Z]{100,}\b',
                "Facebook/Meta Access Token",
                3
            ),
            "instagram_token": (
                r'\bIGQV[0-9a-zA-Z_\-]{100,}\b',
                "Instagram Graph API Token",
                3
            ),
            "linkedin_token": (
                r'\bAQV[0-9a-zA-Z_\-]{100,}\b',
                "LinkedIn OAuth Token",
                3
            ),

            # ── Infrastructure & DevOps ───────────────────────────────────────
            "heroku_api_key": (
                r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b(?=.*heroku)',
                "Heroku API Key (contextual)",
                3
            ),
            "docker_auth": (
                r'"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}"',
                "Docker Registry Auth Token",
                3
            ),
            "kubernetes_secret": (
                r'kind:\s*Secret[\s\S]{0,200}data:',
                "Kubernetes Secret manifest",
                4
            ),
            "npm_token": (
                r'\bnpm_[0-9a-zA-Z]{36,}\b',
                "NPM Access Token",
                3
            ),
            "pypi_token": (
                r'\bpypi-[0-9a-zA-Z\-_]{50,}\b',
                "PyPI API Token",
                3
            ),
            "terraform_token": (
                r'\b[0-9a-zA-Z]{14}\.atlasv1\.[0-9a-zA-Z]{60,}\b',
                "Terraform Cloud/Atlas Token",
                3
            ),
            "vault_token": (
                r'\bhvs\.[0-9A-Za-z]{24}\b',
                "HashiCorp Vault Token",
                4
            ),

            # ── Generic Patterns (catch-all) ──────────────────────────────────
            "generic_secret_assignment": (
                r'(?:secret|api_key|apikey|access_key|auth_token|private_key|client_secret)\s*[=:]\s*["\']?[0-9a-zA-Z\-_/+.]{16,}["\']?',
                "Generic secret/key assignment",
                3
            ),
            "generic_password_assignment": (
                r'(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{6,}["\']',
                "Hardcoded password assignment",
                3
            ),
            "bearer_token": (
                r'\bBearer\s+[0-9a-zA-Z\-_=.]{20,}\b',
                "Bearer token in header",
                3
            ),
            "basic_auth_header": (
                r'\bBasic\s+[A-Za-z0-9+/=]{20,}\b',
                "Basic auth header (base64 credentials)",
                3
            ),
            "jwt_token": (
                r'\beyJ[0-9a-zA-Z_\-]+\.[0-9a-zA-Z_\-]+\.[0-9a-zA-Z_\-]+\b',
                "JSON Web Token (JWT)",
                2
            ),
        }

    def _calculate_severity(self, matched: List[SecretMatch]) -> str:
        if not matched:
            return "NONE"

        # Get max weight from matched secrets
        weights = []
        for m in matched:
            _, _, weight = self.patterns.get(m.secret_type, ("", "", 1))
            weights.append(weight)

        max_weight = max(weights)

        if max_weight == 4:
            return "CRITICAL"
        elif max_weight == 3:
            return "HIGH"
        elif max_weight == 2:
            return "MEDIUM"
        else:
            return "LOW"

    def run(self, text: str) -> DetectionResult:
        matched: List[SecretMatch] = []

        for secret_type, (pattern, description, _) in self.patterns.items():
            try:
                found = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
                if found:
                    val = found.group(0).strip()
                    if val:
                        matched.append(SecretMatch(
                            secret_type=secret_type,
                            value=val,
                            description=description
                        ))
            except re.error:
                continue

        severity = self._calculate_severity(matched)
        threat_found = len(matched) > 0

        summary = (
            f"Detected {len(matched)} secret(s) across "
            f"{len({m.secret_type for m in matched})} category(ies). "
            f"Severity: {severity}."
            if threat_found else "No secrets detected. Input is clean."
        )

        return DetectionResult(
            agent_name=self.name,
            threat_found=threat_found,
            threat_type="SECRET",
            matched=matched,
            severity=severity,
            summary=summary
        )

    def redact(self, text: str) -> str:
        """Returns text with all detected secrets replaced by [REDACTED]."""
        redacted = text
        for _, (pattern, _, _) in self.patterns.items():
            try:
                redacted = re.sub(pattern, "[REDACTED]", redacted,
                                  flags=re.IGNORECASE | re.MULTILINE)
            except re.error:
                continue
        return redacted