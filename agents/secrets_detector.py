import re
from dataclasses import dataclass
from typing import List, Dict, Tuple


@dataclass
class SecretMatch:
    secret_type: str
    value: str
    description: str
    confidence: float


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
        self.redaction_labels: Dict[str, str] = {
            "aws_access_key": "[AWS_ACCESS_KEY]",
            "aws_secret_key": "[AWS_SECRET_KEY]",
            "aws_session_token": "[AWS_SESSION_TOKEN]",
            "aws_mfa_device": "[AWS_MFA_ARN]",
            "gcp_api_key": "[GCP_API_KEY]",
            "gcp_oauth_client": "[GCP_OAUTH_CLIENT]",
            "gcp_service_account": "[GCP_SERVICE_ACCOUNT]",
            "azure_subscription": "[AZURE_SUBSCRIPTION_ID]",
            "azure_storage_key": "[AZURE_STORAGE_KEY]",
            "azure_connection_string": "[AZURE_CONNECTION_STRING]",
            "github_personal_token": "[GITHUB_TOKEN]",
            "github_oauth_token": "[GITHUB_TOKEN]",
            "github_app_token": "[GITHUB_APP_TOKEN]",
            "github_refresh_token": "[GITHUB_REFRESH_TOKEN]",
            "gitlab_token": "[GITLAB_TOKEN]",
            "bitbucket_token": "[BITBUCKET_TOKEN]",
            "circleci_token": "[CICD_TOKEN]",
            "travis_ci_token": "[CICD_TOKEN]",
            "stripe_secret_key": "[STRIPE_SECRET_KEY]",
            "stripe_restricted_key": "[STRIPE_RESTRICTED_KEY]",
            "stripe_test_key": "[STRIPE_TEST_KEY]",
            "stripe_publishable_key": "[STRIPE_PUBLISHABLE_KEY]",
            "razorpay_key": "[RAZORPAY_KEY]",
            "razorpay_test_key": "[RAZORPAY_TEST_KEY]",
            "paypal_client_secret": "[PAYPAL_SECRET]",
            "braintree_token": "[BRAINTREE_TOKEN]",
            "twilio_account_sid": "[TWILIO_ACCOUNT_SID]",
            "twilio_auth_token": "[TWILIO_AUTH_TOKEN]",
            "sendgrid_api_key": "[SENDGRID_API_KEY]",
            "mailgun_api_key": "[MAILGUN_API_KEY]",
            "mailchimp_api_key": "[MAILCHIMP_API_KEY]",
            "vonage_api_key": "[VONAGE_API_KEY]",
            "openai_api_key": "[OPENAI_API_KEY]",
            "openai_org_id": "[OPENAI_ORG_ID]",
            "anthropic_api_key": "[ANTHROPIC_API_KEY]",
            "huggingface_token": "[HUGGINGFACE_TOKEN]",
            "cohere_api_key": "[COHERE_API_KEY]",
            "mysql_uri": "[MYSQL_CREDENTIALS]",
            "postgres_uri": "[POSTGRES_CREDENTIALS]",
            "mongodb_uri": "[MONGODB_CREDENTIALS]",
            "redis_uri": "[REDIS_CREDENTIALS]",
            "mssql_uri": "[MSSQL_CREDENTIALS]",
            "elasticsearch_uri": "[ELASTICSEARCH_CREDENTIALS]",
            "rsa_private_key": "[RSA_PRIVATE_KEY]",
            "ec_private_key": "[EC_PRIVATE_KEY]",
            "private_key_generic": "[PRIVATE_KEY]",
            "openssh_private_key": "[OPENSSH_PRIVATE_KEY]",
            "pgp_private_key": "[PGP_PRIVATE_KEY]",
            "certificate": "[CERTIFICATE]",
            "slack_token": "[SLACK_TOKEN]",
            "slack_webhook": "[SLACK_WEBHOOK]",
            "discord_token": "[DISCORD_TOKEN]",
            "discord_webhook": "[DISCORD_WEBHOOK]",
            "twitter_bearer_token": "[TWITTER_BEARER_TOKEN]",
            "facebook_access_token": "[FACEBOOK_ACCESS_TOKEN]",
            "instagram_token": "[INSTAGRAM_TOKEN]",
            "linkedin_token": "[LINKEDIN_TOKEN]",
            "heroku_api_key": "[HEROKU_API_KEY]",
            "docker_auth": "[DOCKER_AUTH]",
            "kubernetes_secret": "[KUBERNETES_SECRET]",
            "npm_token": "[NPM_TOKEN]",
            "pypi_token": "[PYPI_TOKEN]",
            "terraform_token": "[TERRAFORM_TOKEN]",
            "vault_token": "[VAULT_TOKEN]",
            "generic_secret_assignment": "[API_KEY]",
            "generic_password_assignment": "[PASSWORD]",
            "bearer_token": "[BEARER_TOKEN]",
            "basic_auth_header": "[BASIC_AUTH]",
            "jwt_token": "[JWT_TOKEN]",
        }

        # Each entry: secret_type -> (pattern, description, severity_weight)
        # severity_weight: 1=low, 2=medium, 3=high, 4=critical
        self.patterns: Dict[str, Tuple[str, str, int]] = {

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
        
        # Compile regex patterns once at initialization for performance
        self.compiled_patterns: Dict[str, Tuple[re.Pattern, str, int]] = {}
        for secret_type, (pattern, description, weight) in self.patterns.items():
            try:
                self.compiled_patterns[secret_type] = (
                    re.compile(pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL),
                    description,
                    weight
                )
            except re.error as e:
                print(f"[SecretsDetector] Failed to compile pattern '{secret_type}': {e}")

    def _truncate_text(self, text: str, max_length: int) -> Tuple[str, bool]:
        """Truncate text if it exceeds max length.
        
        Args:
            text: Input text
            max_length: Maximum length before truncation
            
        Returns:
            Tuple of (potentially truncated text, was_truncated flag)
        """
        if len(text) > max_length:
            return text[:max_length], True
        return text, False

    def _calculate_severity(self, matched: List[SecretMatch]) -> str:
        """Calculate overall severity based on matched secret types and weights.
        
        CRITICAL: weight 4 secrets found (API keys, private keys, etc.)
        HIGH: weight 3 secrets (tokens, lesser credentials)
        MEDIUM: weight 2 secrets (test keys, low-sensitivity tokens)
        LOW: weight 1 secrets
        
        Args:
            matched: List of detected secrets
            
        Returns:
            Severity level (NONE, LOW, MEDIUM, HIGH, CRITICAL)
        """
        if not matched:
            return "NONE"

        # Get max weight from matched secrets using compiled_patterns
        weights: List[int] = []
        for m in matched:
            _, _, weight = self.compiled_patterns.get(m.secret_type, (None, "", 1))
            weights.append(weight)

        max_weight = max(weights) if weights else 1

        if max_weight == 4:
            return "CRITICAL"
        elif max_weight == 3:
            return "HIGH"
        elif max_weight == 2:
            return "MEDIUM"
        else:
            return "LOW"

    def _confidence_for(self, secret_type: str) -> float:
        """Calculate confidence score for detected secret type.
        
        Args:
            secret_type: Type of secret detected
            
        Returns:
            Confidence score (0.0 to 1.0)
        """
        _, description, weight = self.compiled_patterns.get(secret_type, (None, "", 1))
        if weight >= 4:
            return 0.97
        if weight == 3:
            return 0.88 if "contextual" not in description.lower() else 0.76
        if secret_type in {"jwt_token", "stripe_publishable_key", "openai_org_id"}:
            return 0.68
        return 0.72

    def run(self, text):
        matched = []
        for secret_type, (compiled_pattern, description, _) in self.compiled_patterns.items():
            try:
                for found in compiled_pattern.finditer(text):
                    val = found.group(0).strip()
                    if val:
                        matched.append(SecretMatch(
                            secret_type=secret_type,
                            value=val,
                            description=description,
                            confidence=self._confidence_for(secret_type),
                        ))
            except (re.error, IndexError) as e:
                print(f"[SecretsDetector] Error scanning pattern '{secret_type}': {e}")
                continue  # skip malformed patterns gracefully

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

    def redact(self, text):
        """Redact detected secrets by replacing with typed placeholders.
        
        Args:
            text: Input text containing secrets
            
        Returns:
            Text with secrets replaced by redaction labels
        """
        redacted = text
        for secret_type, (compiled_pattern, _, _) in self.compiled_patterns.items():
            try:
                placeholder = self.redaction_labels.get(secret_type, "[SECRET]")
                redacted = compiled_pattern.sub(placeholder, redacted)
            except (re.error, AttributeError) as e:
                print(f"[SecretsDetector] Error redacting pattern '{secret_type}': {e}")
                continue
        return redacted
