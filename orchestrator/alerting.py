import json
import smtplib
import urllib.request
from email.message import EmailMessage
from typing import Dict, Optional

from orchestrator.settings import AlertingSettings


class AlertManager:
    """Best-effort alert dispatcher for webhook/slack/email."""

    def __init__(
        self,
        webhook_url: str = "",
        slack_webhook_url: str = "",
        smtp_host: str = "",
        smtp_port: int = 587,
        smtp_user: str = "",
        smtp_password: str = "",
        email_from: str = "",
        email_to: str = "",
        min_severity: str = "HIGH",
    ):
        self.webhook_url = webhook_url
        self.slack_webhook_url = slack_webhook_url
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_password = smtp_password
        self.email_from = email_from
        self.email_to = email_to
        self.min_severity = min_severity

    @classmethod
    def from_env(cls):
        settings = AlertingSettings.from_env()
        return cls(
            webhook_url=settings.webhook_url,
            slack_webhook_url=settings.slack_webhook_url,
            smtp_host=settings.smtp_host,
            smtp_port=settings.smtp_port,
            smtp_user=settings.smtp_user,
            smtp_password=settings.smtp_password,
            email_from=settings.email_from,
            email_to=settings.email_to,
            min_severity=settings.min_severity,
        )

    def _severity_rank(self, severity: str) -> int:
        order = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        return order.get((severity or "NONE").upper(), 0)

    def should_alert(self, severity: str) -> bool:
        return self._severity_rank(severity) >= self._severity_rank(self.min_severity)

    def dispatch(self, payload: Dict):
        severity = payload.get("severity", "NONE")
        if not self.should_alert(severity):
            return
        if self.webhook_url:
            self._post_json(self.webhook_url, payload)
        if self.slack_webhook_url:
            self._post_json(
                self.slack_webhook_url,
                {"text": f"[Semantic Firewall] {payload.get('action')} {severity}: {payload.get('reason', '')[:200]}"},
            )
        if self.smtp_host and self.email_from and self.email_to:
            self._send_email(payload)

    def _post_json(self, url: str, payload: Dict):
        request = urllib.request.Request(
            url=url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=8):  # nosec B310
            pass

    def _send_email(self, payload: Dict):
        message = EmailMessage()
        message["Subject"] = f"[Semantic Firewall] {payload.get('action')} {payload.get('severity')}"
        message["From"] = self.email_from
        message["To"] = self.email_to
        message.set_content(json.dumps(payload, indent=2))
        with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=8) as smtp:
            smtp.starttls()
            if self.smtp_user:
                smtp.login(self.smtp_user, self.smtp_password)
            smtp.send_message(message)
