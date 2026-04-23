import re
from dataclasses import dataclass, field
from typing import List, Optional

from orchestrator.custom_rules import CustomRulesManager


@dataclass
class CustomRuleMatch:
    rule_id: str
    rule_name: str
    custom_type: str
    description: str
    evidence: str
    severity_weight: int
    redact: bool
    confidence: float
    match_count: int = 1  # how many times this rule matched in the text


@dataclass
class DetectionResult:
    agent_name: str
    threat_found: bool
    threat_type: str
    matched: List[CustomRuleMatch]
    severity: str
    summary: str


class CustomRulesDetectorAgent:
    def __init__(self, rules_path: str | None = None):
        self.name = "Custom Rules Detector"
        self.rules_manager = CustomRulesManager(rules_path=rules_path)

        self.severity_weights = {
            "LOW":      1,
            "MEDIUM":   2,
            "HIGH":     3,
            "CRITICAL": 4,
        }

        # Configurable constants
        self.EVIDENCE_BOOST_THRESHOLD = 24  # evidence length to boost confidence

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _confidence_for(self, severity_weight: int, evidence: str) -> float:
        base = {
            4: 0.95,
            3: 0.88,
            2: 0.80,
            1: 0.72,
        }.get(severity_weight, 0.72)
        if len(evidence) >= self.EVIDENCE_BOOST_THRESHOLD:
            base += 0.03
        return min(base, 0.98)

    def _redaction_label(self, rule: dict) -> str:
        threat_type = str(rule.get("threat_type", "CUSTOM_RULE")).upper()
        clean = re.sub(r"[^A-Z0-9]+", "_", threat_type).strip("_")
        return f"[{clean or 'CUSTOM_RULE'}]"

    def _calculate_severity(self, matches: List[CustomRuleMatch]) -> str:
        if not matches:
            return "NONE"
        max_weight = max(m.severity_weight for m in matches)
        return {
            4: "CRITICAL",
            3: "HIGH",
            2: "MEDIUM",
            1: "LOW",
        }.get(max_weight, "LOW")

    def _is_excepted(self, rule: dict, text: str) -> bool:
        exceptions = rule.get("exceptions") or []
        for pattern in exceptions:
            try:
                if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
                    return True
            except re.error:
                continue
        return False

    # ── Main run ───────────────────────────────────────────────────────────────

    def run(
        self,
        text: str,
        scan_target: str = "both",
        workspace_id: str = "default"
    ) -> DetectionResult:

        # Early exit for empty input
        if not text or not text.strip():
            return DetectionResult(
                agent_name=self.name,
                threat_found=False,
                threat_type="CUSTOM_RULE",
                matched=[],
                severity="NONE",
                summary="Empty input — skipped."
            )

        matches: List[CustomRuleMatch] = []

        for rule in self.rules_manager.get_enabled_rules(
            scan_target=scan_target,
            workspace_id=workspace_id,
        ):
            if self._is_excepted(rule, text):
                continue

            # FIX: wrap in try/except to handle bad regex patterns gracefully
            try:
                all_found = re.findall(
                    rule["pattern"], text, re.IGNORECASE | re.DOTALL
                )
            except re.error:
                continue  # skip malformed rules silently

            if all_found:
                severity = rule.get("severity", "LOW").upper()
                severity_weight = self.severity_weights.get(severity, 1)
                match_count = len(all_found)

                # get first match as evidence string
                first = all_found[0]
                evidence = (first if isinstance(first, str) else first[0])[:120]

                matches.append(CustomRuleMatch(
                    rule_id=rule["id"],
                    rule_name=rule["name"],
                    custom_type=rule.get("threat_type", "CUSTOM_RULE").upper(),
                    description=rule["description"],
                    evidence=evidence,
                    severity_weight=severity_weight,
                    redact=bool(rule.get("redact", False)),
                    confidence=self._confidence_for(severity_weight, evidence),
                    match_count=match_count,
                ))

        severity = self._calculate_severity(matches)
        threat_found = bool(matches)

        # FIX: use threat_type from highest severity match, not last match
        threat_type = "CUSTOM_RULE"
        if matches:
            top_match = max(matches, key=lambda m: m.severity_weight)
            threat_type = top_match.custom_type

        summary = (
            f"Matched {len(matches)} custom rule(s). Severity: {severity}."
            if threat_found
            else "No custom rules matched."
        )

        return DetectionResult(
            agent_name=self.name,
            threat_found=threat_found,
            threat_type=threat_type,
            matched=matches,
            severity=severity,
            summary=summary,
        )

    # ── Redact ─────────────────────────────────────────────────────────────────

    def redact(
        self,
        text: str,
        scan_target: str = "both",
        workspace_id: str = "default"
    ) -> str:
        redacted = text
        for rule in self.rules_manager.get_enabled_rules(
            scan_target=scan_target,
            workspace_id=workspace_id,
        ):
            if rule.get("redact") and not self._is_excepted(rule, redacted):
                try:
                    redacted = re.sub(
                        rule["pattern"],
                        self._redaction_label(rule),
                        redacted,
                        flags=re.IGNORECASE | re.DOTALL,
                    )
                except re.error:
                    continue
        return redacted

    # ── Test a single rule ─────────────────────────────────────────────────────

    def test_rule(self, rule: dict, text: str) -> dict:
        """Test a single rule against text. Useful for UI rule builder."""
        if self._is_excepted(rule, text):
            return {
                "matched":    False,
                "excepted":   True,
                "evidence":   "",
                "match_count": 0,
            }
        try:
            all_found = re.findall(
                rule["pattern"], text, re.IGNORECASE | re.DOTALL
            )
            first = all_found[0] if all_found else None
            evidence = ""
            if first:
                evidence = (first if isinstance(first, str) else first[0])[:120]
            return {
                "matched":     bool(all_found),
                "excepted":    False,
                "evidence":    evidence,
                "match_count": len(all_found),
            }
        except re.error as e:
            return {
                "matched":     False,
                "excepted":    False,
                "evidence":    "",
                "match_count": 0,
                "error":       str(e),
            }

    # ── Validate a rule before saving ─────────────────────────────────────────

    def validate_rule(self, rule: dict) -> dict:
        """
        Validate a rule dict before saving to the custom rules store.
        Returns {"valid": True/False, "error": "reason if invalid"}
        """
        required_fields = ["id", "name", "pattern", "severity", "description"]
        for f in required_fields:
            if f not in rule:
                return {"valid": False, "error": f"Missing required field: '{f}'"}

        # validate regex
        try:
            re.compile(rule["pattern"])
        except re.error as e:
            return {"valid": False, "error": f"Invalid regex pattern: {e}"}

        # validate severity
        if rule.get("severity", "").upper() not in self.severity_weights:
            return {
                "valid": False,
                "error": "severity must be one of: LOW, MEDIUM, HIGH, CRITICAL"
            }

        # validate exceptions if present
        for exc in rule.get("exceptions", []):
            try:
                re.compile(exc)
            except re.error as e:
                return {
                    "valid": False,
                    "error": f"Invalid exception pattern '{exc}': {e}"
                }

        return {"valid": True, "error": None}

    # ── Stats ──────────────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        """Return stats about currently loaded rules. Useful for UI dashboard."""
        rules = self.rules_manager.get_enabled_rules()
        return {
            "total_rules": len(rules),
            "by_severity": {
                "CRITICAL": sum(1 for r in rules if r.get("severity", "").upper() == "CRITICAL"),
                "HIGH":     sum(1 for r in rules if r.get("severity", "").upper() == "HIGH"),
                "MEDIUM":   sum(1 for r in rules if r.get("severity", "").upper() == "MEDIUM"),
                "LOW":      sum(1 for r in rules if r.get("severity", "").upper() == "LOW"),
            },
            "redact_enabled":  sum(1 for r in rules if r.get("redact")),
            "with_exceptions": sum(1 for r in rules if r.get("exceptions")),
        }
