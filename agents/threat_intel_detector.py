import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

from orchestrator.threat_intel import ThreatIntelFeedManager


@dataclass
class ThreatIntelMatch:
    intel_id: str
    intel_type: str
    name: str
    description: str
    evidence: str
    confidence: float
    severity_weight: int
    source: str


@dataclass
class DetectionResult:
    agent_name: str
    threat_found: bool
    threat_type: str
    matched: List[ThreatIntelMatch]
    severity: str
    summary: str


class ThreatIntelDetectorAgent:
    def __init__(self, feed_path: str = "threat_intel_feed.json"):
        self.name = "Threat Intel Detector"
        self.feed_manager = ThreatIntelFeedManager(feed_path=feed_path)
        self.severity_weights = {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }
        self._compiled_entries: Dict[str, Tuple[re.Pattern, dict]] = {}
        self._feed_mtime = 0.0

    def _refresh_cache(self):
        path: Path = self.feed_manager.feed_path
        try:
            mtime = path.stat().st_mtime
        except OSError:
            mtime = 0.0
        if self._compiled_entries and mtime <= self._feed_mtime:
            return

        self._compiled_entries = {}
        entries = self.feed_manager.list_entries(enabled_only=True)
        for entry in entries:
            pattern = entry.get("pattern", "")
            try:
                compiled = re.compile(pattern, re.IGNORECASE | re.DOTALL)
            except re.error:
                continue
            self._compiled_entries[entry["id"]] = (compiled, entry)
        self._feed_mtime = mtime

    def _calculate_severity(self, matches: List[ThreatIntelMatch]) -> str:
        if not matches:
            return "NONE"
        max_weight = max(match.severity_weight for match in matches)
        return {
            4: "CRITICAL",
            3: "HIGH",
            2: "MEDIUM",
            1: "LOW",
        }.get(max_weight, "LOW")

    def run(self, text: str, scan_target: str = "input") -> DetectionResult:
        self._refresh_cache()
        matches: List[ThreatIntelMatch] = []

        for _, (compiled, entry) in self._compiled_entries.items():
            scope = entry.get("scope", "both")
            if scope not in {"both", scan_target}:
                continue
            found = compiled.search(text)
            if not found:
                continue
            severity = str(entry.get("severity", "HIGH")).upper()
            severity_weight = self.severity_weights.get(severity, 3)
            matches.append(
                ThreatIntelMatch(
                    intel_id=entry.get("id", "unknown"),
                    intel_type=entry.get("category", "THREAT_INTEL"),
                    name=entry.get("name", "Unnamed signature"),
                    description=entry.get("description", ""),
                    evidence=found.group(0)[:120],
                    confidence=0.93,
                    severity_weight=severity_weight,
                    source=entry.get("source", "feed"),
                )
            )

        severity = self._calculate_severity(matches)
        threat_found = bool(matches)
        summary = (
            f"Matched {len(matches)} threat intelligence signature(s). Severity: {severity}."
            if threat_found
            else "No known threat intelligence signatures matched."
        )

        return DetectionResult(
            agent_name=self.name,
            threat_found=threat_found,
            threat_type="THREAT_INTEL",
            matched=matches,
            severity=severity,
            summary=summary,
        )

