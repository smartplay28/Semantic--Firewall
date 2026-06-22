from collections import defaultdict
from datetime import datetime
from typing import Dict, List


class SessionStore:
    def __init__(self):
        # session_id -> list of past messages + decisions
        self.sessions: Dict[str, List[dict]] = defaultdict(list)
        # session_id -> cumulative threat score
        self.threat_scores: Dict[str, float] = defaultdict(float)

        # Severity -> score mapping
        self.score_map = {
            "NONE":     0.0,
            "LOW":      0.5,
            "MEDIUM":   1.5,
            "HIGH":     3.0,
            "CRITICAL": 5.0,
        }

        # Thresholds
        self.FLAG_THRESHOLD  = 8.0  # cumulative score to escalate to FLAG
        self.BLOCK_THRESHOLD = 12.0  # cumulative score to escalate to BLOCK

    def add_message(self, session_id: str, text: str,
                    decision: str, severity: str):
        """Store a message and update cumulative threat score."""
        self.sessions[session_id].append({
            "text":      text,
            "decision":  decision,
            "severity":  severity,
            "timestamp": datetime.now().isoformat(),
        })
        self.threat_scores[session_id] += self.score_map.get(severity, 0.0)

    def get_history(self, session_id: str) -> List[dict]:
        """Return full message history for a session."""
        return self.sessions.get(session_id, [])

    def get_recent_texts(self, session_id: str, n: int = 3) -> List[str]:
        """Return the last n message texts for combined analysis."""
        history = self.get_history(session_id)
        return [h["text"] for h in history[-n:]]

    def get_threat_score(self, session_id: str) -> float:
        """Return cumulative threat score for a session."""
        return self.threat_scores.get(session_id, 0.0)

    def should_flag(self, session_id: str, threshold: float = None) -> bool:
        limit = self.FLAG_THRESHOLD if threshold is None else threshold
        return self.get_threat_score(session_id) >= limit

    def should_block(self, session_id: str, threshold: float = None) -> bool:
        limit = self.BLOCK_THRESHOLD if threshold is None else threshold
        return self.get_threat_score(session_id) >= limit

    def clear(self, session_id: str):
        """Reset a session (e.g. after user logs out)."""
        self.sessions[session_id] = []
        self.threat_scores[session_id] = 0.0

    def summary(self, session_id: str, flag_threshold: float = None, block_threshold: float = None) -> dict:
        """Return a summary of the session state."""
        return {
            "session_id":       session_id,
            "message_count":    len(self.get_history(session_id)),
            "cumulative_score": self.get_threat_score(session_id),
            "should_flag":      self.should_flag(session_id, threshold=flag_threshold),
            "should_block":     self.should_block(session_id, threshold=block_threshold),
        }
