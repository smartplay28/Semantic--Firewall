import sqlite3
import json
import hashlib
import re
from datetime import datetime
from typing import List, Optional

from orchestrator.paths import var_path


class AuditLogger:
    def __init__(self, db_path: str | None = None):
        self.db_path = db_path or str(var_path("audit.db"))
        self._init_db()

    def _init_db(self):
        """Create tables if they don't exist."""
        from pathlib import Path

        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp       TEXT NOT NULL,
                    workspace_id    TEXT DEFAULT 'default',
                    session_id      TEXT,
                    input_text      TEXT NOT NULL,
                    scan_target     TEXT DEFAULT 'input',
                    policy_profile  TEXT DEFAULT 'balanced',
                    action          TEXT NOT NULL,
                    severity        TEXT NOT NULL,
                    review_status   TEXT DEFAULT 'none',
                    review_assignee TEXT DEFAULT '',
                    review_notes    TEXT DEFAULT '',
                    triggered_agents TEXT,
                    reason          TEXT,
                    processing_time_ms REAL,
                    matched_threats TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS feedback_log (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    audit_log_id    INTEGER NOT NULL,
                    timestamp       TEXT NOT NULL,
                    feedback_type   TEXT NOT NULL,
                    notes           TEXT,
                    FOREIGN KEY(audit_log_id) REFERENCES audit_log(id)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS promotion_log (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp       TEXT NOT NULL,
                    workspace_id    TEXT DEFAULT 'default',
                    item_type       TEXT NOT NULL,
                    item_id         TEXT NOT NULL,
                    item_name       TEXT NOT NULL,
                    note            TEXT,
                    metadata        TEXT
                )
            """)
            columns = {
                row[1] for row in conn.execute("PRAGMA table_info(audit_log)").fetchall()
            }
            if "input_hash" not in columns:
                conn.execute(
                    "ALTER TABLE audit_log ADD COLUMN input_hash TEXT"
                )
            if "scan_target" not in columns:
                conn.execute(
                    "ALTER TABLE audit_log ADD COLUMN scan_target TEXT DEFAULT 'input'"
                )
            if "review_status" not in columns:
                conn.execute(
                    "ALTER TABLE audit_log ADD COLUMN review_status TEXT DEFAULT 'none'"
                )
            if "policy_profile" not in columns:
                conn.execute(
                    "ALTER TABLE audit_log ADD COLUMN policy_profile TEXT DEFAULT 'balanced'"
                )
            if "workspace_id" not in columns:
                conn.execute(
                    "ALTER TABLE audit_log ADD COLUMN workspace_id TEXT DEFAULT 'default'"
                )
            if "review_assignee" not in columns:
                conn.execute(
                    "ALTER TABLE audit_log ADD COLUMN review_assignee TEXT DEFAULT ''"
                )
            if "review_notes" not in columns:
                conn.execute(
                    "ALTER TABLE audit_log ADD COLUMN review_notes TEXT DEFAULT ''"
                )
            conn.commit()
        print(f"[AuditLogger] Database ready at '{self.db_path}'")

    def log(self,
            input_text: str,
            action: str,
            severity: str,
            triggered_agents: List[str],
            reason: str,
            processing_time_ms: float,
            matched_threats: dict,
            scan_target: str = "input",
            policy_profile: str = "balanced",
            workspace_id: str = "default",
            session_id: Optional[str] = None):
        """Log a firewall decision to the database."""
        with sqlite3.connect(self.db_path) as conn:
            review_status = "pending" if action in {"FLAG", "REDACT", "BLOCK"} else "none"
            conn.execute("""
                INSERT INTO audit_log (
                    timestamp, workspace_id, session_id, input_text, scan_target, action, severity,
                    policy_profile, review_status, triggered_agents, reason, processing_time_ms, matched_threats, input_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                datetime.now().isoformat(),
                workspace_id or "default",
                session_id,
                input_text[:500],           # truncate long inputs
                scan_target,
                action,
                severity,
                policy_profile,
                review_status,
                json.dumps(triggered_agents),
                reason[:500],
                processing_time_ms,
                json.dumps(matched_threats),
                hashlib.sha256(input_text.encode("utf-8")).hexdigest(),
            ))
            conn.commit()

    def log_promotion(
        self,
        item_type: str,
        item_id: str,
        item_name: str,
        note: str = "",
        metadata: Optional[dict] = None,
        workspace_id: str = "default",
    ):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO promotion_log (
                    timestamp, workspace_id, item_type, item_id, item_name, note, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                datetime.now().isoformat(),
                workspace_id or "default",
                item_type,
                item_id,
                item_name[:200],
                note[:500],
                json.dumps(metadata or {}),
            ))
            conn.commit()

    def submit_feedback(self, audit_log_id: int, feedback_type: str, notes: str = ""):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO feedback_log (
                    audit_log_id, timestamp, feedback_type, notes
                ) VALUES (?, ?, ?, ?)
            """, (
                audit_log_id,
                datetime.now().isoformat(),
                feedback_type,
                notes[:500],
            ))
            conn.commit()

    def get_feedback_for_entry(self, audit_log_id: int) -> List[dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT * FROM feedback_log
                WHERE audit_log_id = ?
                ORDER BY id DESC
            """, (audit_log_id,)).fetchall()
        return [dict(row) for row in rows]

    def get_feedback_summary(self, workspace_id: Optional[str] = None) -> dict:
        where_clause = ""
        params = ()
        if workspace_id:
            where_clause = """
                WHERE audit_log_id IN (
                    SELECT id FROM audit_log WHERE workspace_id = ?
                )
            """
            params = (workspace_id,)
        with sqlite3.connect(self.db_path) as conn:
            counts = dict(conn.execute("""
                SELECT feedback_type, COUNT(*) FROM feedback_log
                """ + where_clause + """
                GROUP BY feedback_type
            """, params).fetchall())
        return counts

    def get_recent(
        self,
        limit: int = 20,
        action: Optional[str] = None,
        severity: Optional[str] = None,
        scan_target: Optional[str] = None,
        review_status: Optional[str] = None,
        search: Optional[str] = None,
        policy_profile: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> List[dict]:
        """Return the most recent N audit entries."""
        filters = []
        params = []
        if action:
            filters.append("action = ?")
            params.append(action)
        if severity:
            filters.append("severity = ?")
            params.append(severity)
        if scan_target:
            filters.append("scan_target = ?")
            params.append(scan_target)
        if review_status:
            filters.append("review_status = ?")
            params.append(review_status)
        if policy_profile:
            filters.append("policy_profile = ?")
            params.append(policy_profile)
        if workspace_id:
            filters.append("workspace_id = ?")
            params.append(workspace_id)
        if search:
            filters.append("(reason LIKE ? OR input_text LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%"])
        where_clause = f"WHERE {' AND '.join(filters)}" if filters else ""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(f"""
                SELECT * FROM audit_log
                {where_clause}
                ORDER BY id DESC
                LIMIT ?
            """, (*params, limit)).fetchall()
        return [dict(row) for row in rows]

    def get_review_queue(
        self,
        limit: int = 50,
        severity: Optional[str] = None,
        scan_target: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> List[dict]:
        filters = ["review_status = 'pending'"]
        params = []
        if severity:
            filters.append("severity = ?")
            params.append(severity)
        if scan_target:
            filters.append("scan_target = ?")
            params.append(scan_target)
        if workspace_id:
            filters.append("workspace_id = ?")
            params.append(workspace_id)
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(f"""
                SELECT * FROM audit_log
                WHERE {' AND '.join(filters)}
                ORDER BY id DESC
                LIMIT ?
            """, (*params, limit)).fetchall()
        return [dict(row) for row in rows]

    def get_review_queue_analytics(self, workspace_id: Optional[str] = None) -> dict:
        where_clause = "WHERE review_status = 'pending'" + (" AND workspace_id = ?" if workspace_id else "")
        params = (workspace_id,) if workspace_id else ()
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(f"""
                SELECT
                    id,
                    timestamp,
                    severity,
                    COALESCE(review_assignee, '') AS review_assignee
                FROM audit_log
                {where_clause}
                ORDER BY id DESC
            """, params).fetchall()

        buckets = {"under_1h": 0, "1h_to_24h": 0, "1d_to_7d": 0, "over_7d": 0}
        assignees = {}
        severities = {}
        for row in rows:
            age_hours = self._age_hours(row["timestamp"])
            if age_hours < 1:
                buckets["under_1h"] += 1
            elif age_hours < 24:
                buckets["1h_to_24h"] += 1
            elif age_hours < 24 * 7:
                buckets["1d_to_7d"] += 1
            else:
                buckets["over_7d"] += 1
            assignee = row["review_assignee"] or "unassigned"
            assignees[assignee] = assignees.get(assignee, 0) + 1
            severity = row["severity"] or "NONE"
            severities[severity] = severities.get(severity, 0) + 1

        return {
            "pending_total": len(rows),
            "age_buckets": buckets,
            "assignee_load": assignees,
            "severity_mix": severities,
        }

    def set_review_status(
        self,
        audit_log_id: int,
        review_status: str,
        review_assignee: str = "",
        review_notes: str = "",
    ):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                UPDATE audit_log
                SET review_status = ?, review_assignee = ?, review_notes = ?
                WHERE id = ?
            """, (review_status, review_assignee[:200], review_notes[:500], audit_log_id))
            conn.commit()

    def get_stats(self, workspace_id: Optional[str] = None) -> dict:
        """Return aggregated statistics."""
        where_clause = "WHERE workspace_id = ?" if workspace_id else ""
        params = (workspace_id,) if workspace_id else ()
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute(
                f"SELECT COUNT(*) FROM audit_log {where_clause}",
                params,
            ).fetchone()[0]

            action_counts = dict(conn.execute("""
                SELECT action, COUNT(*) FROM audit_log
                """ + where_clause + """
                GROUP BY action
            """, params).fetchall())

            severity_counts = dict(conn.execute("""
                SELECT severity, COUNT(*) FROM audit_log
                """ + where_clause + """
                GROUP BY severity
            """, params).fetchall())

            target_counts = dict(conn.execute("""
                SELECT scan_target, COUNT(*) FROM audit_log
                """ + where_clause + """
                GROUP BY scan_target
            """, params).fetchall())

            profile_counts = dict(conn.execute("""
                SELECT policy_profile, COUNT(*) FROM audit_log
                """ + where_clause + """
                GROUP BY policy_profile
            """, params).fetchall())

            avg_latency = conn.execute("""
                SELECT AVG(processing_time_ms) FROM audit_log
                """ + where_clause,
                params,
            ).fetchone()[0] or 0.0

            recent_blocks = conn.execute("""
                SELECT COUNT(*) FROM audit_log
                WHERE action = 'BLOCK'
                AND timestamp >= datetime('now', '-1 hour')
            """ + (" AND workspace_id = ?" if workspace_id else ""), params).fetchone()[0]

        return {
            "total_requests":   total,
            "action_counts":    action_counts,
            "severity_counts":  severity_counts,
            "target_counts":    target_counts,
            "profile_counts":   profile_counts,
            "avg_latency_ms":   round(avg_latency, 2),
            "blocks_last_hour": recent_blocks,
        }

    def export_recent(self, limit: int = 200, workspace_id: Optional[str] = None) -> List[dict]:
        return self.get_recent(limit=limit, workspace_id=workspace_id)

    def get_feedback_insights(self, workspace_id: Optional[str] = None) -> dict:
        where_clause = "WHERE a.workspace_id = ?" if workspace_id else ""
        params = (workspace_id,) if workspace_id else ()
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT f.feedback_type, f.notes, a.triggered_agents, a.severity, a.policy_profile
                FROM feedback_log f
                JOIN audit_log a ON a.id = f.audit_log_id
                """ + where_clause + """
                ORDER BY f.id DESC
            """, params).fetchall()

        feedback_counts = {}
        agent_counts = {}
        severity_counts = {}
        profile_counts = {}
        top_terms = {}

        for row in rows:
            feedback_type = row["feedback_type"]
            feedback_counts[feedback_type] = feedback_counts.get(feedback_type, 0) + 1
            severity = row["severity"]
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            profile = row["policy_profile"] or "balanced"
            profile_counts[profile] = profile_counts.get(profile, 0) + 1
            for agent in json.loads(row["triggered_agents"] or "[]"):
                key = f"{feedback_type}:{agent}"
                agent_counts[key] = agent_counts.get(key, 0) + 1
            text = (row["notes"] or "").lower()
            for token in re.findall(r"[a-z][a-z0-9_]{3,}", text):
                if token in {"false", "positive", "negative", "should", "would", "there", "because"}:
                    continue
                top_terms[token] = top_terms.get(token, 0) + 1

        hotspot_agents = sorted(
            [{"label": key, "count": value} for key, value in agent_counts.items()],
            key=lambda item: item["count"],
            reverse=True,
        )[:5]
        hotspot_terms = sorted(
            [{"term": key, "count": value} for key, value in top_terms.items() if value > 1],
            key=lambda item: item["count"],
            reverse=True,
        )[:8]

        return {
            "feedback_counts": feedback_counts,
            "hotspot_agents": hotspot_agents,
            "severity_counts": severity_counts,
            "profile_counts": profile_counts,
            "hotspot_terms": hotspot_terms,
        }

    def suggest_policy_adjustments(self, limit: int = 8, workspace_id: Optional[str] = None) -> List[dict]:
        where_clause = "WHERE a.workspace_id = ?" if workspace_id else ""
        params = (workspace_id,) if workspace_id else ()
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT f.feedback_type, a.triggered_agents, a.policy_profile, a.severity, a.reason
                FROM feedback_log f
                JOIN audit_log a ON a.id = f.audit_log_id
                """ + where_clause + """
                ORDER BY f.id DESC
            """, params).fetchall()

        counters = {}
        for row in rows:
            profile = row["policy_profile"] or "balanced"
            severity = row["severity"] or "LOW"
            for agent in json.loads(row["triggered_agents"] or "[]"):
                key = (profile, agent, row["feedback_type"], severity)
                counters[key] = counters.get(key, 0) + 1

        suggestions = []
        for (profile, agent, feedback_type, severity), count in sorted(counters.items(), key=lambda item: item[1], reverse=True):
            if feedback_type == "false_positive":
                suggestion = {
                    "profile": profile,
                    "agent": agent,
                    "feedback_type": feedback_type,
                    "count": count,
                    "recommendation": f"Consider adding an allowlist pattern or relaxing {agent} in profile '{profile}'.",
                    "priority": "HIGH" if count >= 3 else "MEDIUM",
                    "severity": severity,
                }
            else:
                suggestion = {
                    "profile": profile,
                    "agent": agent,
                    "feedback_type": feedback_type,
                    "count": count,
                    "recommendation": f"Consider tightening {agent} or lowering thresholds in profile '{profile}'.",
                    "priority": "HIGH" if count >= 2 else "MEDIUM",
                    "severity": severity,
                }
            suggestions.append(suggestion)
            if len(suggestions) >= limit:
                break
        return suggestions

    def get_reviewer_timeline(self, limit_days: int = 14, workspace_id: Optional[str] = None) -> List[dict]:
        where_clause = "WHERE a.workspace_id = ?" if workspace_id else ""
        params = (workspace_id,) if workspace_id else ()
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT substr(f.timestamp, 1, 10) AS day, f.feedback_type, COUNT(*) AS total
                FROM feedback_log f
                JOIN audit_log a ON a.id = f.audit_log_id
                """ + where_clause + """
                GROUP BY substr(f.timestamp, 1, 10), f.feedback_type
                ORDER BY day DESC
                LIMIT ?
            """, (*params, limit_days * 3)).fetchall()
        return [dict(row) for row in rows]

    def suggest_rules_from_feedback(self, limit: int = 5, workspace_id: Optional[str] = None) -> List[dict]:
        where_clause = "AND a.workspace_id = ?" if workspace_id else ""
        params = (workspace_id,) if workspace_id else ()
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT a.input_text, f.notes
                FROM feedback_log f
                JOIN audit_log a ON a.id = f.audit_log_id
                WHERE f.feedback_type = 'false_negative'
                """ + where_clause + """
                ORDER BY f.id DESC
                LIMIT 200
            """, params).fetchall()

        phrase_counts = {}
        examples = {}

        for row in rows:
            text = f"{row['input_text'] or ''} {row['notes'] or ''}"
            candidates = re.findall(r"\b[A-Z][a-zA-Z0-9]+(?:\s+[A-Z][a-zA-Z0-9]+){0,2}\b", text)
            candidates += re.findall(r'"([^"]{4,60})"', text)
            for candidate in candidates:
                phrase = candidate.strip()
                if len(phrase) < 4:
                    continue
                phrase_counts[phrase] = phrase_counts.get(phrase, 0) + 1
                examples.setdefault(phrase, row["input_text"])

        suggestions = []
        for phrase, count in sorted(phrase_counts.items(), key=lambda item: item[1], reverse=True):
            if count < 1:
                continue
            suggestions.append(
                {
                    "name": f"Suggested rule: {phrase[:40]}",
                    "pattern": re.escape(phrase),
                    "description": f"Suggested from {count} false-negative feedback item(s).",
                    "severity": "MEDIUM" if count == 1 else "HIGH",
                    "scope": "both",
                    "tags": ["suggested", "feedback"],
                    "example": examples.get(phrase, ""),
                    "support": count,
                }
            )
            if len(suggestions) >= limit:
                break
        return suggestions

    def get_promotion_history(self, limit: int = 50, workspace_id: Optional[str] = None) -> List[dict]:
        where_clause = "WHERE workspace_id = ?" if workspace_id else ""
        params = (workspace_id, limit) if workspace_id else (limit,)
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(f"""
                SELECT * FROM promotion_log
                {where_clause}
                ORDER BY id DESC
                LIMIT ?
            """, params).fetchall()
        return [dict(row) for row in rows]

    def _age_hours(self, timestamp: str) -> float:
        try:
            created = datetime.fromisoformat(timestamp)
            return max(0.0, (datetime.now() - created).total_seconds() / 3600.0)
        except Exception:
            return 0.0

    def clear(self):
        """Clear all audit logs (use with caution)."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM audit_log")
            conn.commit()
        print("[AuditLogger] All logs cleared.")
