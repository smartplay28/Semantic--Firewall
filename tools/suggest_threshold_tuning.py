import argparse
import json
from collections import defaultdict
from pathlib import Path
import sys

# Allow running as a standalone script: `python tools/suggest_threshold_tuning.py`
ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from orchestrator.audit_logger import AuditLogger


AGENT_TO_THREAT = {
    "PII Detector": "PII",
    "Secrets Detector": "SECRET",
    "Abuse Detector": "ABUSE",
    "Injection Detector": "INJECTION",
    "Unsafe Content Detector": "UNSAFE_CONTENT",
    "Threat Intel Detector": "THREAT_INTEL",
    "Custom Rules Detector": "CUSTOM_RULE",
}

TIGHTEN_ACTION = {
    "LOW": "FLAG",
    "MEDIUM": "REDACT",
    "HIGH": "BLOCK",
    "CRITICAL": "BLOCK",
}

RELAX_ACTION = {
    "LOW": "ALLOW",
    "MEDIUM": "FLAG",
    "HIGH": "REDACT",
    "CRITICAL": "BLOCK",
}


def suggest_overrides(adjustments: list[dict], min_count: int) -> dict:
    grouped = defaultdict(lambda: defaultdict(dict))
    for item in adjustments:
        if item.get("count", 0) < min_count:
            continue
        profile = item.get("profile", "balanced")
        agent = item.get("agent", "")
        severity = item.get("severity", "LOW")
        feedback_type = item.get("feedback_type", "false_positive")
        threat_type = AGENT_TO_THREAT.get(agent)
        if not threat_type:
            continue
        action_map = RELAX_ACTION if feedback_type == "false_positive" else TIGHTEN_ACTION
        grouped[profile][threat_type][severity] = action_map.get(severity, "FLAG")
    return grouped


def suggest_agent_confidence_thresholds(adjustments: list[dict], min_count: int) -> dict:
    # Start from current default detector confidence threshold for LLM-backed agents.
    defaults = {
        "Injection Detector": 0.50,
        "Unsafe Content Detector": 0.50,
    }
    deltas = defaultdict(float)
    counts = defaultdict(int)

    for item in adjustments:
        agent = item.get("agent", "")
        feedback_type = item.get("feedback_type", "false_positive")
        count = int(item.get("count", 0))
        if agent not in defaults or count < min_count:
            continue
        direction = 1.0 if feedback_type == "false_positive" else -1.0
        # Larger count means stronger recommendation.
        step = min(0.10, 0.02 * count)
        deltas[agent] += direction * step
        counts[agent] += count

    recommendations = {}
    for agent, base in defaults.items():
        adjusted = max(0.30, min(0.90, base + deltas.get(agent, 0.0)))
        recommendations[agent] = {
            "suggested_confidence_threshold": round(adjusted, 2),
            "base_threshold": base,
            "support_count": counts.get(agent, 0),
            "rationale": (
                "Increase threshold to reduce false positives."
                if adjusted > base
                else "Decrease threshold to reduce false negatives."
                if adjusted < base
                else "Keep threshold unchanged."
            ),
        }
    return recommendations


def main():
    parser = argparse.ArgumentParser(description="Suggest policy threshold tuning from audit feedback.")
    parser.add_argument("--db-path", default="var/audit.db")
    parser.add_argument("--workspace-id", default=None)
    parser.add_argument("--min-count", type=int, default=2)
    parser.add_argument("--limit", type=int, default=200)
    parser.add_argument("--output", default="results/threshold_tuning_recommendations.json")
    args = parser.parse_args()

    logger = AuditLogger(db_path=args.db_path)
    adjustments = logger.suggest_policy_adjustments(limit=args.limit, workspace_id=args.workspace_id)
    overrides = suggest_overrides(adjustments, min_count=args.min_count)

    payload = {
        "generated_at": __import__("datetime").datetime.now().isoformat(),
        "workspace_id": args.workspace_id,
        "source": "feedback_adjustments",
        "min_count": args.min_count,
        "recommendations": overrides,
        "agent_confidence_threshold_recommendations": suggest_agent_confidence_thresholds(
            adjustments,
            min_count=args.min_count,
        ),
        "raw_adjustments": adjustments,
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Saved threshold tuning recommendations to {output_path}")


if __name__ == "__main__":
    main()
