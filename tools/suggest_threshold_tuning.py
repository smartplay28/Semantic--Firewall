import argparse
import json
from collections import defaultdict
from pathlib import Path

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


def main():
    parser = argparse.ArgumentParser(description="Suggest policy threshold tuning from audit feedback.")
    parser.add_argument("--db-path", default="audit.db")
    parser.add_argument("--workspace-id", default=None)
    parser.add_argument("--min-count", type=int, default=2)
    parser.add_argument("--limit", type=int, default=200)
    parser.add_argument("--output", default="threshold_tuning_recommendations.json")
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
        "raw_adjustments": adjustments,
    }

    output_path = Path(args.output)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Saved threshold tuning recommendations to {output_path}")


if __name__ == "__main__":
    main()
