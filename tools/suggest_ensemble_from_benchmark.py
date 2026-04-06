import argparse
import json
from pathlib import Path


CATEGORY_TO_WEIGHT_ENV = {
    "injection": "SEMANTIC_FIREWALL_WEIGHT_INJECTION",
    "unsafe_content": "SEMANTIC_FIREWALL_WEIGHT_UNSAFE_CONTENT",
    "abuse": "SEMANTIC_FIREWALL_WEIGHT_ABUSE",
    "secrets": "SEMANTIC_FIREWALL_WEIGHT_SECRETS",
    "pii": "SEMANTIC_FIREWALL_WEIGHT_PII",
}


def suggest_weight(base_weight: float, fp: int, fn: int, total: int) -> float:
    total = max(1, total)
    gap = (fn - fp) / total
    # Small bounded adjustment to avoid destabilizing production defaults.
    if gap > 0.08:
        return min(2.0, base_weight + 0.15)
    if gap < -0.08:
        return max(0.5, base_weight - 0.15)
    return base_weight


def suggest_thresholds(current: dict, fp_total: int, fn_total: int) -> dict:
    flag = float(current.get("flag", 1.8))
    redact = float(current.get("redact", 2.6))
    block = float(current.get("block", 3.5))

    if fn_total > fp_total:
        # Too many misses: make escalation easier.
        return {
            "flag": round(max(1.0, flag - 0.1), 3),
            "redact": round(max(1.6, redact - 0.1), 3),
            "block": round(max(2.5, block - 0.1), 3),
        }
    if fp_total > fn_total:
        # Too many false alarms: make escalation stricter.
        return {
            "flag": round(min(2.5, flag + 0.1), 3),
            "redact": round(min(3.4, redact + 0.1), 3),
            "block": round(min(4.6, block + 0.1), 3),
        }
    return {"flag": flag, "redact": redact, "block": block}


def main():
    parser = argparse.ArgumentParser(description="Suggest ensemble weights/thresholds from benchmark error buckets.")
    parser.add_argument("--results", default="results/benchmark_results.json")
    parser.add_argument("--tool-name", default="Semantic Firewall (balanced)")
    parser.add_argument("--output", default="results/ensemble_recommendations.json")
    args = parser.parse_args()

    payload = json.loads(Path(args.results).read_text(encoding="utf-8"))
    tools = payload.get("tools", [])
    selected = next((tool for tool in tools if tool.get("tool") == args.tool_name), None)
    if selected is None:
        raise RuntimeError(f"Tool '{args.tool_name}' not found in {args.results}")

    buckets = selected.get("error_buckets_by_category", {})
    fp_total = sum(int(bucket.get("fp", 0)) for bucket in buckets.values())
    fn_total = sum(int(bucket.get("fn", 0)) for bucket in buckets.values())

    base_weights = {
        "SEMANTIC_FIREWALL_WEIGHT_INJECTION": 1.3,
        "SEMANTIC_FIREWALL_WEIGHT_UNSAFE_CONTENT": 1.3,
        "SEMANTIC_FIREWALL_WEIGHT_ABUSE": 1.0,
        "SEMANTIC_FIREWALL_WEIGHT_SECRETS": 1.2,
        "SEMANTIC_FIREWALL_WEIGHT_PII": 1.0,
    }
    suggested_weights = dict(base_weights)
    for category, env_name in CATEGORY_TO_WEIGHT_ENV.items():
        bucket = buckets.get(category, {})
        suggested_weights[env_name] = round(
            suggest_weight(
                base_weight=base_weights[env_name],
                fp=int(bucket.get("fp", 0)),
                fn=int(bucket.get("fn", 0)),
                total=int(bucket.get("total", 0)),
            ),
            3,
        )

    thresholds = suggest_thresholds(
        current={"flag": 1.8, "redact": 2.6, "block": 3.5},
        fp_total=fp_total,
        fn_total=fn_total,
    )

    env_overrides = {
        **suggested_weights,
        "SEMANTIC_FIREWALL_ENSEMBLE_FLAG_THRESHOLD": thresholds["flag"],
        "SEMANTIC_FIREWALL_ENSEMBLE_REDACT_THRESHOLD": thresholds["redact"],
        "SEMANTIC_FIREWALL_ENSEMBLE_BLOCK_THRESHOLD": thresholds["block"],
    }
    output = {
        "source_results": args.results,
        "tool_name": args.tool_name,
        "total_fp": fp_total,
        "total_fn": fn_total,
        "env_overrides": env_overrides,
        "rationale": (
            "Lowered thresholds / raised sensitive weights because false negatives dominate."
            if fn_total > fp_total
            else "Raised thresholds / lowered sensitive weights because false positives dominate."
            if fp_total > fn_total
            else "No global threshold shift suggested."
        ),
    }
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(f"Saved ensemble recommendations to {args.output}")


if __name__ == "__main__":
    main()
