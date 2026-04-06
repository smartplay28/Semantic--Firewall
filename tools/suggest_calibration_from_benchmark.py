import argparse
import json
from pathlib import Path


CATEGORY_TO_THREAT = {
    "injection": "INJECTION",
    "unsafe_content": "UNSAFE_CONTENT",
    "pii": "PII",
    "secrets": "SECRET",
    "abuse": "ABUSE",
}


def suggest_calibration(error_buckets: dict) -> dict:
    recommendations: dict[str, dict] = {}
    for category, bucket in error_buckets.items():
        threat = CATEGORY_TO_THREAT.get(category)
        if not threat:
            continue
        fp = int(bucket.get("fp", 0))
        fn = int(bucket.get("fn", 0))
        total = max(1, int(bucket.get("total", 1)))
        fp_rate = fp / total
        fn_rate = fn / total

        # Start from neutral affine calibration p' = p * slope + bias
        slope = 1.0
        bias = 0.0
        rationale = "No significant shift suggested."
        if fn_rate - fp_rate > 0.08:
            # Too many misses -> become more sensitive.
            slope = 1.08
            bias = 0.03
            rationale = "Higher FN than FP: nudge probabilities up."
        elif fp_rate - fn_rate > 0.08:
            # Too many false alarms -> become stricter.
            slope = 0.92
            bias = -0.03
            rationale = "Higher FP than FN: nudge probabilities down."

        recommendations[threat] = {
            "suggested_slope": round(slope, 3),
            "suggested_bias": round(bias, 3),
            "fp": fp,
            "fn": fn,
            "total": total,
            "rationale": rationale,
        }
    return recommendations


def main():
    parser = argparse.ArgumentParser(description="Suggest calibration params from benchmark error buckets.")
    parser.add_argument("--results", default="results/benchmark_results.json")
    parser.add_argument("--tool-name", default="Semantic Firewall (balanced)")
    parser.add_argument("--output", default="results/calibration_recommendations.json")
    args = parser.parse_args()

    results_path = Path(args.results)
    payload = json.loads(results_path.read_text(encoding="utf-8"))
    tools = payload.get("tools", [])
    selected = next((tool for tool in tools if tool.get("tool") == args.tool_name), None)
    if selected is None:
        raise RuntimeError(f"Tool '{args.tool_name}' not found in {args.results}")

    error_buckets = selected.get("error_buckets_by_category", {})
    recs = suggest_calibration(error_buckets)
    out = {
        "source_results": args.results,
        "tool_name": args.tool_name,
        "recommendations": recs,
    }
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"Saved calibration recommendations to {out_path}")


if __name__ == "__main__":
    main()
