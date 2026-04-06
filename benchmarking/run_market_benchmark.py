import argparse
import contextlib
import json
import io
import random
import statistics
from datetime import date
from pathlib import Path
import sys

# Allow running as a standalone script: `python benchmarking/run_market_benchmark.py`
ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from benchmarking.adapters import (
    RegexHeuristicBaselineAdapter,
    SemanticFirewallAdapter,
    build_optional_market_adapters,
)


def read_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def compute_binary_metrics(truths: list[str], preds: list[str]) -> dict:
    tp = fp = tn = fn = 0
    for y_true, y_pred in zip(truths, preds):
        true_threat = y_true == "threat"
        pred_threat = y_pred == "threat"
        if true_threat and pred_threat:
            tp += 1
        elif not true_threat and pred_threat:
            fp += 1
        elif not true_threat and not pred_threat:
            tn += 1
        else:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    accuracy = (tp + tn) / len(truths) if truths else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "accuracy": round(accuracy, 4),
    }


def compute_error_buckets(samples: list[dict], truths: list[str], preds: list[str]) -> dict:
    buckets: dict[str, dict[str, int]] = {}
    for sample, y_true, y_pred in zip(samples, truths, preds):
        category = sample.get("category", "unknown")
        bucket = buckets.setdefault(category, {"fp": 0, "fn": 0, "total": 0})
        bucket["total"] += 1
        true_threat = y_true == "threat"
        pred_threat = y_pred == "threat"
        if pred_threat and not true_threat:
            bucket["fp"] += 1
        elif true_threat and not pred_threat:
            bucket["fn"] += 1
    return buckets


def weighted_overall_score(precision: float, recall: float, f1_score: float, avg_latency_ms: float) -> float:
    # Simple research-friendly proxy score.
    quality = (0.25 * precision) + (0.25 * recall) + (0.50 * f1_score)
    latency_penalty = min(avg_latency_ms / 1000.0, 0.20)
    return round(max(0.0, (quality - latency_penalty) * 100.0), 2)


def percentile_ms(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return round(ordered[0], 2)
    rank = (len(ordered) - 1) * percentile
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    weight = rank - low
    result = ordered[low] * (1 - weight) + ordered[high] * weight
    return round(result, 2)


def main():
    parser = argparse.ArgumentParser(description="Run benchmark from tests-derived dataset against available adapters.")
    parser.add_argument("--dataset", default="datasets/benchmark_from_tests.jsonl")
    parser.add_argument("--leaderboard-output", default="leaderboard.json")
    parser.add_argument("--results-output", default="results/benchmark_results.json")
    parser.add_argument("--max-samples", type=int, default=0, help="Use only first N samples after deterministic shuffle (0 = all).")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for deterministic sampling.")
    parser.add_argument("--quiet", action="store_true", help="Suppress noisy detector stdout while benchmarking.")
    parser.add_argument(
        "--policy-profiles",
        default="balanced,strict,developer_assistant,customer_support,research",
        help="Comma-separated policy profiles for Semantic Firewall benchmarking.",
    )
    args = parser.parse_args()

    dataset_path = Path(args.dataset)
    if not dataset_path.exists():
        raise FileNotFoundError(
            f"Dataset not found at {dataset_path}. Run: python benchmarking/extract_dataset_from_tests.py"
        )
    samples = read_jsonl(dataset_path)
    if not samples:
        raise RuntimeError("Dataset is empty.")
    if args.max_samples and args.max_samples > 0 and len(samples) > args.max_samples:
        random.seed(args.seed)
        random.shuffle(samples)
        samples = samples[: args.max_samples]

    requested_profiles = [
        profile.strip()
        for profile in str(args.policy_profiles).split(",")
        if profile.strip()
    ] or ["balanced"]
    adapters = [
        *[SemanticFirewallAdapter(policy_profile=profile) for profile in requested_profiles],
        RegexHeuristicBaselineAdapter(),
        *build_optional_market_adapters(),
    ]
    truths = [sample["label"] for sample in samples]

    benchmark_details = {"dataset": str(dataset_path), "sample_count": len(samples), "tools": []}
    leaderboard_rows = []

    for adapter in adapters:
        if hasattr(adapter, "available") and not adapter.available():
            benchmark_details["tools"].append({"tool": adapter.name, "status": "skipped_not_installed"})
            continue

        preds = []
        latencies = []
        errors = 0
        timeout_events = 0
        degraded_count = 0
        semantic_llm_stats = {
            "sample_count_with_stats": 0,
            "detectors": {
                "Injection Detector": {
                    "llm_called": 0,
                    "regex_only": 0,
                    "skipped_by_orchestrator_gate": 0,
                    "llm_skipped_reason": {},
                },
                "Unsafe Content Detector": {
                    "llm_called": 0,
                    "regex_only": 0,
                    "skipped_by_orchestrator_gate": 0,
                    "llm_skipped_reason": {},
                },
            },
        }
        for sample in samples:
            if args.quiet:
                with contextlib.redirect_stdout(io.StringIO()):
                    result = adapter.predict(sample["text"])
            else:
                result = adapter.predict(sample["text"])
            preds.append(result.predicted_label)
            latencies.append(result.latency_ms)
            if result.error:
                errors += 1
            timeout_events += int((result.meta or {}).get("timeout_events", 0))
            degraded_count += 1 if (result.meta or {}).get("degraded") else 0
            if adapter.name.startswith("Semantic Firewall ("):
                llm_stats = (result.meta or {}).get("llm_detectors", {})
                if llm_stats:
                    semantic_llm_stats["sample_count_with_stats"] += 1
                for detector_name in ("Injection Detector", "Unsafe Content Detector"):
                    detector_data = llm_stats.get(detector_name)
                    if not detector_data:
                        continue
                    bucket = semantic_llm_stats["detectors"][detector_name]
                    if detector_data.get("llm_called"):
                        bucket["llm_called"] += 1
                    if detector_data.get("regex_only"):
                        bucket["regex_only"] += 1
                    if detector_data.get("skipped_by_orchestrator_gate"):
                        bucket["skipped_by_orchestrator_gate"] += 1
                    reason = detector_data.get("llm_skipped_reason")
                    if reason:
                        bucket["llm_skipped_reason"][reason] = bucket["llm_skipped_reason"].get(reason, 0) + 1

        metrics = compute_binary_metrics(truths, preds)
        error_buckets = compute_error_buckets(samples, truths, preds)
        avg_latency_ms = round(statistics.mean(latencies), 2) if latencies else 0.0
        p50_latency_ms = percentile_ms(latencies, 0.50)
        p95_latency_ms = percentile_ms(latencies, 0.95)
        overall_score = weighted_overall_score(
            precision=metrics["precision"],
            recall=metrics["recall"],
            f1_score=metrics["f1_score"],
            avg_latency_ms=avg_latency_ms,
        )
        row = {
            "tool": adapter.name,
            "overall_score": overall_score,
            "precision": metrics["precision"],
            "recall": metrics["recall"],
            "f1_score": metrics["f1_score"],
            "avg_latency_ms": avg_latency_ms,
            "p50_latency_ms": p50_latency_ms,
            "p95_latency_ms": p95_latency_ms,
            "updated_at": str(date.today()),
        }
        if adapter.name.startswith("Semantic Firewall ("):
            sample_count_with_stats = semantic_llm_stats["sample_count_with_stats"]
            detector_metrics = {}
            for detector_name, detector_bucket in semantic_llm_stats["detectors"].items():
                denominator = sample_count_with_stats or 1
                detector_metrics[detector_name] = {
                    "llm_called_count": detector_bucket["llm_called"],
                    "llm_called_rate": round(detector_bucket["llm_called"] / denominator, 4),
                    "regex_only_count": detector_bucket["regex_only"],
                    "regex_only_rate": round(detector_bucket["regex_only"] / denominator, 4),
                    "skipped_by_orchestrator_gate_count": detector_bucket["skipped_by_orchestrator_gate"],
                    "skipped_by_orchestrator_gate_rate": round(
                        detector_bucket["skipped_by_orchestrator_gate"] / denominator, 4
                    ),
                    "llm_skipped_reason_counts": detector_bucket["llm_skipped_reason"],
                }
            row["llm_detector_metrics"] = {
                "samples_with_telemetry": sample_count_with_stats,
                "detectors": detector_metrics,
            }
        leaderboard_rows.append(row)
        tool_detail = {
            "tool": adapter.name,
            "status": "ok",
            "errors": errors,
            "latency_ms": {
                "avg": avg_latency_ms,
                "p50": p50_latency_ms,
                "p95": p95_latency_ms,
                "timeout_rate": round(timeout_events / max(len(samples), 1), 4),
            },
            "metrics": metrics,
            "error_buckets_by_category": error_buckets,
            "degraded_rate": round(degraded_count / max(len(samples), 1), 4),
        }
        if adapter.name.startswith("Semantic Firewall ("):
            tool_detail["llm_detector_metrics"] = row["llm_detector_metrics"]
        benchmark_details["tools"].append(tool_detail)

    leaderboard_rows.sort(key=lambda item: item["overall_score"], reverse=True)
    leaderboard_payload = {
        "generated_by": "benchmarking/run_market_benchmark.py",
        "dataset": str(dataset_path),
        "rows": leaderboard_rows,
    }
    leaderboard_path = Path(args.leaderboard_output)
    leaderboard_path.write_text(json.dumps(leaderboard_payload, indent=2), encoding="utf-8")

    results_path = Path(args.results_output)
    results_path.parent.mkdir(parents=True, exist_ok=True)
    results_path.write_text(json.dumps(benchmark_details, indent=2), encoding="utf-8")

    print(f"Leaderboard written to {leaderboard_path}")
    print(f"Detailed results written to {results_path}")


if __name__ == "__main__":
    main()
