import argparse
import json
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


def weighted_overall_score(precision: float, recall: float, f1_score: float, avg_latency_ms: float) -> float:
    # Simple research-friendly proxy score.
    quality = (0.25 * precision) + (0.25 * recall) + (0.50 * f1_score)
    latency_penalty = min(avg_latency_ms / 1000.0, 0.20)
    return round(max(0.0, (quality - latency_penalty) * 100.0), 2)


def main():
    parser = argparse.ArgumentParser(description="Run benchmark from tests-derived dataset against available adapters.")
    parser.add_argument("--dataset", default="datasets/benchmark_from_tests.jsonl")
    parser.add_argument("--leaderboard-output", default="leaderboard.json")
    parser.add_argument("--results-output", default="results/benchmark_results.json")
    args = parser.parse_args()

    dataset_path = Path(args.dataset)
    if not dataset_path.exists():
        raise FileNotFoundError(
            f"Dataset not found at {dataset_path}. Run: python benchmarking/extract_dataset_from_tests.py"
        )
    samples = read_jsonl(dataset_path)
    if not samples:
        raise RuntimeError("Dataset is empty.")

    adapters = [SemanticFirewallAdapter(), RegexHeuristicBaselineAdapter(), *build_optional_market_adapters()]
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
        for sample in samples:
            result = adapter.predict(sample["text"])
            preds.append(result.predicted_label)
            latencies.append(result.latency_ms)
            if result.error:
                errors += 1

        metrics = compute_binary_metrics(truths, preds)
        avg_latency_ms = round(statistics.mean(latencies), 2) if latencies else 0.0
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
            "updated_at": str(date.today()),
        }
        leaderboard_rows.append(row)
        benchmark_details["tools"].append(
            {
                "tool": adapter.name,
                "status": "ok",
                "errors": errors,
                "latency_ms": {
                    "avg": avg_latency_ms,
                    "p95": round(statistics.quantiles(latencies, n=20)[18], 2) if len(latencies) >= 20 else avg_latency_ms,
                },
                "metrics": metrics,
            }
        )

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
