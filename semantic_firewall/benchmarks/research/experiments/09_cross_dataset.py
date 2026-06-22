"""
Experiment 9: Cross-Dataset Generalization
===========================================
Tests the Semantic Firewall against a completely unseen slice of the
neuralchemy/Prompt-injection-dataset to prove it doesn't overfit to the
first 500 samples used in the Ablation and Baseline experiments.

We use samples 500–1000 (indices the firewall has NEVER seen).

Outputs:
  data/results/tables/cross_dataset.csv
"""
import os
import sys
import time
import argparse
from pathlib import Path

from helpers import (
    PROJECT_ROOT, RESULTS_ROOT, TABLES_DIR,
    compute_metrics, format_pct, write_csv_rows, write_json,
    experiment_metadata, normalize_binary_label,
    print_header, print_section,
)

sys.path.insert(0, str(PROJECT_ROOT))
from dotenv import load_dotenv
load_dotenv(PROJECT_ROOT / ".env")

from semantic_firewall.sdk import Firewall

try:
    from datasets import load_dataset
except ImportError:
    load_dataset = None


def main():
    parser = argparse.ArgumentParser(description="Cross-dataset generalization experiment")
    parser.add_argument("--max-samples", type=int, default=500,
                        help="Number of OOD samples to test")
    parser.add_argument("--offset", type=int, default=500,
                        help="Starting index offset into the dataset (skip training samples)")
    parser.add_argument("--sleep", type=float, default=2.0,
                        help="Sleep between samples for rate limiting")
    args = parser.parse_args()

    print_header("EXPERIMENT 9: CROSS-DATASET GENERALIZATION (500 UNSEEN SAMPLES)")

    if load_dataset is None:
        raise RuntimeError("datasets package is required")

    print("  Loading neuralchemy/Prompt-injection-dataset ...")
    dataset = load_dataset("neuralchemy/Prompt-injection-dataset", "core")
    full_test = list(dataset["test"])
    print(f"  Full dataset size: {len(full_test)}")

    # Use a completely different slice than baseline/ablation (which used [0:500])
    end_idx = min(args.offset + args.max_samples, len(full_test))
    test_set = full_test[args.offset:end_idx]
    print(f"  Using samples [{args.offset}:{end_idx}] = {len(test_set)} unseen samples\n")

    if len(test_set) == 0:
        print("  ERROR: No samples available at this offset. Dataset may be too small.")
        return

    # Reset semantic cache to ensure cold start
    from semantic_firewall.core.orchestrator.semantic_cache import SemanticCache
    import threading
    SemanticCache._instance = None
    SemanticCache._lock = threading.Lock()

    os.environ["SEMANTIC_FIREWALL_DISABLE_LLM_DETECTORS"] = "0"
    os.environ["SEMANTIC_FIREWALL_LLM_GATE_ENABLED"] = "1"
    os.environ["SEMANTIC_FIREWALL_LLM_GATE_THRESHOLD"] = "1.0"
    fw = Firewall()
    fw._local._cache.clear()

    tp = fp = tn = fn = 0
    latencies_ms = []

    print_section("Running Evaluation")
    for i, example in enumerate(test_set):
        text = example["text"]
        true_label = normalize_binary_label(example["label"])

        try:
            started_at = time.perf_counter()
            decision = fw.analyze(text)
            latencies_ms.append((time.perf_counter() - started_at) * 1000)
            predicted = 1 if decision.action in {"BLOCK", "FLAG", "REDACT"} else 0
        except Exception as e:
            print(f"  [!] Error on sample {i}: {e}")
            predicted = 0

        if true_label == 1 and predicted == 1: tp += 1
        elif true_label == 0 and predicted == 1: fp += 1
        elif true_label == 0 and predicted == 0: tn += 1
        else: fn += 1

        if (i + 1) % 50 == 0:
            print(f"    Progress: {i+1}/{len(test_set)}")
        if args.sleep > 0:
            time.sleep(args.sleep)

    metrics = compute_metrics(tp, fp, tn, fn)
    avg_latency = sum(latencies_ms) / len(latencies_ms) if latencies_ms else 0

    # Print results
    print_section("Cross-Dataset Generalization Results")
    print(f"  Samples Tested  : {len(test_set)} (indices {args.offset}-{end_idx})")
    print(f"  TP={tp}, FP={fp}, TN={tn}, FN={fn}")
    print(f"  Accuracy        : {format_pct(metrics['accuracy'])}")
    print(f"  Precision       : {format_pct(metrics['precision'])}")
    print(f"  Recall          : {format_pct(metrics['recall'])}")
    print(f"  F1 Score        : {format_pct(metrics['f1'])}")
    print(f"  FPR             : {format_pct(metrics['false_positive_rate'])}")
    print(f"  FNR             : {format_pct(metrics['false_negative_rate'])}")
    print(f"  Avg Latency     : {avg_latency:.2f} ms")

    # Save results
    result_data = {
        "meta": experiment_metadata(),
        "dataset_source": "neuralchemy/Prompt-injection-dataset:core:test",
        "sample_range": f"{args.offset}-{end_idx}",
        "total_samples": len(test_set),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "metrics": metrics,
        "avg_latency_ms": round(avg_latency, 2),
    }
    write_json(RESULTS_ROOT / "baselines" / "cross_dataset_generalization.json", result_data)

    # CSV table
    header = ["metric", "value"]
    rows = [
        ["dataset", "neuralchemy (unseen slice)"],
        ["sample_range", f"{args.offset}-{end_idx}"],
        ["num_samples", len(test_set)],
        ["accuracy", round(metrics["accuracy"], 4)],
        ["precision", round(metrics["precision"], 4)],
        ["recall", round(metrics["recall"], 4)],
        ["f1", round(metrics["f1"], 4)],
        ["false_positive_rate", round(metrics["false_positive_rate"], 4)],
        ["false_negative_rate", round(metrics["false_negative_rate"], 4)],
        ["avg_latency_ms", round(avg_latency, 2)],
    ]
    write_csv_rows(TABLES_DIR / "cross_dataset.csv", header, rows)

    print_header("EXPERIMENT 9 COMPLETE")


if __name__ == "__main__":
    main()
