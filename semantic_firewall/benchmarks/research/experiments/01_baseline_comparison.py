"""
Experiment 1: Baseline Comparison
==================================
Compares three configurations on the neuralchemy prompt-injection dataset:
  A) Regex-Only   â€” LLM agents disabled (env: SEMANTIC_FIREWALL_DISABLE_LLM_DETECTORS=1)
  B) LLM-Only     â€” Regex pre-screening disabled, LLM gate threshold=0
  C) Full System  â€” Default production configuration

Outputs:
  data/results/baselines/baseline_regex_only.json
  data/results/baselines/baseline_llm_only.json
  data/results/baselines/baseline_full_system.json
  data/results/tables/main_comparison.csv
"""
import os
import sys
import json
import time
import argparse
from pathlib import Path

# â”€â”€ project imports â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
from helpers import (
    PROJECT_ROOT, RESULTS_ROOT, TABLES_DIR,
    compute_metrics, format_pct, write_csv_rows, write_json,
    experiment_metadata, load_local_jsonl_dataset, normalize_binary_label,
    print_header, print_section,
)

sys.path.insert(0, str(PROJECT_ROOT))
from dotenv import load_dotenv
load_dotenv(PROJECT_ROOT / ".env")

from semantic_firewall.sdk import Firewall

try:
    from datasets import load_dataset
except ImportError:  # optional when using local pilot datasets
    load_dataset = None


def run_evaluation(fw: Firewall, test_set, label: str, sleep_sec: float = 0.0):
    """Run the firewall on every sample and return metrics + raw results."""
    tp = fp = tn = fn = 0
    raw_results = []
    errors = {"false_positives": [], "false_negatives": []}
    latencies_ms = []

    for i, example in enumerate(test_set):
        text = example["text"]
        true_label = normalize_binary_label(example["label"])
        category = example.get("category", "unknown")
        severity = example.get("severity") or "benign"
        sample_id = example.get("id", i)

        try:
            started_at = time.perf_counter()
            decision = fw.analyze(text)
            latencies_ms.append((time.perf_counter() - started_at) * 1000)
            predicted = 1 if decision.action in {"BLOCK", "FLAG", "REDACT"} else 0
            predicted_action = decision.action
        except Exception as e:
            print(f"  [!] Error on sample {i}: {e}")
            predicted = 0  # fail-open for measurement
            predicted_action = "ERROR"

        if true_label == 1 and predicted == 1:
            tp += 1
        elif true_label == 0 and predicted == 1:
            fp += 1
            if len(errors["false_positives"]) < 20:
                errors["false_positives"].append(
                    {"i": i, "id": sample_id, "text": text[:200], "category": category, "predicted_action": predicted_action}
                )
        elif true_label == 0 and predicted == 0:
            tn += 1
        else:
            fn += 1
            if len(errors["false_negatives"]) < 20:
                errors["false_negatives"].append(
                    {"i": i, "id": sample_id, "text": text[:200], "category": category, "predicted_action": predicted_action}
                )

        raw_results.append({
            "id": sample_id,
            "index": i,
            "true_label": true_label,
            "predicted": predicted,
            "predicted_action": predicted_action,
            "category": category,
            "severity": severity,
        })

        if (i + 1) % 50 == 0:
            print(f"    [{label}] Progress: {i+1}/{len(test_set)}")
        if sleep_sec > 0:
            time.sleep(sleep_sec)

    metrics = compute_metrics(tp, fp, tn, fn)
    return {
        "label": label,
        "meta": experiment_metadata(),
        "total_samples": len(test_set),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "metrics": metrics,
        "avg_latency_ms": round(sum(latencies_ms) / len(latencies_ms), 2) if latencies_ms else 0.0,
        "errors": errors,
        "raw_results": raw_results,
    }


def load_evaluation_set(dataset_jsonl: str | None, max_samples: int):
    if dataset_jsonl:
        dataset_path = Path(dataset_jsonl)
        if not dataset_path.is_absolute():
            dataset_path = PROJECT_ROOT / dataset_path
        test_set = load_local_jsonl_dataset(dataset_path)
        source_name = str(dataset_path.relative_to(PROJECT_ROOT))
    else:
        if load_dataset is None:
            raise RuntimeError("datasets package is required when --dataset-jsonl is not provided")
        print("Loading neuralchemy/Prompt-injection-dataset ...")
        dataset = load_dataset("neuralchemy/Prompt-injection-dataset", "core")
        test_set = list(dataset["test"])
        source_name = "neuralchemy/Prompt-injection-dataset:core:test"

    if max_samples and max_samples > 0:
        test_set = test_set[: min(max_samples, len(test_set))]
    return test_set, source_name


def main():
    parser = argparse.ArgumentParser(description="Baseline comparison experiment")
    parser.add_argument("--max-samples", type=int, default=200,
                        help="Max samples from the selected dataset (0 = all)")
    parser.add_argument("--sleep", type=float, default=2.0,
                        help="Sleep between samples for LLM configs (rate-limit)")
    parser.add_argument("--dataset-jsonl", type=str, default=None,
                        help="Optional local JSONL benchmark file")
    parser.add_argument("--skip-llm-only", action="store_true",
                        help="Skip the LLM-only baseline for low-cost pilot runs")
    args = parser.parse_args()

    print_header("EXPERIMENT 1: BASELINE COMPARISON")

    # â”€â”€ Load dataset â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    test_set, dataset_source = load_evaluation_set(args.dataset_jsonl, args.max_samples)
    print(f"  Dataset: {dataset_source}")
    print(f"  Using {len(test_set)} test samples.\n")

    baselines_dir = RESULTS_ROOT / "baselines"
    all_results = {}

    # â”€â”€ A) Regex-Only â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    print_section("A) Regex-Only Baseline")
    os.environ["SEMANTIC_FIREWALL_DISABLE_LLM_DETECTORS"] = "1"
    os.environ["SEMANTIC_FIREWALL_LLM_GATE_ENABLED"] = "0"
    fw_regex = Firewall()
    result_a = run_evaluation(fw_regex, test_set, "regex_only", sleep_sec=0.0)
    result_a["dataset_source"] = dataset_source
    write_json(baselines_dir / "baseline_regex_only.json", result_a)
    all_results["regex_only"] = {**result_a["metrics"], "avg_latency_ms": result_a["avg_latency_ms"]}
    print(f"  Regex-Only â†’ F1={format_pct(result_a['metrics']['f1'])}, "
          f"Precision={format_pct(result_a['metrics']['precision'])}, "
          f"Recall={format_pct(result_a['metrics']['recall'])}")

    # â”€â”€ B) LLM-Only â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if not args.skip_llm_only:
        print_section("B) LLM-Only Baseline")
        os.environ["SEMANTIC_FIREWALL_DISABLE_LLM_DETECTORS"] = "0"
        os.environ["SEMANTIC_FIREWALL_LLM_GATE_ENABLED"] = "0"
        os.environ["SEMANTIC_FIREWALL_LLM_GATE_THRESHOLD"] = "0.0"
        fw_llm = Firewall()
        result_b = run_evaluation(fw_llm, test_set, "llm_only", sleep_sec=args.sleep)
        result_b["dataset_source"] = dataset_source
        write_json(baselines_dir / "baseline_llm_only.json", result_b)
        all_results["llm_only"] = {**result_b["metrics"], "avg_latency_ms": result_b["avg_latency_ms"]}
        print(f"  LLM-Only   â†’ F1={format_pct(result_b['metrics']['f1'])}, "
              f"Precision={format_pct(result_b['metrics']['precision'])}, "
              f"Recall={format_pct(result_b['metrics']['recall'])}")
    else:
        print_section("B) LLM-Only Baseline")
        print("  Skipped via --skip-llm-only")

    # â”€â”€ C) Full System â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    print_section("C) Full System (Production)")
    # Restore defaults
    os.environ["SEMANTIC_FIREWALL_DISABLE_LLM_DETECTORS"] = "0"
    os.environ["SEMANTIC_FIREWALL_LLM_GATE_ENABLED"] = "1"
    os.environ["SEMANTIC_FIREWALL_LLM_GATE_THRESHOLD"] = "1.0"
    fw_full = Firewall()
    result_c = run_evaluation(fw_full, test_set, "full_system", sleep_sec=args.sleep)
    result_c["dataset_source"] = dataset_source
    write_json(baselines_dir / "baseline_full_system.json", result_c)
    all_results["full_system"] = {**result_c["metrics"], "avg_latency_ms": result_c["avg_latency_ms"]}
    print(f"  Full System â†’ F1={format_pct(result_c['metrics']['f1'])}, "
          f"Precision={format_pct(result_c['metrics']['precision'])}, "
          f"Recall={format_pct(result_c['metrics']['recall'])}")

    # â”€â”€ Build comparison table â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    print_section("Generating Comparison Table")
    header = ["configuration", "sample_count", "accuracy", "precision", "recall", "f1",
              "false_positive_rate", "false_negative_rate", "avg_latency_ms", "notes"]
    rows = []
    for name, metrics in all_results.items():
        rows.append([
            name,
            len(test_set),
            round(metrics["accuracy"], 4),
            round(metrics["precision"], 4),
            round(metrics["recall"], 4),
            round(metrics["f1"], 4),
            round(metrics["false_positive_rate"], 4),
            round(metrics["false_negative_rate"], 4),
            round(metrics.get("avg_latency_ms", 0.0), 2),
            "pilot_local_jsonl" if args.dataset_jsonl else "hf_dataset",
        ])
    write_csv_rows(TABLES_DIR / "main_comparison.csv", header, rows)

    # â”€â”€ Summary â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    print_header("EXPERIMENT 1 COMPLETE")
    print("Results saved to:")
    print(f"  â€¢ {baselines_dir}")
    print(f"  â€¢ {TABLES_DIR / 'main_comparison.csv'}")


if __name__ == "__main__":
    main()



