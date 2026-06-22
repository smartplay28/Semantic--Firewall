"""
Experiment 2: Ablation Study
==============================
Removes one component at a time to measure its individual contribution:
  A) Full System         â€” baseline (all components enabled)
  B) Without LLM Gate    â€” LLM agents always invoked (no cost optimization)
  C) Without Semantic Cache â€” No vector-DB threat cache
  D) Without Session Judge â€” No multi-turn session scoring
  E) Without Ensemble     â€” No weighted ensemble scoring

Uses the neuralchemy dataset for consistent comparison with Experiment 1.

Outputs:
  data/results/ablation/ablation_*.json
  data/results/tables/ablation.csv
"""
import os
import sys
import argparse

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
import time

try:
    from datasets import load_dataset
except ImportError:  # optional when using local pilot datasets
    load_dataset = None


def run_eval(fw, test_set, label, sleep_sec=0.0):
    """Simplified evaluation runner."""
    tp = fp = tn = fn = 0
    latencies_ms = []
    for i, example in enumerate(test_set):
        text = example["text"]
        true_label = normalize_binary_label(example["label"])
        try:
            started_at = time.perf_counter()
            decision = fw.analyze(text)
            latencies_ms.append((time.perf_counter() - started_at) * 1000)
            predicted = 1 if decision.action in {"BLOCK", "FLAG", "REDACT"} else 0
        except Exception:
            predicted = 0

        if true_label == 1 and predicted == 1:
            tp += 1
        elif true_label == 0 and predicted == 1:
            fp += 1
        elif true_label == 0 and predicted == 0:
            tn += 1
        else:
            fn += 1

        if (i + 1) % 50 == 0:
            print(f"    [{label}] {i+1}/{len(test_set)}")
        if sleep_sec > 0:
            time.sleep(sleep_sec)

    metrics = compute_metrics(tp, fp, tn, fn)
    return {
        "label": label,
        "meta": experiment_metadata(),
        "total": len(test_set),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "metrics": metrics,
        "avg_latency_ms": round(sum(latencies_ms) / len(latencies_ms), 2) if latencies_ms else 0.0,
    }


def load_evaluation_set(dataset_jsonl: str | None, max_samples: int):
    if dataset_jsonl:
        dataset_path = PROJECT_ROOT / dataset_jsonl if not os.path.isabs(dataset_jsonl) else dataset_jsonl
        dataset_path = str(dataset_path)
        test_set = load_local_jsonl_dataset(__import__("pathlib").Path(dataset_path))
        source_name = os.path.relpath(dataset_path, PROJECT_ROOT)
    else:
        if load_dataset is None:
            raise RuntimeError("datasets package is required when --dataset-jsonl is not provided")
        print("Loading neuralchemy/Prompt-injection-dataset ...")
        dataset = load_dataset("neuralchemy/Prompt-injection-dataset", "core")
        test_set = list(dataset["test"])
        source_name = "neuralchemy/Prompt-injection-dataset:core:test"

    if max_samples > 0:
        test_set = test_set[: min(max_samples, len(test_set))]
    return test_set, source_name


def main():
    parser = argparse.ArgumentParser(description="Ablation study experiment")
    parser.add_argument("--max-samples", type=int, default=200,
                        help="Max samples (0 = all)")
    parser.add_argument("--sleep", type=float, default=2.0,
                        help="Sleep between samples for rate limiting")
    parser.add_argument("--dataset-jsonl", type=str, default=None,
                        help="Optional local JSONL benchmark file")
    args = parser.parse_args()

    print_header("EXPERIMENT 2: ABLATION STUDY")

    test_set, dataset_source = load_evaluation_set(args.dataset_jsonl, args.max_samples)
    print(f"  Dataset: {dataset_source}")
    print(f"  Using {len(test_set)} test samples.\n")

    ablation_dir = RESULTS_ROOT / "ablation"
    all_results = {}

    # Helper to set env and create a fresh Firewall with clean caches
    def _set_env(**overrides):
        defaults = {
            "SEMANTIC_FIREWALL_DISABLE_LLM_DETECTORS": "0",
            "SEMANTIC_FIREWALL_LLM_GATE_ENABLED": "1",
            "SEMANTIC_FIREWALL_LLM_GATE_THRESHOLD": "1.0",
            "SEMANTIC_FIREWALL_SIMILAR_CACHE_ENABLED": "1",
            "SEMANTIC_FIREWALL_ENSEMBLE_ENABLED": "1",
        }
        defaults.update(overrides)
        for k, v in defaults.items():
            os.environ[k] = v

    def _fresh_firewall(label: str):
        """Create a Firewall with completely clean caches to prevent data leakage."""
        # Reset the SemanticCache singleton so it creates a fresh instance
        from semantic_firewall.core.orchestrator.semantic_cache import SemanticCache
        SemanticCache._instance = None
        SemanticCache._lock = __import__("threading").Lock()

        fw = Firewall()
        # Clear the in-memory hash cache
        fw._local._cache.clear()
        print(f"  [ABLATION] Caches cleared for config: {label}")
        return fw

    # â”€â”€ A) Full System â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    print_section("A) Full System (Control)")
    _set_env()
    fw = _fresh_firewall("full_system")
    result = run_eval(fw, test_set, "full_system", sleep_sec=args.sleep)
    result["dataset_source"] = dataset_source
    write_json(ablation_dir / "ablation_full_system.json", result)
    all_results["full_system"] = {**result["metrics"], "avg_latency_ms": result["avg_latency_ms"]}
    print(f"  â†’ F1={format_pct(result['metrics']['f1'])}")

    # â”€â”€ B) Without LLM Gate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    print_section("B) Without LLM Gate (LLM always invoked)")
    _set_env(SEMANTIC_FIREWALL_LLM_GATE_ENABLED="0",
             SEMANTIC_FIREWALL_LLM_GATE_THRESHOLD="0.0")
    fw = _fresh_firewall("no_llm_gate")
    result = run_eval(fw, test_set, "no_llm_gate", sleep_sec=args.sleep)
    result["dataset_source"] = dataset_source
    write_json(ablation_dir / "ablation_no_llm_gate.json", result)
    all_results["no_llm_gate"] = {**result["metrics"], "avg_latency_ms": result["avg_latency_ms"]}
    print(f"  â†’ F1={format_pct(result['metrics']['f1'])}")

    # â”€â”€ C) Without Semantic Cache â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    print_section("C) Without Semantic Cache")
    _set_env(SEMANTIC_FIREWALL_SIMILAR_CACHE_ENABLED="0")
    fw = _fresh_firewall("no_semantic_cache")
    result = run_eval(fw, test_set, "no_semantic_cache", sleep_sec=args.sleep)
    result["dataset_source"] = dataset_source
    write_json(ablation_dir / "ablation_no_semantic_cache.json", result)
    all_results["no_semantic_cache"] = {**result["metrics"], "avg_latency_ms": result["avg_latency_ms"]}
    print(f"  â†’ F1={format_pct(result['metrics']['f1'])}")

    # â”€â”€ D) Without Ensemble Scoring â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    print_section("D) Without Ensemble Scoring")
    _set_env(SEMANTIC_FIREWALL_ENSEMBLE_ENABLED="0")
    fw = _fresh_firewall("no_ensemble")
    result = run_eval(fw, test_set, "no_ensemble", sleep_sec=args.sleep)
    result["dataset_source"] = dataset_source
    write_json(ablation_dir / "ablation_no_ensemble.json", result)
    all_results["no_ensemble"] = {**result["metrics"], "avg_latency_ms": result["avg_latency_ms"]}
    print(f"  â†’ F1={format_pct(result['metrics']['f1'])}")

    # â”€â”€ E) Without LLM Agents (Regex-Only) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    print_section("E) Without LLM Agents (Regex-Only)")
    _set_env(SEMANTIC_FIREWALL_DISABLE_LLM_DETECTORS="1",
             SEMANTIC_FIREWALL_LLM_GATE_ENABLED="0")
    fw = _fresh_firewall("regex_only")
    result = run_eval(fw, test_set, "regex_only", sleep_sec=0.0)
    result["dataset_source"] = dataset_source
    write_json(ablation_dir / "ablation_regex_only.json", result)
    all_results["regex_only"] = {**result["metrics"], "avg_latency_ms": result["avg_latency_ms"]}
    print(f"  â†’ F1={format_pct(result['metrics']['f1'])}")

    # â”€â”€ Build ablation table â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    print_section("Generating Ablation Table")
    header = ["configuration", "sample_count", "accuracy", "precision", "recall", "f1",
              "fpr", "fnr", "delta_f1_vs_full", "avg_latency_ms", "notes"]
    full_f1 = all_results["full_system"]["f1"]
    rows = []
    for name, m in all_results.items():
        delta = m["f1"] - full_f1
        rows.append([
            name,
            len(test_set),
            round(m["accuracy"], 4),
            round(m["precision"], 4),
            round(m["recall"], 4),
            round(m["f1"], 4),
            round(m["false_positive_rate"], 4),
            round(m["false_negative_rate"], 4),
            round(delta, 4),
            round(m.get("avg_latency_ms", 0.0), 2),
            "pilot_local_jsonl" if args.dataset_jsonl else "hf_dataset",
        ])
    write_csv_rows(TABLES_DIR / "ablation.csv", header, rows)

    # â”€â”€ Summary â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    print_header("EXPERIMENT 2 COMPLETE")
    print("Results saved to:")
    print(f"  â€¢ {ablation_dir}")
    print(f"  â€¢ {TABLES_DIR / 'ablation.csv'}")


if __name__ == "__main__":
    main()



