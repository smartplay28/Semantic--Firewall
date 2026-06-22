"""
Run remaining ablation configs for neuralchemy dataset (N=100)
"""
import os, sys, time, argparse
from pathlib import Path

from helpers import (
    PROJECT_ROOT, RESULTS_ROOT, TABLES_DIR,
    compute_metrics, write_json, experiment_metadata, print_header, print_section
)

sys.path.insert(0, str(PROJECT_ROOT))
from dotenv import load_dotenv
load_dotenv(PROJECT_ROOT / ".env")

from datasets import load_dataset
from semantic_firewall.sdk import Firewall

def run_eval(fw, test_set, label, sleep_sec):
    tp = fp = tn = fn = 0
    latencies_ms = []
    for i, example in enumerate(test_set):
        text = example["text"]
        true_label = int(example["label"])
        try:
            start = time.perf_counter()
            decision = fw.analyze(text)
            latencies_ms.append((time.perf_counter() - start) * 1000)
            predicted = 1 if decision.action in {"BLOCK", "FLAG", "REDACT"} else 0
        except Exception as e:
            predicted = 0
            print(f"  [ERROR] {e}")

        if true_label == 1 and predicted == 1: tp += 1
        elif true_label == 0 and predicted == 1: fp += 1
        elif true_label == 0 and predicted == 0: tn += 1
        else: fn += 1

        if (i+1) % 10 == 0: print(f"  [{label}] Progress: {i+1}/{len(test_set)}")
        if sleep_sec > 0: time.sleep(sleep_sec)

    metrics = compute_metrics(tp, fp, tn, fn)
    return {
        "label": label,
        "meta": experiment_metadata(),
        "total": len(test_set),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "metrics": metrics,
        "avg_latency_ms": round(sum(latencies_ms)/len(latencies_ms), 2) if latencies_ms else 0,
        "dataset_source": "neuralchemy/Prompt-injection-dataset:core:test"
    }

def main():
    print_header("REMAINING ABLATION (N=100)")
    dataset = load_dataset("neuralchemy/Prompt-injection-dataset", "core")
    test_set = dataset["test"].select(range(100))

    out_dir = RESULTS_ROOT / "ablation"
    out_dir.mkdir(parents=True, exist_ok=True)
    
    # 1. no_ensemble
    print_section("Config: no_ensemble")
    os.environ["SEMANTIC_FIREWALL_ENSEMBLE_ENABLED"] = "0"
    os.environ["SEMANTIC_FIREWALL_LLM_GATE_ENABLED"] = "1"
    os.environ["SEMANTIC_FIREWALL_DISABLE_LLM_DETECTORS"] = "0"
    fw_no_ensemble = Firewall()
    res_no_ensemble = run_eval(fw_no_ensemble, test_set, "no_ensemble", 4.0)
    write_json(out_dir / "ablation_no_ensemble.json", res_no_ensemble)
    print(f"  no_ensemble F1: {res_no_ensemble['metrics']['f1']:.3f}")

    # 2. regex_only (FREE, no sleep needed)
    print_section("Config: regex_only")
    os.environ["SEMANTIC_FIREWALL_ENSEMBLE_ENABLED"] = "1"
    os.environ["SEMANTIC_FIREWALL_LLM_GATE_ENABLED"] = "1"
    os.environ["SEMANTIC_FIREWALL_DISABLE_LLM_DETECTORS"] = "1"
    fw_regex = Firewall()
    res_regex = run_eval(fw_regex, test_set, "regex_only", 0.0)
    write_json(out_dir / "ablation_regex_only.json", res_regex)
    print(f"  regex_only F1: {res_regex['metrics']['f1']:.3f}")

    print_header("DONE")

if __name__ == "__main__":
    main()
