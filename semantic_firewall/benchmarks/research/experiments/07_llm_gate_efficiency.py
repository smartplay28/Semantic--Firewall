"""
Experiment 7: LLM Gate Efficiency Measurement
================================================
Measures how effectively the LLM Gate reduces API calls by tracking
which prompts trigger LLM invocation vs. which are handled by regex alone.

Compares:
  - With LLM Gate (threshold=1.0): Only risky prompts go to LLM
  - Without LLM Gate (threshold=0.0): All prompts go to LLM

Tracks: API calls saved, cost reduction, latency difference.

Uses the neuralchemy dataset for consistency.

Outputs:
  data/results/llm_gate/llm_gate_analysis.json
  data/results/tables/llm_gate_efficiency.csv
"""
import os
import sys
import time
import argparse
from pathlib import Path

from helpers import (
    PROJECT_ROOT, RESULTS_ROOT, TABLES_DIR,
    compute_metrics, format_pct, write_csv_rows, write_json,
    experiment_metadata, print_header, print_section,
)

sys.path.insert(0, str(PROJECT_ROOT))
from dotenv import load_dotenv
load_dotenv(PROJECT_ROOT / ".env")

from datasets import load_dataset
from semantic_firewall.sdk import Firewall


def run_with_tracking(fw, test_set, label, sleep_sec=0.0):
    """Run firewall and track which prompts trigger LLM agents."""
    tp = fp = tn = fn = 0
    total_latency_ms = 0
    llm_invoked_count = 0
    regex_only_count = 0

    for i, example in enumerate(test_set):
        text = example["text"]
        true_label = int(example["label"])

        start = time.perf_counter()
        try:
            decision = fw.analyze(text)
            elapsed_ms = (time.perf_counter() - start) * 1000
            predicted = 1 if decision.action in {"BLOCK", "FLAG", "REDACT"} else 0

            # Check if LLM agents were triggered
            agents = getattr(decision, "triggered_agents", []) or []
            llm_agents = {"Injection Detector", "Unsafe Content Detector"}
            if any(a in llm_agents for a in agents):
                llm_invoked_count += 1
            else:
                regex_only_count += 1

        except Exception:
            elapsed_ms = (time.perf_counter() - start) * 1000
            predicted = 0
            regex_only_count += 1

        total_latency_ms += elapsed_ms

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
    avg_latency = total_latency_ms / len(test_set) if test_set else 0

    return {
        "label": label,
        "total": len(test_set),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "metrics": metrics,
        "llm_invoked": llm_invoked_count,
        "regex_only": regex_only_count,
        "avg_latency_ms": round(avg_latency, 2),
        "total_latency_ms": round(total_latency_ms, 2),
    }


def main():
    parser = argparse.ArgumentParser(description="LLM Gate efficiency experiment")
    parser.add_argument("--max-samples", type=int, default=200,
                        help="Max samples (0 = all)")
    parser.add_argument("--sleep", type=float, default=2.0,
                        help="Sleep between samples")
    args = parser.parse_args()

    print_header("EXPERIMENT 7: LLM GATE EFFICIENCY")

    gate_dir = RESULTS_ROOT / "llm_gate"

    print("Loading dataset ...")
    dataset = load_dataset("neuralchemy/Prompt-injection-dataset", "core")
    test_set = dataset["test"]
    if args.max_samples > 0:
        test_set = test_set.select(range(min(args.max_samples, len(test_set))))
    print(f"  Using {len(test_set)} test samples.\n")

    # â”€â”€ A) With LLM Gate enabled (default) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    print_section("A) WITH LLM Gate (threshold=1.0)")
    os.environ["SEMANTIC_FIREWALL_DISABLE_LLM_DETECTORS"] = "0"
    os.environ["SEMANTIC_FIREWALL_LLM_GATE_ENABLED"] = "1"
    os.environ["SEMANTIC_FIREWALL_LLM_GATE_THRESHOLD"] = "1.0"
    fw_gated = Firewall()
    result_gated = run_with_tracking(fw_gated, test_set, "with_gate", sleep_sec=args.sleep)

    gated_pct = (result_gated["regex_only"] / result_gated["total"] * 100) if result_gated["total"] else 0
    print(f"  LLM invoked on     : {result_gated['llm_invoked']}/{result_gated['total']} samples")
    print(f"  Regex-only (saved) : {result_gated['regex_only']}/{result_gated['total']} ({gated_pct:.1f}%)")
    print(f"  F1                 : {format_pct(result_gated['metrics']['f1'])}")
    print(f"  Avg latency        : {result_gated['avg_latency_ms']:.1f} ms")

    # â”€â”€ B) Without LLM Gate (all go to LLM) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    print_section("B) WITHOUT LLM Gate (threshold=0.0)")
    os.environ["SEMANTIC_FIREWALL_LLM_GATE_ENABLED"] = "0"
    os.environ["SEMANTIC_FIREWALL_LLM_GATE_THRESHOLD"] = "0.0"
    fw_ungated = Firewall()
    result_ungated = run_with_tracking(fw_ungated, test_set, "without_gate", sleep_sec=args.sleep)

    print(f"  LLM invoked on     : {result_ungated['llm_invoked']}/{result_ungated['total']} samples")
    print(f"  F1                 : {format_pct(result_ungated['metrics']['f1'])}")
    print(f"  Avg latency        : {result_ungated['avg_latency_ms']:.1f} ms")

    # â”€â”€ Comparison â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    print_section("LLM Gate Efficiency Summary")

    api_calls_saved = result_ungated["llm_invoked"] - result_gated["llm_invoked"]
    api_savings_pct = (api_calls_saved / result_ungated["llm_invoked"] * 100) if result_ungated["llm_invoked"] else 0
    latency_reduction = result_ungated["avg_latency_ms"] - result_gated["avg_latency_ms"]
    f1_delta = result_gated["metrics"]["f1"] - result_ungated["metrics"]["f1"]

    print(f"  API calls saved        : {api_calls_saved} ({api_savings_pct:.1f}%)")
    print(f"  Latency reduction      : {latency_reduction:.1f} ms/request")
    print(f"  F1 difference          : {f1_delta:+.4f} (gate vs no-gate)")
    print(f"  Quality trade-off      : {'Minimal' if abs(f1_delta) < 0.03 else 'Significant'}")

    # â”€â”€ Save results â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    write_json(gate_dir / "llm_gate_analysis.json", {
        "meta": experiment_metadata(),
        "with_gate": result_gated,
        "without_gate": result_ungated,
        "comparison": {
            "api_calls_saved": api_calls_saved,
            "api_savings_pct": round(api_savings_pct, 2),
            "latency_reduction_ms": round(latency_reduction, 2),
            "f1_delta": round(f1_delta, 4),
        },
    })

    # CSV for paper
    header = ["configuration", "llm_invoked", "regex_only", "api_savings_pct",
              "avg_latency_ms", "f1", "precision", "recall"]
    rows = [
        ["with_gate",
         result_gated["llm_invoked"], result_gated["regex_only"],
         round(gated_pct, 2), result_gated["avg_latency_ms"],
         round(result_gated["metrics"]["f1"], 4),
         round(result_gated["metrics"]["precision"], 4),
         round(result_gated["metrics"]["recall"], 4)],
        ["without_gate",
         result_ungated["llm_invoked"], result_ungated["regex_only"],
         0.0, result_ungated["avg_latency_ms"],
         round(result_ungated["metrics"]["f1"], 4),
         round(result_ungated["metrics"]["precision"], 4),
         round(result_ungated["metrics"]["recall"], 4)],
    ]
    write_csv_rows(TABLES_DIR / "llm_gate_efficiency.csv", header, rows)

    print_header("EXPERIMENT 7 COMPLETE")


if __name__ == "__main__":
    main()



