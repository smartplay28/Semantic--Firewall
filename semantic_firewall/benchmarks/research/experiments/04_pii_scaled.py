"""
Experiment 4: Scaled PII Detection Benchmark
===============================================
Runs the PII detector on 500 samples from ai4privacy/pii-masking-200k
(up from the original 100) for statistical significance.

No API calls needed â€” runs purely on regex, so it's fast.

Outputs:
  data/results/pii/pii_scaled_results.json
  data/results/pii/pii_scaled_summary.json
  data/results/tables/pii_scaled.csv
"""
import sys
import argparse
import os
from pathlib import Path

from helpers import (
    PROJECT_ROOT, RESULTS_ROOT, TABLES_DIR,
    compute_metrics, format_pct, write_csv_rows, write_json,
    experiment_metadata, print_header, print_section,
)

sys.path.insert(0, str(PROJECT_ROOT))
from dotenv import load_dotenv
load_dotenv(PROJECT_ROOT / ".env")

from semantic_firewall.core.agents.pii_detector import PIIDetectorAgent
from tqdm import tqdm

TARGET_LABELS = {
    'EMAIL', 'IPV4', 'IPV6', 'MAC', 'PHONENUMBER', 'IBAN', 'DOB',
    'CREDITCARDNUMBER', 'CREDITCARDCVV', 'SSN', 'ZIPCODE', 'ACCOUNTNUMBER'
}


def main():
    parser = argparse.ArgumentParser(description="Scaled PII benchmark")
    parser.add_argument("--num-samples", type=int, default=2000,
                        help="Number of samples to test (default: 2000)")
    parser.add_argument("--offline", action="store_true",
                        help="Use the local Hugging Face cache only.")
    args = parser.parse_args()

    print_header("EXPERIMENT 4: SCALED PII DETECTION")

    pii_dir = RESULTS_ROOT / "pii"
    num_samples = args.num_samples

    if args.offline:
        os.environ["HF_DATASETS_OFFLINE"] = "1"
        os.environ["HF_HUB_OFFLINE"] = "1"

    from datasets import load_dataset

    print(f"Loading ALL samples from ai4privacy/pii-masking-200k ...")
    dataset = load_dataset(
        "ai4privacy/pii-masking-200k",
        "default",
        download_mode="reuse_dataset_if_exists",
    )
    test_data = dataset['train']
    num_samples = len(test_data)

    pii_agent = PIIDetectorAgent()

    tp = fp = fn = 0
    per_type = {}  # per PII-type breakdown
    results = []

    print(f"\nRunning PII evaluation on {num_samples} samples ...\n")

    for idx, item in enumerate(tqdm(test_data, desc="PII Evaluation")):
        source_text = item['source_text']
        dataset_masks = item.get('privacy_mask', [])

        # Ground truth
        ground_truth_values = set()
        ground_truth_types = {}
        for mask in dataset_masks:
            if mask['label'] in TARGET_LABELS:
                val = mask['value'].strip().lower()
                ground_truth_values.add(val)
                ground_truth_types[val] = mask['label']

        # Agent predictions
        pii_agent_result = pii_agent.run(source_text)
        agent_values = set()
        if pii_agent_result and pii_agent_result.matched:
            for match in pii_agent_result.matched:
                agent_values.add(match.value.strip().lower())

        # Metrics
        sample_tp_vals = ground_truth_values & agent_values
        sample_fp_vals = agent_values - ground_truth_values
        sample_fn_vals = ground_truth_values - agent_values

        sample_tp = len(sample_tp_vals)
        sample_fp = len(sample_fp_vals)
        sample_fn = len(sample_fn_vals)

        tp += sample_tp
        fp += sample_fp
        fn += sample_fn

        # Per-type tracking
        for val in sample_tp_vals:
            pii_type = ground_truth_types.get(val, "UNKNOWN")
            per_type.setdefault(pii_type, {"tp": 0, "fp": 0, "fn": 0})
            per_type[pii_type]["tp"] += 1
        for val in sample_fn_vals:
            pii_type = ground_truth_types.get(val, "UNKNOWN")
            per_type.setdefault(pii_type, {"tp": 0, "fp": 0, "fn": 0})
            per_type[pii_type]["fn"] += 1

        results.append({
            "id": idx,
            "text": source_text[:200],
            "ground_truth": list(ground_truth_values),
            "agent_found": list(agent_values),
            "missed": list(sample_fn_vals),
            "false_positives": list(sample_fp_vals),
        })

    # â”€â”€ Overall metrics â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    tn = 0  # PII detection doesn't have a clean TN concept at value level
    overall = compute_metrics(tp, fp, tn, fn)

    print_section("Overall PII Results")
    print(f"  Samples tested     : {num_samples}")
    print(f"  True Positives     : {tp}")
    print(f"  False Positives    : {fp}")
    print(f"  False Negatives    : {fn}")
    print(f"  Precision          : {format_pct(overall['precision'])}")
    print(f"  Recall             : {format_pct(overall['recall'])}")
    print(f"  F1 Score           : {format_pct(overall['f1'])}")

    # â”€â”€ Per-type breakdown â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    print_section("Per-Type PII Breakdown")
    per_type_metrics = {}
    for pii_type in sorted(per_type.keys()):
        t = per_type[pii_type]
        m = compute_metrics(t["tp"], 0, 0, t["fn"])
        per_type_metrics[pii_type] = m
        print(f"  {pii_type:20s} â†’ TP={t['tp']:3d}, FN={t['fn']:3d}, "
              f"Recall={format_pct(m['recall'])}")

    # â”€â”€ Save results â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    write_json(pii_dir / "pii_scaled_results.json", results)
    write_json(pii_dir / "pii_scaled_summary.json", {
        "meta": experiment_metadata(),
        "num_samples": num_samples,
        "tp": tp, "fp": fp, "fn": fn,
        "overall_metrics": overall,
        "per_type": per_type,
        "per_type_metrics": per_type_metrics,
    })

    # CSV for paper
    header = ["metric", "value"]
    rows = [
        ["num_samples", num_samples],
        ["true_positives", tp],
        ["false_positives", fp],
        ["false_negatives", fn],
        ["precision", round(overall["precision"], 4)],
        ["recall", round(overall["recall"], 4)],
        ["f1", round(overall["f1"], 4)],
    ]
    write_csv_rows(TABLES_DIR / "pii_scaled.csv", header, rows)

    # Per-type CSV
    type_header = ["pii_type", "tp", "fn", "recall"]
    type_rows = []
    for pii_type in sorted(per_type.keys()):
        t = per_type[pii_type]
        m = per_type_metrics[pii_type]
        type_rows.append([pii_type, t["tp"], t["fn"], round(m["recall"], 4)])
    write_csv_rows(TABLES_DIR / "pii_per_type.csv", type_header, type_rows)

    print_header("EXPERIMENT 4 COMPLETE")


if __name__ == "__main__":
    main()



