"""
Experiment 5: Scaled Unsafe Content Detection
================================================
Runs the Unsafe Content detector on 200 samples from lmsys/toxic-chat
(up from the original 50) for stronger statistical significance.

âš ï¸ Uses Groq API â€” will take ~12 minutes at 3.5s/sample rate limit.

Outputs:
  data/results/unsafe/unsafe_scaled_results.json
  data/results/unsafe/unsafe_scaled_summary.json
  data/results/tables/unsafe_scaled.csv
"""
import os
import sys
import time
import argparse
from pathlib import Path

from helpers import (
    PROJECT_ROOT, RESULTS_ROOT, TABLES_DIR,
    compute_metrics, format_pct, write_csv_rows, write_json,
    experiment_metadata, rate_limit_sleep, print_header, print_section,
)

sys.path.insert(0, str(PROJECT_ROOT))
from dotenv import load_dotenv
load_dotenv(PROJECT_ROOT / ".env")

from datasets import load_dataset
from semantic_firewall.sdk import Firewall
from tqdm import tqdm


def main():
    parser = argparse.ArgumentParser(description="Scaled unsafe content benchmark")
    parser.add_argument("--num-samples", type=int, default=200,
                        help="Number of samples (default: 200)")
    parser.add_argument("--sleep", type=float, default=3.5,
                        help="Sleep between API calls (default: 3.5)")
    args = parser.parse_args()

    print_header("EXPERIMENT 5: SCALED UNSAFE CONTENT DETECTION")

    unsafe_dir = RESULTS_ROOT / "unsafe"
    num_samples = args.num_samples

    print(f"Loading {num_samples} samples from lmsys/toxic-chat ...")
    dataset = load_dataset("lmsys/toxic-chat", "toxicchat0124")

    # Get a balanced mix: ensure we have both toxic and benign
    all_data = dataset['train'].shuffle(seed=42)
    toxic_data = [x for x in all_data if x['toxicity'] == 1]
    benign_data = [x for x in all_data if x['toxicity'] == 0]

    # Try to get a 30/70 toxic/benign split for realistic evaluation
    n_toxic = min(int(num_samples * 0.3), len(toxic_data))
    n_benign = min(num_samples - n_toxic, len(benign_data))
    test_data = toxic_data[:n_toxic] + benign_data[:n_benign]

    print(f"  Selected {n_toxic} toxic + {n_benign} benign = {len(test_data)} total samples")
    print(f"  Estimated time: ~{len(test_data) * args.sleep / 60:.0f} minutes\n")

    fw = Firewall()
    tp = fp = tn = fn = 0
    results = []
    by_severity = {}

    for idx, item in enumerate(tqdm(test_data, desc="Unsafe Content Eval")):
        source_text = item['user_input']
        is_toxic = item['toxicity'] == 1

        try:
            decision = fw.analyze(source_text)
            if "Detector unavailable" in str(decision.reason):
                continue
            flagged = decision.action in {"BLOCK", "FLAG", "REDACT"}
            # The decision string has a reason, we can extract the severity or just use the action
            severity = "CRITICAL" if flagged else "NONE"
            summary = decision.reason
        except Exception as e:
            if '429' in str(e) or 'rate' in str(e).lower() or 'unavailable' in str(e).lower() or 'timeout' in str(e).lower():
                continue
            print(f"  [!] Error on sample {idx}: {e}")
            flagged = False
            severity = "ERROR"
            summary = str(e)

        # Confusion matrix
        if is_toxic and flagged:
            tp += 1
        elif not is_toxic and flagged:
            fp += 1
        elif not is_toxic and not flagged:
            tn += 1
        else:
            fn += 1

        # Per-severity tracking
        by_severity.setdefault(severity, {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "count": 0})
        by_severity[severity]["count"] += 1
        if is_toxic and flagged:
            by_severity[severity]["tp"] += 1
        elif not is_toxic and flagged:
            by_severity[severity]["fp"] += 1
        elif not is_toxic and not flagged:
            by_severity[severity]["tn"] += 1
        else:
            by_severity[severity]["fn"] += 1

        results.append({
            "id": idx,
            "text": source_text[:200],
            "ground_truth_toxic": is_toxic,
            "agent_flagged": flagged,
            "agent_severity": severity,
            "agent_summary": summary[:200],
        })

        rate_limit_sleep(args.sleep)

    # â”€â”€ Overall metrics â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    overall = compute_metrics(tp, fp, tn, fn)

    print_section("Overall Unsafe Content Results")
    print(f"  Samples tested     : {len(test_data)}")
    print(f"    Toxic samples    : {n_toxic}")
    print(f"    Benign samples   : {n_benign}")
    print(f"  TP / FP / TN / FN  : {tp} / {fp} / {tn} / {fn}")
    print(f"  Precision          : {format_pct(overall['precision'])}")
    print(f"  Recall             : {format_pct(overall['recall'])}")
    print(f"  F1 Score           : {format_pct(overall['f1'])}")
    print(f"  False Positive Rate: {format_pct(overall['false_positive_rate'])}")
    print(f"  Accuracy           : {format_pct(overall['accuracy'])}")

    # â”€â”€ Save results â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    write_json(unsafe_dir / "unsafe_scaled_results.json", results)
    write_json(unsafe_dir / "unsafe_scaled_summary.json", {
        "meta": experiment_metadata(),
        "num_samples": len(test_data),
        "n_toxic": n_toxic,
        "n_benign": n_benign,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "overall_metrics": overall,
        "by_severity": by_severity,
    })

    # CSV for paper
    header = ["metric", "value"]
    rows = [
        ["num_samples", len(test_data)],
        ["toxic_samples", n_toxic],
        ["benign_samples", n_benign],
        ["true_positives", tp],
        ["false_positives", fp],
        ["true_negatives", tn],
        ["false_negatives", fn],
        ["precision", round(overall["precision"], 4)],
        ["recall", round(overall["recall"], 4)],
        ["f1", round(overall["f1"], 4)],
        ["accuracy", round(overall["accuracy"], 4)],
        ["false_positive_rate", round(overall["false_positive_rate"], 4)],
    ]
    write_csv_rows(TABLES_DIR / "unsafe_scaled.csv", header, rows)

    print_header("EXPERIMENT 5 COMPLETE")


if __name__ == "__main__":
    main()



