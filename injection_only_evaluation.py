import argparse
from collections import defaultdict
import csv
import os
from pathlib import Path
import time


def safe_div(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def compute_metrics(tp: int, fp: int, tn: int, fn: int) -> dict:
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    f1 = safe_div(2 * precision * recall, precision + recall)
    accuracy = safe_div(tp + tn, tp + tn + fp + fn)
    false_positive_rate = safe_div(fp, fp + tn)
    false_negative_rate = safe_div(fn, fn + tp)
    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": false_positive_rate,
        "false_negative_rate": false_negative_rate,
    }


def format_pct(value: float) -> str:
    return f"{value * 100:5.1f}%"


def write_summary_csv(path: Path, overall: dict, results: dict) -> None:
    rows = [
        ["metric", "value"],
        ["evaluation_mode", "injection_only"],
        ["total_samples", results["total"]],
        ["true_positives", results["tp"]],
        ["false_positives", results["fp"]],
        ["true_negatives", results["tn"]],
        ["false_negatives", results["fn"]],
        ["accuracy", round(overall["accuracy"], 6)],
        ["precision", round(overall["precision"], 6)],
        ["recall", round(overall["recall"], 6)],
        ["f1", round(overall["f1"], 6)],
        ["false_positive_rate", round(overall["false_positive_rate"], 6)],
        ["false_negative_rate", round(overall["false_negative_rate"], 6)],
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerows(rows)


def write_breakdown_csv(path: Path, bucket_name: str, bucket_data: dict) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                bucket_name,
                "count",
                "tp",
                "fp",
                "tn",
                "fn",
                "accuracy",
                "precision",
                "recall",
                "f1",
                "false_positive_rate",
                "false_negative_rate",
            ]
        )
        for bucket in sorted(bucket_data):
            stats = bucket_data[bucket]
            metrics = compute_metrics(
                tp=stats["tp"],
                fp=stats["fp"],
                tn=stats["tn"],
                fn=stats["fn"],
            )
            writer.writerow(
                [
                    bucket,
                    stats["total"],
                    stats["tp"],
                    stats["fp"],
                    stats["tn"],
                    stats["fn"],
                    round(metrics["accuracy"], 6),
                    round(metrics["precision"], 6),
                    round(metrics["recall"], 6),
                    round(metrics["f1"], 6),
                    round(metrics["false_positive_rate"], 6),
                    round(metrics["false_negative_rate"], 6),
                ]
            )


def write_errors_csv(path: Path, rows: list[dict], error_type: str) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["error_type", "category", "severity", "action", "predicted_label", "text", "reason"],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "error_type": error_type,
                    "category": row["category"],
                    "severity": row["severity"],
                    "action": row["action"],
                    "predicted_label": row["predicted_label"],
                    "text": row["text"],
                    "reason": row["reason"],
                }
            )


parser = argparse.ArgumentParser(description="Evaluate Injection Detector behavior on the neuralchemy dataset.")
parser.add_argument("--max-samples", type=int, default=0, help="Limit evaluation to the first N test samples (0 = all).")
parser.add_argument("--sleep-seconds", type=float, default=0.0, help="Optional delay between samples to avoid API rate limits.")
parser.add_argument(
    "--regex-only",
    action="store_true",
    help="Disable LLM-backed detectors for this run and evaluate regex/rule coverage only.",
)
parser.add_argument(
    "--offline",
    action="store_true",
    help="Use the local Hugging Face dataset cache and avoid network checks.",
)
args = parser.parse_args()

if args.regex_only:
    os.environ["GROQ_API_KEY"] = ""
if args.offline:
    os.environ["HF_DATASETS_OFFLINE"] = "1"
    os.environ["HF_HUB_OFFLINE"] = "1"

from datasets import load_dataset
from agents.injection_detector import InjectionDetectorAgent

print("\n" + "=" * 80)
print("INJECTION-ONLY EVALUATION ON NEURALCHEMY DATASET")
print("=" * 80)

print("\nLoading dataset...")
dataset = load_dataset("neuralchemy/Prompt-injection-dataset", "core", download_mode="reuse_dataset_if_exists")
test_set = dataset["test"]
if args.max_samples and args.max_samples > 0:
    test_set = test_set.select(range(min(args.max_samples, len(test_set))))

print("Initializing injection detector...")
agent = InjectionDetectorAgent()

results = {
    "tp": 0,
    "fp": 0,
    "tn": 0,
    "fn": 0,
    "total": len(test_set),
    "by_category": defaultdict(lambda: {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "total": 0}),
    "by_severity": defaultdict(lambda: {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "total": 0}),
    "false_positives": [],
    "false_negatives": [],
}

print(f"\nTesting on {len(test_set)} examples...")
print("Prediction rule: malicious iff Injection Detector triggers.")
print("Execution path: InjectionDetectorAgent only; other firewall agents are not run.\n")
if args.regex_only:
    print("Regex-only mode enabled: LLM-backed detectors are disabled for this run.\n")
if args.offline:
    print("Offline dataset mode enabled: using local Hugging Face cache only.\n")
if args.sleep_seconds > 0:
    print(f"Pacing enabled: sleeping {args.sleep_seconds:.2f}s between samples.\n")

for i, example in enumerate(test_set):
    text = example["text"]
    true_label = int(example["label"])
    category = example["category"]
    severity = example.get("severity") or "benign"

    detection = agent.run(text)
    predicted_label = 1 if detection.threat_found else 0

    if true_label == 1 and predicted_label == 1:
        bucket = "tp"
    elif true_label == 0 and predicted_label == 1:
        bucket = "fp"
    elif true_label == 0 and predicted_label == 0:
        bucket = "tn"
    else:
        bucket = "fn"

    results[bucket] += 1
    results["by_category"][category][bucket] += 1
    results["by_category"][category]["total"] += 1
    results["by_severity"][severity][bucket] += 1
    results["by_severity"][severity]["total"] += 1

    error_row = {
        "text": text,
        "category": category,
        "severity": severity,
        "action": "INJECTION" if detection.threat_found else "ALLOW",
        "predicted_label": predicted_label,
        "reason": detection.summary,
    }
    if bucket == "fp" and len(results["false_positives"]) < 20:
        results["false_positives"].append(error_row)
    elif bucket == "fn" and len(results["false_negatives"]) < 20:
        results["false_negatives"].append(error_row)

    if (i + 1) % 25 == 0 or i + 1 == len(test_set):
        print(f"  Progress: [{i + 1}/{len(test_set)}]")
    if args.sleep_seconds > 0 and i + 1 < len(test_set):
        time.sleep(args.sleep_seconds)


overall = compute_metrics(
    tp=results["tp"],
    fp=results["fp"],
    tn=results["tn"],
    fn=results["fn"],
)

reports_dir = Path("results")
reports_dir.mkdir(parents=True, exist_ok=True)
summary_csv = reports_dir / "neuralchemy_injection_only_summary.csv"
category_csv = reports_dir / "neuralchemy_injection_only_by_category.csv"
severity_csv = reports_dir / "neuralchemy_injection_only_by_severity.csv"
fp_csv = reports_dir / "neuralchemy_injection_only_false_positives.csv"
fn_csv = reports_dir / "neuralchemy_injection_only_false_negatives.csv"

write_summary_csv(summary_csv, overall, results)
write_breakdown_csv(category_csv, "category", results["by_category"])
write_breakdown_csv(severity_csv, "severity", results["by_severity"])
write_errors_csv(fp_csv, results["false_positives"], "false_positive")
write_errors_csv(fn_csv, results["false_negatives"], "false_negative")

print("\n" + "=" * 80)
print("OVERALL METRICS")
print("=" * 80)
print(f"Total samples        : {results['total']}")
print(f"TP / FP / TN / FN    : {results['tp']} / {results['fp']} / {results['tn']} / {results['fn']}")
print(f"Accuracy             : {format_pct(overall['accuracy'])}")
print(f"Precision            : {format_pct(overall['precision'])}")
print(f"Recall               : {format_pct(overall['recall'])}")
print(f"F1 Score             : {format_pct(overall['f1'])}")
print(f"False Positive Rate  : {format_pct(overall['false_positive_rate'])}")
print(f"False Negative Rate  : {format_pct(overall['false_negative_rate'])}")

print("\n" + "=" * 80)
print("PER-CATEGORY BREAKDOWN")
print("=" * 80)
for category in sorted(results["by_category"]):
    stats = results["by_category"][category]
    metrics = compute_metrics(
        tp=stats["tp"],
        fp=stats["fp"],
        tn=stats["tn"],
        fn=stats["fn"],
    )
    print(
        f"{category:22s} "
        f"count={stats['total']:3d} "
        f"recall={format_pct(metrics['recall'])} "
        f"fpr={format_pct(metrics['false_positive_rate'])} "
        f"f1={format_pct(metrics['f1'])}"
    )

print("\n" + "=" * 80)
print("TOP FALSE POSITIVES")
print("=" * 80)
for i, fp in enumerate(results["false_positives"], 1):
    print(f"{i}. [{fp['category']} | {fp['severity']}] action={fp['action']}")
    print(f"   Text   : {fp['text'][:120]}...")
    print(f"   Reason : {fp['reason'][:160]}...")

print("\n" + "=" * 80)
print("TOP FALSE NEGATIVES")
print("=" * 80)
for i, fn in enumerate(results["false_negatives"], 1):
    print(f"{i}. [{fn['category']} | {fn['severity']}] action={fn['action']}")
    print(f"   Text   : {fn['text'][:120]}...")
    print(f"   Reason : {fn['reason'][:160]}...")

print(f"\nCSV reports written to: {reports_dir}")
