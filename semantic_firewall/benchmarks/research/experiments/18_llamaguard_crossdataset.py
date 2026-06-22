"""
Experiment 18: Llama Guard on ToxicChat & BeaverTails (Real Head-to-Head)
==========================================================================
Runs Meta Llama Guard 4 (12B) via OpenRouter on the exact same ToxicChat
and BeaverTails test splits used in Experiments 14 & 15, producing real
head-to-head numbers instead of relying on published baselines.
"""
import os
import sys
import time
import argparse
from pathlib import Path
from openai import OpenAI

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
from dotenv import load_dotenv
load_dotenv(PROJECT_ROOT / ".env")

from semantic_firewall.benchmarks.research.experiments.helpers import (
    RESULTS_ROOT, TABLES_DIR,
    compute_metrics, format_pct, write_csv_rows, write_json,
    print_header, print_section,
)

try:
    from datasets import load_dataset
except ImportError:
    load_dataset = None

client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=os.environ.get("OPENROUTER_API_KEY"),
)

MODEL_ID = "meta-llama/llama-guard-4-12b"


def get_toxicchat_label(row):
    text = row.get("user_input", row.get("text", row.get("prompt", "")))
    label = 1 if row.get("toxicity", 0) == 1 or row.get("jailbreaking", 0) == 1 else 0
    return text, label


def get_beavertails_label(row):
    text = row.get("prompt", "")
    is_safe = row.get("is_safe", True)
    return text, 0 if is_safe else 1


def evaluate_llamaguard(text: str, max_retries: int = 3) -> dict:
    """Query Llama Guard 4 via OpenRouter."""
    for attempt in range(max_retries):
        try:
            start = time.perf_counter()
            response = client.chat.completions.create(
                model=MODEL_ID,
                messages=[{"role": "user", "content": text}],
                temperature=0.0,
            )
            latency = (time.perf_counter() - start) * 1000
            output = response.choices[0].message.content.strip().lower()

            if any(kw in output for kw in ["unsafe", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "s12", "s13"]):
                predicted = 1
            elif "safe" in output:
                predicted = 0
            else:
                predicted = 1 if any(kw in output for kw in ["injection", "jailbreak", "attack", "malicious", "harmful", "block"]) else 0

            return {"predicted": predicted, "raw_output": output[:200], "latency": latency}
        except Exception as e:
            err = str(e)
            if "429" in err or "rate" in err.lower():
                wait = 3 * (attempt + 1)
                print(f"  [Rate Limited] Waiting {wait}s...")
                time.sleep(wait)
            else:
                print(f"  [!] API Error: {err[:100]}")
                return {"predicted": 0, "raw_output": f"ERROR: {err[:100]}", "latency": -1}
    return {"predicted": 0, "raw_output": "MAX_RETRIES", "latency": -1}


def run_benchmark(test_set, label_extractor, dataset_name: str, sleep_sec: float = 0.5):
    """Run full Llama Guard benchmark on a dataset."""
    print_section(f"Evaluating Llama Guard 4 on {len(test_set)} {dataset_name} samples")

    tp = fp = tn = fn = 0
    latencies = []

    for i, row in enumerate(test_set):
        text, true_label = label_extractor(row)
        if not text.strip():
            continue

        result = evaluate_llamaguard(text)
        
        # Skip completely if API failed or timed out
        if result["latency"] == -1:
            continue
            
        predicted = result["predicted"]
        latencies.append(result["latency"])

        if true_label == 1 and predicted == 1: tp += 1
        elif true_label == 0 and predicted == 1: fp += 1
        elif true_label == 0 and predicted == 0: tn += 1
        elif true_label == 1 and predicted == 0: fn += 1

        if (i + 1) % 50 == 0:
            curr = compute_metrics(tp, fp, tn, fn)
            print(f"    [{dataset_name}] {i+1}/{len(test_set)} | F1: {format_pct(curr['f1'])} | Recall: {format_pct(curr['recall'])}")

        if sleep_sec > 0:
            time.sleep(sleep_sec)

    metrics = compute_metrics(tp, fp, tn, fn)
    avg_latency = sum(latencies) / len(latencies) if latencies else 0
    eval_count = tp + fp + tn + fn

    print(f"\n  [{dataset_name}] FINAL -> F1={format_pct(metrics['f1'])}, Precision={format_pct(metrics['precision'])}, Recall={format_pct(metrics['recall'])}")
    print(f"  TP={tp}, FP={fp}, TN={tn}, FN={fn}")
    print(f"  Avg Latency: {avg_latency:.2f}ms | Evaluated: {eval_count}")

    return {
        "dataset": dataset_name,
        "model": "llama_guard_4_12b",
        "total": eval_count,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "metrics": metrics,
        "avg_latency_ms": round(avg_latency, 2),
    }


def main():
    parser = argparse.ArgumentParser(description="Llama Guard cross-dataset evaluation")
    parser.add_argument("--max-samples", type=int, default=2000)
    parser.add_argument("--sleep", type=float, default=0.5)
    args = parser.parse_args()

    print_header("EXPERIMENT 18: LLAMA GUARD ON TOXICCHAT & BEAVERTAILS (REAL HEAD-TO-HEAD)")

    if load_dataset is None:
        raise RuntimeError("datasets package is required")

    # Load ToxicChat
    print("  Loading lmsys/toxic-chat ...")
    eval_dataset = load_dataset("lmsys/toxic-chat", "toxicchat0124")
    toxicchat_set = list(eval_dataset["test"])[:args.max_samples]
    print(f"  ToxicChat test samples: {len(toxicchat_set)}")

    # Load BeaverTails
    print("  Loading PKU-Alignment/BeaverTails ...")
    try:
        beaver_data = list(load_dataset("PKU-Alignment/BeaverTails", split="30k_test"))[:args.max_samples]
    except Exception:
        beaver_data = list(load_dataset("PKU-Alignment/BeaverTails", split="330k_test"))[:args.max_samples]
    print(f"  BeaverTails test samples: {len(beaver_data)}")

    all_results = {}

    # 1. Run on ToxicChat
    tc_result = run_benchmark(toxicchat_set, get_toxicchat_label, "toxicchat", sleep_sec=args.sleep)
    all_results["toxicchat"] = tc_result

    # 2. Run on BeaverTails
    bv_result = run_benchmark(beaver_data, get_beavertails_label, "beavertails", sleep_sec=args.sleep)
    all_results["beavertails"] = bv_result

    # Save JSON
    os.makedirs(RESULTS_ROOT / "ood", exist_ok=True)
    write_json(RESULTS_ROOT / "ood" / "llamaguard_crossdataset.json", all_results)

    # Save CSV
    header = ["dataset", "model", "sample_count", "accuracy", "precision", "recall", "f1", "avg_latency_ms", "fpr"]
    rows = []
    for key, data in all_results.items():
        m = data["metrics"]
        rows.append([
            data["dataset"],
            "llama_guard_4_12b",
            data["total"],
            round(m["accuracy"], 4),
            round(m["precision"], 4),
            round(m["recall"], 4),
            round(m["f1"], 4),
            data["avg_latency_ms"],
            round(m["false_positive_rate"], 4),
        ])
    write_csv_rows(TABLES_DIR / "llamaguard_crossdataset.csv", header, rows)

    print_header("EXPERIMENT 18 COMPLETE")


if __name__ == "__main__":
    main()
