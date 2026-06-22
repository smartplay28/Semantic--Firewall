"""
Experiment 13: Dedicated Security Model Comparison
====================================================
Compares the Semantic Firewall against DEDICATED security models:
  - Meta Llama Guard 4 12B (via OpenRouter)
  - OpenAI GPT-OSS-Safeguard 20B (via OpenRouter)

These are purpose-built safety classifiers, NOT general-purpose LLMs.
This is the comparison reviewers actually want to see.
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
    normalize_binary_label,
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


def evaluate_guard_model(text: str, model_id: str) -> dict:
    """Query a dedicated security model via OpenRouter."""
    try:
        start = time.perf_counter()
        response = client.chat.completions.create(
            model=model_id,
            messages=[
                {"role": "user", "content": text}
            ],
            temperature=0.0
        )
        latency = (time.perf_counter() - start) * 1000
        output = response.choices[0].message.content.strip().lower()
        
        # Llama Guard outputs "safe" or "unsafe" with category codes
        # GPT-OSS-Safeguard similarly outputs safety classifications
        if "unsafe" in output or "s1" in output or "s2" in output or "s3" in output or "s4" in output or "s5" in output or "s6" in output:
            predicted = 1
        elif "safe" in output:
            predicted = 0
        else:
            # If output contains "injection", "jailbreak", "attack", "malicious" etc
            if any(kw in output for kw in ["injection", "jailbreak", "attack", "malicious", "harmful", "block", "reject"]):
                predicted = 1
            else:
                predicted = 0
        
        return {"predicted": predicted, "raw_output": output[:200], "latency": latency}
    except Exception as e:
        err = str(e)
        if '429' in err:
            time.sleep(3)
            return evaluate_guard_model(text, model_id)
        print(f"  [!] API Error: {err[:100]}")
        return {"predicted": 0, "raw_output": f"ERROR: {err[:100]}", "latency": 0.0}


def run_benchmark(model_id: str, label: str, test_set: list, sleep_sec: float = 0.0):
    """Run full benchmark against a security model."""
    print_section(f"Evaluating: {label} ({model_id})")
    
    tp = fp = tn = fn = 0
    latencies = []
    
    for i, example in enumerate(test_set):
        text = example["text"]
        true_label = normalize_binary_label(example["label"])
        
        result = evaluate_guard_model(text, model_id)
        predicted = result["predicted"]
        if result["latency"] > 0:
            latencies.append(result["latency"])
        
        if true_label == 1 and predicted == 1: tp += 1
        elif true_label == 0 and predicted == 1: fp += 1
        elif true_label == 0 and predicted == 0: tn += 1
        else: fn += 1
        
        if (i + 1) % 50 == 0:
            curr_metrics = compute_metrics(tp, fp, tn, fn)
            print(f"    [{label}] {i+1}/{len(test_set)} | Running F1: {format_pct(curr_metrics['f1'])}")
        
        if sleep_sec > 0:
            time.sleep(sleep_sec)
    
    metrics = compute_metrics(tp, fp, tn, fn)
    avg_latency = sum(latencies) / len(latencies) if latencies else 0
    
    print(f"\n  {label} -> F1={format_pct(metrics['f1'])}, Precision={format_pct(metrics['precision'])}, Recall={format_pct(metrics['recall'])}")
    print(f"  TP={tp}, FP={fp}, TN={tn}, FN={fn}")
    print(f"  Avg Latency: {avg_latency:.2f}ms")
    
    return {
        "label": label,
        "model_id": model_id,
        "total": len(test_set),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "metrics": metrics,
        "avg_latency_ms": round(avg_latency, 2),
    }


def main():
    parser = argparse.ArgumentParser(description="Security model comparison")
    parser.add_argument("--max-samples", type=int, default=500)
    parser.add_argument("--sleep", type=float, default=0.0)
    args = parser.parse_args()
    
    print_header("EXPERIMENT 13: DEDICATED SECURITY MODEL COMPARISON")
    
    if load_dataset is None:
        raise RuntimeError("datasets package is required")
    
    print("Loading neuralchemy/Prompt-injection-dataset ...")
    dataset = load_dataset("neuralchemy/Prompt-injection-dataset", "core")
    test_set = list(dataset["test"])[:args.max_samples]
    print(f"  Using {len(test_set)} test samples.\n")
    
    # The dedicated security models to benchmark
    security_models = [
        ("meta-llama/llama-guard-4-12b", "Llama Guard 4 (12B)"),
        ("openai/gpt-oss-safeguard-20b", "GPT-OSS-Safeguard (20B)"),
    ]
    
    all_results = {}
    
    for model_id, label in security_models:
        result = run_benchmark(model_id, label, test_set, sleep_sec=args.sleep)
        all_results[label] = result
    
    # Save results
    os.makedirs(RESULTS_ROOT / "security_models", exist_ok=True)
    write_json(RESULTS_ROOT / "security_models" / "security_model_comparison.json", all_results)
    
    # CSV
    csv_file = TABLES_DIR / "security_model_comparison.csv"
    header = ["model", "sample_count", "accuracy", "precision", "recall", "f1", "fpr", "fnr", "avg_latency_ms"]
    rows = []
    for label, data in all_results.items():
        m = data["metrics"]
        rows.append([
            label,
            data["total"],
            round(m["accuracy"], 4),
            round(m["precision"], 4),
            round(m["recall"], 4),
            round(m["f1"], 4),
            round(m["false_positive_rate"], 4),
            round(m["false_negative_rate"], 4),
            data["avg_latency_ms"],
        ])
    write_csv_rows(csv_file, rows, header)
    
    print_header("EXPERIMENT 13 COMPLETE")
    print(f"  Results: {RESULTS_ROOT / 'security_models'}")
    print(f"  CSV: {csv_file}")


if __name__ == "__main__":
    main()
