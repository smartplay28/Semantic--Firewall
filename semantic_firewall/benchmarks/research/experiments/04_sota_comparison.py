"""
Experiment 4: State-of-the-Art (SOTA) Comparison
=================================================
Compares the Semantic Firewall against Meta's Llama-Guard 4 12B model.
This is critical for Tier-1 publication to prove superiority over the industry standard.
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
    load_local_jsonl_dataset, normalize_binary_label,
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
        dataset = load_dataset("neuralchemy/Prompt-injection-dataset", "core")
        test_set = list(dataset["test"])
        source_name = "neuralchemy/Prompt-injection-dataset:core:test"

    if max_samples and max_samples > 0:
        test_set = test_set[: min(max_samples, len(test_set))]
    return test_set, source_name

def evaluate_sota_model(text: str) -> dict:
    """Queries Llama-Guard 4 12B via OpenRouter."""
    try:
        start = time.perf_counter()
        response = client.chat.completions.create(
            model="meta-llama/llama-guard-4-12b",
            messages=[
                {"role": "user", "content": text}
            ],
            temperature=0.0
        )
        latency = (time.perf_counter() - start) * 1000
        output = response.choices[0].message.content.strip().lower()
        predicted = 1 if output.startswith("unsafe") else 0
        return {"predicted": predicted, "action": output.split()[0].upper(), "latency": latency}
    except Exception as e:
        print(f"  [!] Llama Guard API Error: {e}")
        return {"predicted": 0, "action": "ERROR", "latency": 0.0}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-samples", type=int, default=500)
    parser.add_argument("--sleep", type=float, default=0.0)
    parser.add_argument("--dataset-jsonl", type=str, default=None)
    args = parser.parse_args()

    print_header("EXPERIMENT 4: SOTA COMPARISON (LLAMA-GUARD 4 12B)")
    test_set, dataset_source = load_evaluation_set(args.dataset_jsonl, args.max_samples)
    print(f"  Dataset: {dataset_source}")
    print(f"  Using {len(test_set)} test samples.\n")

    tp = fp = tn = fn = 0
    latencies = []
    
    for i, example in enumerate(test_set):
        text = example["text"]
        true_label = normalize_binary_label(example["label"])
        
        result = evaluate_sota_model(text)
        predicted = result["predicted"]
        if result["latency"] > 0:
            latencies.append(result["latency"])
        
        if true_label == 1 and predicted == 1: tp += 1
        elif true_label == 0 and predicted == 1: fp += 1
        elif true_label == 0 and predicted == 0: tn += 1
        else: fn += 1
            
        if (i + 1) % 50 == 0:
            print(f"    [Llama-Guard 4 12B] Progress: {i+1}/{len(test_set)}")
        if args.sleep > 0:
            time.sleep(args.sleep)

    metrics = compute_metrics(tp, fp, tn, fn)
    avg_latency = sum(latencies)/len(latencies) if latencies else 0
    
    print(f"\n  Llama-Guard 4 12B -> F1={format_pct(metrics['f1'])}, Precision={format_pct(metrics['precision'])}, Recall={format_pct(metrics['recall'])}")
    print(f"  Avg Latency: {avg_latency:.2f}ms")

    csv_file = TABLES_DIR / "main_comparison.csv"
    row = [
        "llama_guard_4_12b",
        len(test_set),
        round(metrics["accuracy"], 4),
        round(metrics["precision"], 4),
        round(metrics["recall"], 4),
        round(metrics["f1"], 4),
        round(metrics["false_positive_rate"], 4),
        round(metrics["false_negative_rate"], 4),
        round(avg_latency, 2),
        "sota_baseline"
    ]
    
    with open(csv_file, 'a', encoding='utf-8') as f:
        f.write(','.join(map(str, row)) + '\n')
    
    print(f"  * Results appended to {csv_file}")
    
if __name__ == "__main__":
    main()
