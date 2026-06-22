"""
Experiment 16: Threshold Sensitivity Analysis
=============================================
Evaluates the full Semantic Firewall pipeline across varying threshold 
values for the LLM Gate (0.80, 0.85, 0.90, 0.95, 0.99) to plot the 
trade-off between F1 Score and False Positive Rate (FPR).
"""
import os
import sys
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
from dotenv import load_dotenv
load_dotenv(PROJECT_ROOT / ".env")

from semantic_firewall.sdk import Firewall
from semantic_firewall.benchmarks.research.experiments.helpers import (
    RESULTS_ROOT, TABLES_DIR,
    compute_metrics, write_csv_rows, write_json,
    normalize_binary_label, print_header, print_section, format_pct
)

try:
    from datasets import load_dataset
except ImportError:
    load_dataset = None

def _fresh_firewall():
    from semantic_firewall.core.orchestrator.semantic_cache import SemanticCache
    SemanticCache._instance = None
    import threading
    SemanticCache._lock = threading.Lock()
    fw = Firewall()
    if fw._local and hasattr(fw._local, '_cache'):
        pass # fw._local._cache.clear() # USER REQUESTED TO REUSE WARM CACHE
    return fw

def evaluate_single(fw, text, true_label):
    try:
        decision = fw.analyze(text)
        if "Detector unavailable" in str(decision.reason):
            return true_label, 0, -1
        predicted = 1 if decision.action in {"BLOCK", "FLAG", "REDACT"} else 0
        return true_label, predicted, 1
    except Exception as e:
        if '429' in str(e):
            time.sleep(2)
            return evaluate_single(fw, text, true_label)
        return true_label, 0, -1

def run_threshold_eval(threshold, test_chunk, workers=5):
    print_section(f"Evaluating Threshold: {threshold}")
    os.environ["SEMANTIC_FIREWALL_LLM_GATE_THRESHOLD"] = str(threshold)
    fw = _fresh_firewall()
    
    tp = fp = tn = fn = 0
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(evaluate_single, fw, ex["text"], normalize_binary_label(ex["label"])): ex for ex in test_chunk}
        for i, future in enumerate(as_completed(futures)):
            t_label, p_label, status = future.result()
            if status == -1: continue
            if t_label == 1 and p_label == 1: tp += 1
            elif t_label == 0 and p_label == 1: fp += 1
            elif t_label == 0 and p_label == 0: tn += 1
            elif t_label == 1 and p_label == 0: fn += 1
            if (i+1) % 50 == 0:
                print(f"  ... processed {i+1}/{len(test_chunk)}")
                
    metrics = compute_metrics(tp, fp, tn, fn)
    print(f"  -> F1: {format_pct(metrics['f1'])} | FPR: {format_pct(metrics['false_positive_rate'])}")
    return metrics

def main():
    print_header("EXPERIMENT 16: THRESHOLD SENSITIVITY")
    dataset = load_dataset("neuralchemy/Prompt-injection-dataset", "core")
    # For speed of threshold testing over 5 configs, we use 500 samples
    full_dataset = list(dataset["train"])
    test_chunk = full_dataset[:500]
    
    thresholds = [0.80, 0.85, 0.90, 0.95, 0.99]
    results = {}
    
    for th in thresholds:
        metrics = run_threshold_eval(th, test_chunk, workers=5)
        results[str(th)] = metrics
        
    os.makedirs(RESULTS_ROOT / "threshold", exist_ok=True)
    write_json(RESULTS_ROOT / "threshold" / "threshold_sensitivity.json", results)
    
    header = ["threshold", "f1", "fpr", "precision", "recall"]
    rows = []
    for th, m in results.items():
        rows.append([th, round(m["f1"], 4), round(m["false_positive_rate"], 4), round(m["precision"], 4), round(m["recall"], 4)])
    write_csv_rows(TABLES_DIR / "threshold_sensitivity.csv", rows, header)
    print("Threshold Analysis Complete!")

if __name__ == "__main__":
    main()
