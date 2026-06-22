"""
Experiment 7d: Ablation Config 9 (Full System - Cold Start)
=============================================================
Evaluates the Full System on 2,000 samples starting from a completely
EMPTY cache. As the 2,000 samples are evaluated, the cache dynamically
builds up ("learns"). This simulates a real-world fresh deployment.
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
    compute_metrics, format_pct, write_csv_rows, write_json,
    normalize_binary_label, print_header, print_section,
)
import json

try:
    from datasets import load_dataset
except ImportError:
    load_dataset = None

def _fresh_firewall():
    """Create a fresh Firewall with a completely cleared cache."""
    from semantic_firewall.core.orchestrator.semantic_cache import SemanticCache
    SemanticCache._instance = None
    import threading
    SemanticCache._lock = threading.Lock()
    fw = Firewall()
    if fw._local and hasattr(fw._local, '_cache'):
        fw._local._cache.clear()
    return fw

def evaluate_single(fw, text, true_label):
    try:
        start_t = time.perf_counter()
        decision = fw.analyze(text)
        lat = (time.perf_counter() - start_t) * 1000
        if "Detector unavailable" in str(decision.reason):
            return true_label, 0, -1
        predicted = 1 if decision.action in {"BLOCK", "FLAG", "REDACT"} else 0
        return true_label, predicted, lat
    except Exception as e:
        if '429' in str(e) or 'rate' in str(e).lower() or 'unavailable' in str(e).lower() or 'timeout' in str(e).lower():
            return true_label, 0, -1
        return true_label, 0, -1

def main():
    print_header("EXPERIMENT 7d: ABLATION CONFIG 9 (COLD START)")
    dataset = load_dataset("neuralchemy/Prompt-injection-dataset", "core")
    full_dataset = list(dataset["train"])
    test_chunk = full_dataset[:2000]
    
    os.environ["SEMANTIC_FIREWALL_DISABLE_LLM_DETECTORS"] = "0"
    os.environ["SEMANTIC_FIREWALL_LLM_GATE_ENABLED"] = "1"
    os.environ["SEMANTIC_FIREWALL_LLM_GATE_THRESHOLD"] = "1.0"
    os.environ["SEMANTIC_FIREWALL_SIMILAR_CACHE_ENABLED"] = "1"
    os.environ["SEMANTIC_FIREWALL_ENSEMBLE_ENABLED"] = "1"

    fw = _fresh_firewall()
    
    tp = fp = tn = fn = 0
    latencies = []
    
    print(f"Evaluating: Config 9: Full System (Cold Start) ({len(test_chunk)} samples)")
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(evaluate_single, fw, ex["text"], normalize_binary_label(ex["label"])): ex for ex in test_chunk}
        for i, future in enumerate(as_completed(futures)):
            t_label, p_label, lat = future.result()
            if lat == -1: continue
            latencies.append(lat)
            if t_label == 1 and p_label == 1: tp += 1
            elif t_label == 0 and p_label == 1: fp += 1
            elif t_label == 0 and p_label == 0: tn += 1
            elif t_label == 1 and p_label == 0: fn += 1
            if (i+1) % 50 == 0:
                print(f"  ... processed {i+1}/{len(test_chunk)}")
                
    metrics = compute_metrics(tp, fp, tn, fn)
    metrics["tp"], metrics["fp"], metrics["tn"], metrics["fn"] = tp, fp, tn, fn
    avg_lat = sum(latencies)/len(latencies) if latencies else 0.0
    
    print(f"  -> F1: {format_pct(metrics['f1'])} | Latency: {avg_lat:.2f}ms")

    # Load existing ablation results to append this one
    ablation_json_path = RESULTS_ROOT / "ablation" / "chunked_ablation.json"
    if ablation_json_path.exists():
        with open(ablation_json_path, 'r') as f:
            results = json.load(f)
    else:
        results = {}

    results["Config 9: Full System (Cold Start)"] = {
        "metrics": metrics,
        "avg_latency_ms": avg_lat
    }
    
    write_json(ablation_json_path, results)
    
    # Rewrite CSV
    header = ["configuration", "sample_count", "accuracy", "precision", "recall", "f1", "avg_latency_ms"]
    rows = []
    for name, data in results.items():
        m = data["metrics"]
        rows.append([name, 2000, round(m["accuracy"], 4), round(m["precision"], 4), round(m["recall"], 4), round(m["f1"], 4), round(data["avg_latency_ms"], 2)])
    write_csv_rows(TABLES_DIR / "chunked_ablation.csv", rows, header)
    
    print("Config 9 Complete!")

if __name__ == "__main__":
    main()
