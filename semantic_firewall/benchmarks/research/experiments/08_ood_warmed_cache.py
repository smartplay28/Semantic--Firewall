import os
import sys
import time
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from helpers import (
    PROJECT_ROOT, RESULTS_ROOT, TABLES_DIR,
    compute_metrics, format_pct, write_csv_rows, write_json,
    normalize_binary_label, print_header, print_section,
)

sys.path.insert(0, str(PROJECT_ROOT))
from dotenv import load_dotenv
load_dotenv(PROJECT_ROOT / ".env")

from semantic_firewall.sdk import Firewall
try:
    from datasets import load_dataset
except ImportError:
    load_dataset = None

def _set_env(**overrides):
    defaults = {
        "SEMANTIC_FIREWALL_DISABLE_LLM_DETECTORS": "0",
        "SEMANTIC_FIREWALL_LLM_GATE_ENABLED": "1",
        "SEMANTIC_FIREWALL_LLM_GATE_THRESHOLD": "1.0",
        "SEMANTIC_FIREWALL_SIMILAR_CACHE_ENABLED": "1",
        "SEMANTIC_FIREWALL_ENSEMBLE_ENABLED": "1",
    }
    defaults.update(overrides)
    for k, v in defaults.items():
        os.environ[k] = str(v)

def _fresh_firewall():
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
        predicted = 1 if decision.action in {"BLOCK", "FLAG", "REDACT"} else 0
        return true_label, predicted, lat
    except Exception as e:
        if '429' in str(e):
            time.sleep(2)
            return evaluate_single(fw, text, true_label)
        return true_label, 0, 0.0

def warm_cache(fw, dataset, chunk_size=50):
    print_section(f"Warming Cache with {len(dataset)} samples")
    def warm_single(text):
        try:
            fw.analyze(text)
        except Exception:
            pass
            
    # Process sequentially to ensure DB doesn't lock up or hit crazy limits
    for i, ex in enumerate(dataset):
        warm_single(ex["text"])
        if (i+1) % 100 == 0:
            print(f"  ... warmed {i+1}/{len(dataset)}")
    print("Cache warmed successfully.")

def run_eval(fw, label, test_set, workers=5):
    print_section(f"Evaluating {label} ({len(test_set)} OOD samples)")
    tp = fp = tn = fn = 0
    latencies = []
    
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(evaluate_single, fw, ex["text"], normalize_binary_label(ex["label"])): ex for ex in test_set}
        for i, future in enumerate(as_completed(futures)):
            t_label, p_label, lat = future.result()
            latencies.append(lat)
            if t_label == 1 and p_label == 1: tp += 1
            elif t_label == 0 and p_label == 1: fp += 1
            elif t_label == 0 and p_label == 0: tn += 1
            elif t_label == 1 and p_label == 0: fn += 1
            if (i+1) % 50 == 0:
                print(f"  ... processed {i+1}/{len(test_set)}")
                
    metrics = compute_metrics(tp, fp, tn, fn)
    metrics["tp"], metrics["fp"], metrics["tn"], metrics["fn"] = tp, fp, tn, fn
    avg_lat = sum(latencies)/len(latencies) if latencies else 0.0
    print(f"  -> F1: {format_pct(metrics['f1'])} | Latency: {avg_lat:.2f}ms")
    return metrics, avg_lat

def main():
    print_header("EXPERIMENT 8: PRE-WARMED CACHE OUT-OF-DISTRIBUTION (OOD) GENERALIZATION")
    
    if load_dataset is None:
        raise RuntimeError("datasets package is required")
        
    print("Loading Neuralchemy for Cache Warming...")
    ds_train = load_dataset("neuralchemy/Prompt-injection-dataset", "core")
    warm_set = list(ds_train["train"])[:2000]
    
    print("Loading deepset/prompt-injections for OOD Testing...")
    ds_test = load_dataset("deepset/prompt-injections")
    # map deepset labels: 1 is injection, 0 is safe
    full_ood = []
    for row in ds_test["train"]:
        # some datasets use 'label', some use 'is_injection'
        label = row.get("label", row.get("is_injection", 0))
        text = row.get("text", row.get("prompt", ""))
        full_ood.append({"text": text, "label": label})
        
    test_set = full_ood[:2000]
    
    results = {}
    
    # Run 1: Raw API
    _set_env(SEMANTIC_FIREWALL_DISABLE_LLM_DETECTORS=1, SEMANTIC_FIREWALL_SIMILAR_CACHE_ENABLED=0)
    fw_raw = _fresh_firewall()
    metrics, lat = run_eval(fw_raw, "Raw API (No Firewall)", test_set, workers=8)
    results["raw_api"] = {"metrics": metrics, "avg_latency_ms": lat}
    
    # Run 2: Full System with pre-warmed cache
    _set_env() # Defaults (full system)
    fw_full = _fresh_firewall()
    warm_cache(fw_full, warm_set)
    metrics_full, lat_full = run_eval(fw_full, "Full Firewall (Warmed Cache)", test_set, workers=8)
    results["full_system_warmed"] = {"metrics": metrics_full, "avg_latency_ms": lat_full}
    
    os.makedirs(RESULTS_ROOT / "ood", exist_ok=True)
    write_json(RESULTS_ROOT / "ood" / "warmed_cache_ood.json", results)
    
    header = ["configuration", "sample_count", "accuracy", "precision", "recall", "f1", "avg_latency_ms"]
    rows = []
    for name, data in results.items():
        m = data["metrics"]
        rows.append([name, len(test_set), round(m["accuracy"], 4), round(m["precision"], 4), round(m["recall"], 4), round(m["f1"], 4), round(data["avg_latency_ms"], 2)])
    
    write_csv_rows(TABLES_DIR / "warmed_cache_ood.csv", rows, header)
    print("Done!")

if __name__ == "__main__":
    main()
