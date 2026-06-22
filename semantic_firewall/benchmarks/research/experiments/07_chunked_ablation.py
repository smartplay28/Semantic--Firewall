import os
import sys
import time
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from helpers import (
    PROJECT_ROOT, RESULTS_ROOT, TABLES_DIR,
    compute_metrics, format_pct, write_csv_rows, write_json,
    experiment_metadata, normalize_binary_label,
    print_header, print_section,
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

def run_chunk_eval(label, config_env, test_chunk, workers=5):
    print_section(f"Evaluating: {label} ({len(test_chunk)} samples)")
    _set_env(**config_env)
    fw = _fresh_firewall()
    
    tp = fp = tn = fn = 0
    latencies = []
    
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(evaluate_single, fw, ex["text"], normalize_binary_label(ex["label"])): ex for ex in test_chunk}
        for i, future in enumerate(as_completed(futures)):
            t_label, p_label, lat = future.result()
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
    return metrics, avg_lat

def main():
    print_header("EXPERIMENT 7: CHUNKED ABLATION STUDY")
    dataset = load_dataset("neuralchemy/Prompt-injection-dataset", "core")
    full_dataset = list(dataset["train"])
    
    # We need 2000 samples total, divided into 8 chunks = 250 samples per chunk.
    chunk_size = 250
    
    configs = [
        ("Raw LLM Gate Only", {"SEMANTIC_FIREWALL_DISABLE_LLM_DETECTORS": 1, "SEMANTIC_FIREWALL_SIMILAR_CACHE_ENABLED": 0}),
        ("Regex Only", {"SEMANTIC_FIREWALL_DISABLE_LLM_DETECTORS": 1, "SEMANTIC_FIREWALL_LLM_GATE_ENABLED": 0}),
        ("Semantic Cache Only", {"SEMANTIC_FIREWALL_DISABLE_LLM_DETECTORS": 1, "SEMANTIC_FIREWALL_LLM_GATE_ENABLED": 0}),
        ("Parallel Detectors Only", {"SEMANTIC_FIREWALL_SIMILAR_CACHE_ENABLED": 0, "SEMANTIC_FIREWALL_LLM_GATE_ENABLED": 0}),
        ("Regex + Cache", {"SEMANTIC_FIREWALL_DISABLE_LLM_DETECTORS": 1, "SEMANTIC_FIREWALL_LLM_GATE_ENABLED": 0}),
        ("Regex + Parallel Detectors", {"SEMANTIC_FIREWALL_SIMILAR_CACHE_ENABLED": 0, "SEMANTIC_FIREWALL_LLM_GATE_ENABLED": 0}),
        ("All Fast Layers (No LLM)", {"SEMANTIC_FIREWALL_LLM_GATE_ENABLED": 0}),
        ("Full System", {})
    ]
    
    test_chunk = full_dataset[:2000]
    
    results = {}
    for i, (name, env_cfg) in enumerate(configs):
        if name == "Semantic Cache Only":
            # Just cache implies no regex.
            env_cfg["SEMANTIC_FIREWALL_REGEX_ENABLED"] = 0
        if name == "Regex + Cache":
            env_cfg["SEMANTIC_FIREWALL_REGEX_ENABLED"] = 1
            
        metrics, avg_lat = run_chunk_eval(name, env_cfg, test_chunk, workers=8)
        results[name] = {"metrics": metrics, "avg_latency_ms": avg_lat}
        
    write_json(RESULTS_ROOT / "ablation" / "chunked_ablation.json", results)
    
    header = ["configuration", "sample_count", "accuracy", "precision", "recall", "f1", "avg_latency_ms"]
    rows = []
    for name, data in results.items():
        m = data["metrics"]
        rows.append([name, 2000, round(m["accuracy"], 4), round(m["precision"], 4), round(m["recall"], 4), round(m["f1"], 4), round(data["avg_latency_ms"], 2)])
    write_csv_rows(TABLES_DIR / "chunked_ablation.csv", rows, header)
    print("Done!")

if __name__ == "__main__":
    main()
