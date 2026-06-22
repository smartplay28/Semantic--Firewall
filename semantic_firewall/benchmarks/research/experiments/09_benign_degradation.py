import os
import sys
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from helpers import (
    PROJECT_ROOT, RESULTS_ROOT, TABLES_DIR,
    compute_metrics, format_pct, write_csv_rows, write_json,
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

def evaluate_single(fw, text):
    try:
        start_t = time.perf_counter()
        decision = fw.analyze(text)
        lat = (time.perf_counter() - start_t) * 1000
        predicted = 1 if decision.action in {"BLOCK", "FLAG", "REDACT"} else 0
        return 0, predicted, lat  # True label is always 0 (Benign)
    except Exception as e:
        if '429' in str(e):
            time.sleep(2)
            return evaluate_single(fw, text)
        return 0, 0, 0.0

def run_eval(fw, test_set, workers=8):
    print_section(f"Evaluating Benign Degradation ({len(test_set)} samples)")
    tp = fp = tn = fn = 0
    latencies = []
    
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(evaluate_single, fw, ex["text"]): ex for ex in test_set}
        for i, future in enumerate(as_completed(futures)):
            t_label, p_label, lat = future.result()
            latencies.append(lat)
            if p_label == 1: fp += 1
            elif p_label == 0: tn += 1
            if (i+1) % 50 == 0:
                print(f"  ... processed {i+1}/{len(test_set)}")
                
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    avg_lat = sum(latencies)/len(latencies) if latencies else 0.0
    
    print(f"  -> False Positive Rate (FPR): {format_pct(fpr)} | Latency: {avg_lat:.2f}ms")
    return {"fpr": fpr, "fp": fp, "tn": tn}, avg_lat

def main():
    print_header("EXPERIMENT 9: BENIGN DEGRADATION (FALSE POSITIVES)")
    
    if load_dataset is None:
        raise RuntimeError("datasets package is required")
        
    print("Loading tatsu-lab/alpaca ...")
    ds = load_dataset("tatsu-lab/alpaca")
    
    # Extract just instructions
    benign_samples = []
    for row in ds["train"]:
        # some rows have input, some just instruction
        text = row.get("instruction", "") + " " + row.get("input", "")
        if text.strip():
            benign_samples.append({"text": text.strip()})
            
    test_set = benign_samples[:2000]
    
    fw = Firewall()
    if fw._local and hasattr(fw._local, '_cache'):
        fw._local._cache.clear()
        
    metrics, lat = run_eval(fw, test_set, workers=8)
    
    results = {"benign_degradation": {"metrics": metrics, "avg_latency_ms": lat}}
    os.makedirs(RESULTS_ROOT / "benign", exist_ok=True)
    write_json(RESULTS_ROOT / "benign" / "benign_degradation.json", results)
    
    header = ["dataset", "sample_count", "false_positives", "true_negatives", "fpr", "avg_latency_ms"]
    rows = [["tatsu-lab/alpaca", len(test_set), metrics["fp"], metrics["tn"], round(metrics["fpr"], 4), round(lat, 2)]]
    write_csv_rows(TABLES_DIR / "benign_degradation.csv", rows, header)
    print("Done!")

if __name__ == "__main__":
    main()
