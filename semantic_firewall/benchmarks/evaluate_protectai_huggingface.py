import asyncio
import time
import pandas as pd
from datasets import load_dataset
from semantic_firewall.core.orchestrator.orchestrator import SemanticFirewallOrchestrator

async def run_huggingface_eval():
    print("=" * 60)
    print("PROTECT AI / HUGGINGFACE DATASET BENCHMARK")
    print("=" * 60)
    
    # Load ProtectAI's aggregated dataset or the standard Deepset injection dataset
    print("[+] Downloading HuggingFace dataset 'deepset/prompt-injections' (Standard benchmark)...")
    dataset = load_dataset("deepset/prompt-injections", split="train")
    
    # Shuffle and select samples (max 1000 or the dataset size)
    sample_size = min(1000, len(dataset))
    dataset = dataset.shuffle(seed=42).select(range(sample_size))
    print(f"[+] Successfully loaded {len(dataset)} samples from HuggingFace.")
    
    orchestrator = SemanticFirewallOrchestrator()
    print("[+] Loaded Semantic Firewall (Regex -> ChromaDB -> Llama-3.3-70B)")
    
    tp = 0
    fp = 0
    tn = 0
    fn = 0
    latencies = []
    
    print("[+] Executing evaluation on live Semantic Firewall...")
    for i, sample in enumerate(dataset):
        text = str(sample.get("text", sample.get("prompt", "")))
        label = sample.get("label", 1)  # 1 is injection, 0 is benign
        
        if not text.strip():
            continue
            
        start_time = time.time()
        decision = orchestrator.analyze(text)
        latency = time.time() - start_time
        latencies.append(latency)
        
        is_blocked = decision.action == "BLOCK"
        is_malicious = label == 1
        
        if is_blocked and is_malicious:
            tp += 1
        elif is_blocked and not is_malicious:
            fp += 1
        elif not is_blocked and not is_malicious:
            tn += 1
        elif not is_blocked and is_malicious:
            fn += 1
            
        if (i + 1) % 25 == 0:
            print(f"  ... processed {i + 1}/1000 (Avg Latency: {(sum(latencies)/len(latencies))*1000:.2f}ms)")
            
    # Calculate metrics
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    avg_latency = sum(latencies) / len(latencies) if latencies else 0
    
    print("=" * 60)
    print("HUGGINGFACE DATASET EVALUATION RESULTS:")
    print("=" * 60)
    print(f"True Positives (TP)  : {tp}")
    print(f"True Negatives (TN)  : {tn}")
    print(f"False Positives (FP) : {fp}")
    print(f"False Negatives (FN) : {fn}")
    print(f"Precision            : {precision * 100:.2f}%")
    print(f"Recall               : {recall * 100:.2f}%")
    print(f"F1 Score             : {f1 * 100:.2f}%")
    print(f"Average Latency      : {avg_latency * 1000:.2f} ms")
    print("=" * 60)
    
    results_df = pd.DataFrame([{
        "Dataset": "HuggingFace_Prompt_Injections",
        "Precision": precision,
        "Recall": recall,
        "F1": f1,
        "AvgLatency_ms": avg_latency * 1000
    }])
    results_df.to_csv("hf_evaluation_results.csv", index=False)
    print("[+] Results saved to hf_evaluation_results.csv")

if __name__ == "__main__":
    asyncio.run(run_huggingface_eval())
