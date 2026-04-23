import os
import json
import dataclasses
from datasets import load_dataset
from agents.pii_detector import PIIDetectorAgent
from tqdm import tqdm

TARGET_LABELS = {
    'EMAIL', 'IPV4', 'IPV6', 'MAC', 'PHONENUMBER', 'IBAN', 'DOB', 
    'CREDITCARDNUMBER', 'CREDITCARDCVV', 'SSN', 'ZIPCODE', 'ACCOUNTNUMBER'
}

def run_pii_benchmark(num_samples=100):
    print(f"Loading {num_samples} samples from ai4privacy/pii-masking-200k...")
    dataset = load_dataset("ai4privacy/pii-masking-200k", "default")
    test_data = dataset['train'].select(range(num_samples))
    
    pii_agent = PIIDetectorAgent()
    
    tp, fp, fn = 0, 0, 0
    results = []
    
    print("\nStarting PII evaluation with automatic scoring...")
    for idx, item in enumerate(tqdm(test_data)):
        source_text = item['source_text']
        dataset_masks = item.get('privacy_mask', [])
        
        # Get ground truth values for things we care about
        ground_truth_values = set()
        for mask in dataset_masks:
            if mask['label'] in TARGET_LABELS:
                ground_truth_values.add(mask['value'].strip().lower())
        
        # Analyze directly with the PII Agent
        pii_agent_result = pii_agent.run(source_text)
        
        # Get what the agent found
        agent_values = set()
        if pii_agent_result and pii_agent_result.matched:
            for match in pii_agent_result.matched:
                agent_values.add(match.value.strip().lower())
                
        # Calculate metrics for this sample
        sample_tp = len(ground_truth_values & agent_values)
        sample_fp = len(agent_values - ground_truth_values)
        sample_fn = len(ground_truth_values - agent_values)
        
        tp += sample_tp
        fp += sample_fp
        fn += sample_fn
        
        results.append({
            "id": idx,
            "text": source_text,
            "ground_truth": list(ground_truth_values),
            "agent_found": list(agent_values),
            "missed_by_agent": list(ground_truth_values - agent_values),
            "false_positives": list(agent_values - ground_truth_values)
        })

    # Save results for manual review
    with open("results/pii_benchmark_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
        
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    
    print("\n" + "="*50)
    print("PII BENCHMARK COMPLETE")
    print("="*50)
    print(f"Total samples tested : {num_samples}")
    print(f"Target Labels Tracked: {', '.join(TARGET_LABELS)}")
    print(f"\nTrue Positives (TP)  : {tp}")
    print(f"False Positives (FP) : {fp}")
    print(f"False Negatives (FN) : {fn}")
    print("-" * 50)
    print(f"Precision            : {precision*100:.1f}%")
    print(f"Recall               : {recall*100:.1f}%")
    print("="*50)
    print("Check 'results/pii_benchmark_results.json' to see exactly what was missed/falsely flagged.")

if __name__ == "__main__":
    run_pii_benchmark(100)
