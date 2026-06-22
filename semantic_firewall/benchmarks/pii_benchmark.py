import os
import json
from collections import defaultdict
from datasets import load_dataset
from semantic_firewall.core.agents.pii_detector import PIIDetectorAgent
from tqdm import tqdm

TARGET_LABELS = {
    'EMAIL', 'IPV4', 'IPV6', 'MAC', 'PHONENUMBER', 'IBAN', 'DOB', 
    'CREDITCARDNUMBER', 'CREDITCARDCVV', 'SSN', 'ZIPCODE', 'ACCOUNTNUMBER'
}

def run_pii_benchmark(num_samples=250000):
    print("Loading ai4privacy/pii-masking-200k...")
    dataset = load_dataset("ai4privacy/pii-masking-200k", "default")
    
    print("Filtering for English language only...")
    english_dataset = dataset['train'].filter(lambda x: x['language'] == 'en')
    
    total_available = len(english_dataset)
    samples_to_test = min(num_samples, total_available)
    print(f"Testing on {samples_to_test} English samples out of {total_available}...")
    
    test_data = english_dataset.select(range(samples_to_test))
    
    pii_agent = PIIDetectorAgent()
    
    category_tp = defaultdict(int)
    category_fn = defaultdict(int)
    
    global_tp = 0
    global_fp = 0
    global_fn = 0
    
    for idx, item in enumerate(tqdm(test_data)):
        source_text = item['source_text']
        dataset_masks = item.get('privacy_mask', [])
        
        # Ground truth mapping: value -> label
        ground_truth_map = {}
        for mask in dataset_masks:
            label = mask['label']
            if label in TARGET_LABELS:
                val = mask['value'].strip().lower()
                ground_truth_map[val] = label
                
        # Analyze directly with the PII Agent
        pii_agent_result = pii_agent.run(source_text)
        
        # Agent found values
        agent_values = set()
        if pii_agent_result and pii_agent_result.matched:
            for match in pii_agent_result.matched:
                agent_values.add(match.value.strip().lower())
                
        gt_values = set(ground_truth_map.keys())
        
        # Global metrics
        sample_tp = len(gt_values & agent_values)
        sample_fp = len(agent_values - gt_values)
        sample_fn = len(gt_values - agent_values)
        
        global_tp += sample_tp
        global_fp += sample_fp
        global_fn += sample_fn
        
        # Category metrics
        for val in gt_values:
            label = ground_truth_map[val]
            if val in agent_values:
                category_tp[label] += 1
            else:
                category_fn[label] += 1

    precision = global_tp / (global_tp + global_fp) if (global_tp + global_fp) > 0 else 0
    recall = global_tp / (global_tp + global_fn) if (global_tp + global_fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    print("\n" + "="*60)
    print("ENGLISH-ONLY PII BENCHMARK COMPLETE")
    print("="*60)
    print(f"Total Samples Tested: {samples_to_test}")
    print(f"Total Ground-Truth PII Entities: {global_tp + global_fn}")
    print(f"True Positives: {global_tp} False Positives: {global_fp} False Negatives: {global_fn}")
    print(f"Recall: {recall*100:.1f}% Precision: {precision*100:.1f}% F1 Score: {f1*100:.1f}%")
    print("-" * 60)
    print(f"{'PII Type':<20} | {'TP':<8} | {'FN':<8} | {'Recall'}")
    print("-" * 60)
    
    sorted_labels = sorted(TARGET_LABELS, key=lambda x: (category_tp[x] / (category_tp[x] + category_fn[x]) if category_tp[x] + category_fn[x] > 0 else 0), reverse=True)
    
    for label in sorted_labels:
        tp = category_tp[label]
        fn = category_fn[label]
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0
        print(f"{label:<20} | {tp:<8} | {fn:<8} | {rec*100:.1f}%")
    print("="*60)

if __name__ == "__main__":
    run_pii_benchmark(250000)



