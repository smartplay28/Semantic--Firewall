import sys
import argparse
import os
import time
from pathlib import Path

from helpers import PROJECT_ROOT, print_header

sys.path.insert(0, str(PROJECT_ROOT))
from dotenv import load_dotenv
load_dotenv(PROJECT_ROOT / ".env")

from semantic_firewall.core.orchestrator.orchestrator import SemanticFirewallOrchestrator
from tqdm import tqdm
from datasets import load_dataset

def auto_detect_cols(dataset):
    cols = dataset.column_names
    text_col = next((c for c in ['text', 'prompt', 'sentence', 'input'] if c in cols), cols[0])
    label_col = next((c for c in ['label', 'is_injection', 'injection', 'target'] if c in cols), cols[-1])
    return text_col, label_col

def test_dataset(dataset_name, split, orchestrator, num_samples):
    print(f"\nLoading up to {num_samples} samples from {dataset_name} ({split}) ...")
    try:
        dataset = load_dataset(dataset_name, split=split)
    except Exception as e:
        print(f"Failed to load dataset: {e}")
        return

    text_col, label_col = auto_detect_cols(dataset)
    print(f"Using text col: '{text_col}', label col: '{label_col}'")
    
    test_data = dataset.shuffle(seed=42).select(range(min(num_samples, len(dataset))))

    tp = fp = fn = tn = 0
    
    print(f"Running evaluation on {dataset_name} ...")
    for item in tqdm(test_data, desc=dataset_name.split('/')[-1]):
        prompt = str(item[text_col])
        try:
            # handle string labels like "injection" or "safe"
            lbl = str(item[label_col]).lower()
            is_injection = (lbl in ['1', 'true', 'injection', 'yes'])
        except:
            is_injection = bool(item[label_col])
            
        # Cache will naturally process requests
        
        result = orchestrator.analyze(text=prompt)
        blocked = (result.action == "BLOCK")
        
        if is_injection and blocked:
            tp += 1
        elif is_injection and not blocked:
            fn += 1
        elif not is_injection and blocked:
            fp += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0

    print(f"\n--- Results for {dataset_name} ---")
    print(f"Accuracy:  {accuracy*100:.1f}%")
    print(f"Precision: {precision*100:.1f}%")
    print(f"Recall:    {recall*100:.1f}%")
    print(f"TP: {tp}, FP: {fp}, FN: {fn}, TN: {tn}\n")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--num-samples", type=int, default=25)
    args = parser.parse_args()

    print_header("EXPERIMENT 5: LLM GUARD DATASET COMPARISON")
    orchestrator = SemanticFirewallOrchestrator()
    
    # Abdennebi split is usually 'wildguard' or 'InjecGuard_valid' since it doesn't have 'train'
    test_dataset("Abdennebi/protectai-prompt-injection-validation", "wildguard", orchestrator, args.num_samples)
    test_dataset("dmaniloff/glassbox_protectai_injection_test", "test", orchestrator, args.num_samples)

if __name__ == "__main__":
    main()
