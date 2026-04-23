from datasets import load_dataset
from semantic_firewall import Firewall
import json

print("=" * 60)
print("DOWNLOADING DATASET (first time only, ~100MB)...")
print("=" * 60)

# Download dataset
dataset = load_dataset("neuralchemy/Prompt-injection-dataset", "core")

print("\n✓ Dataset loaded successfully!")
print(f"  Train: {len(dataset['train'])} examples")
print(f"  Validation: {len(dataset['validation'])} examples")
print(f"  Test: {len(dataset['test'])} examples")

# Get first few examples
test_set = dataset["test"]
print("\n" + "=" * 60)
print("FIRST 3 EXAMPLES:")
print("=" * 60)
for i in range(3):
    example = test_set[i]
    print(f"\nExample {i+1}:")
    print(f"  Text: {example['text'][:80]}...")
    print(f"  Label: {example['label']} (1=attack, 0=benign)")
    print(f"  Category: {example['category']}")
    print(f"  Severity: {example['severity']}")

# Test your firewall on these examples
print("\n" + "=" * 60)
print("TESTING YOUR FIREWALL:")
print("=" * 60)

fw = Firewall()

correct = 0
for i in range(min(10, len(test_set))):  # Test on first 10
    example = test_set[i]
    text = example["text"]
    true_label = example["label"]  # 1 = attack, 0 = benign
    
    # Run your firewall
    decision = fw.analyze(text)
    
    # Check if correct (attacks should be flagged/blocked)
    predicted_label = 1 if decision.action in ["BLOCK", "FLAG"] else 0
    is_correct = predicted_label == true_label
    correct += is_correct
    
    status = "✓ CORRECT" if is_correct else "✗ WRONG"
    print(f"\n[{i+1}] {status}")
    print(f"    Text: {text[:60]}...")
    print(f"    Expected: {true_label} | Got: {predicted_label} (Action: {decision.action})")

print(f"\n" + "=" * 60)
print(f"QUICK TEST RESULTS: {correct}/10 correct ({correct*10}%)")
print("=" * 60)