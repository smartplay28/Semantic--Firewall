import os
import time
import json
from datasets import load_dataset
from agents.unsafe_content_detector import UnsafeContentDetectorAgent
from tqdm import tqdm
from dotenv import load_dotenv

load_dotenv()



def run_unsafe_benchmark(num_samples=50):
    print(f"Loading {num_samples} samples from lmsys/toxic-chat...")
    # toxic-chat has prompts labeled with 'toxicity' (0 or 1)
    dataset = load_dataset("lmsys/toxic-chat", "toxicchat0124")
    
    # Let's try to get a mix of toxic and benign prompts
    test_data = dataset['train'].shuffle(seed=42).select(range(num_samples))
    
    # Initialize ONLY the Unsafe Content agent
    unsafe_agent = UnsafeContentDetectorAgent()
    
    tp, fp, fn, tn = 0, 0, 0, 0
    results = []
    
    print("\nStarting Unsafe Content evaluation (This uses the Groq API)...")
    for idx, item in enumerate(tqdm(test_data)):
        source_text = item['user_input']
        
        # In toxic-chat, toxicity == 1 means it's genuinely toxic/unsafe
        is_actually_toxic = item['toxicity'] == 1 
        
        # Analyze directly with the Agent
        try:
            agent_result = unsafe_agent.run(source_text)
            flagged_by_agent = agent_result.threat_found if agent_result else False
            
            # Calculate metrics
            if is_actually_toxic and flagged_by_agent:
                tp += 1
            elif not is_actually_toxic and flagged_by_agent:
                fp += 1
            elif is_actually_toxic and not flagged_by_agent:
                fn += 1
            else:
                tn += 1
                
            results.append({
                "id": idx,
                "text": source_text,
                "ground_truth_toxic": is_actually_toxic,
                "agent_flagged": flagged_by_agent,
                "agent_severity": agent_result.severity if agent_result else "NONE",
                "agent_summary": agent_result.summary if agent_result else ""
            })
            
        except Exception as e:
            print(f"Error on sample {idx}: {e}")
            
        # Avoid Groq API rate limits (e.g. 30 requests per minute)
        time.sleep(3.5)

    # Save results
    with open("results/unsafe_benchmark_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
        
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    
    print("\n" + "="*50)
    print("UNSAFE CONTENT BENCHMARK COMPLETE")
    print("="*50)
    print(f"Total samples tested : {num_samples}")
    print(f"\nTrue Positives (TP)  : {tp} (Correctly blocked toxic prompt)")
    print(f"False Positives (FP) : {fp} (Falsely blocked a safe prompt)")
    print(f"True Negatives (TN)  : {tn} (Correctly allowed safe prompt)")
    print(f"False Negatives (FN) : {fn} (Failed to block a toxic prompt)")
    print("-" * 50)
    print(f"Precision            : {precision*100:.1f}%")
    print(f"Recall               : {recall*100:.1f}%")
    print("="*50)

if __name__ == "__main__":
    # We use a small number like 50 because this makes real LLM API calls to Groq
    run_unsafe_benchmark(50)
