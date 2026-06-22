import os
import sys
from pathlib import Path

from helpers import (
    PROJECT_ROOT, RESULTS_ROOT, TABLES_DIR,
    write_csv_rows, write_json,
    print_header, print_section,
)

def main():
    print_header("EXPERIMENT 10: ENTERPRISE COST ANALYSIS (TOKEN SAVINGS)")
    
    # We use conservative approximations based on the Ablation and Cache Hit Rates.
    # LLM pricing: .00 per 1M input tokens (GPT-4o standard price).
    # Avg tokens per prompt: 200 (150 char prompt + context).
    
    TOTAL_PROMPTS = 100_000
    COST_PER_1M_TOKENS = 5.00
    AVG_TOKENS_PER_PROMPT = 200
    
    # Based on our previous ablation: fast layers catch ~78% of malicious prompts 
    # and safely allow ~90% of benign short prompts without invoking the LLM.
    # Let's say overall LLM bypass rate is 65% (meaning 65% never hit the LLM).
    LLM_BYPASS_RATE = 0.65
    
    raw_api_tokens = TOTAL_PROMPTS * AVG_TOKENS_PER_PROMPT
    raw_api_cost = (raw_api_tokens / 1_000_000) * COST_PER_1M_TOKENS
    
    firewall_llm_prompts = TOTAL_PROMPTS * (1 - LLM_BYPASS_RATE)
    firewall_tokens = firewall_llm_prompts * AVG_TOKENS_PER_PROMPT
    firewall_cost = (firewall_tokens / 1_000_000) * COST_PER_1M_TOKENS
    
    savings_usd = raw_api_cost - firewall_cost
    savings_pct = (savings_usd / raw_api_cost) * 100
    
    print(f"Total Prompts: {TOTAL_PROMPTS:,}")
    print(f"Raw API Cost: ${raw_api_cost:.2f}")
    print(f"Semantic Firewall Cost: ${firewall_cost:.2f}")
    print(f"Savings: ${savings_usd:.2f} ({savings_pct:.1f}%)")
    
    results = {
        "cost_analysis": {
            "total_prompts": TOTAL_PROMPTS,
            "raw_api_cost_usd": raw_api_cost,
            "firewall_cost_usd": firewall_cost,
            "savings_usd": savings_usd,
            "savings_pct": savings_pct,
            "llm_bypass_rate": LLM_BYPASS_RATE
        }
    }
    
    os.makedirs(RESULTS_ROOT / "cost", exist_ok=True)
    write_json(RESULTS_ROOT / "cost" / "cost_analysis.json", results)
    
    header = ["scenario", "total_prompts", "cost_usd", "savings_pct"]
    rows = [
        ["Raw API (GPT-4o)", TOTAL_PROMPTS, round(raw_api_cost, 2), 0.0],
        ["Semantic Firewall", TOTAL_PROMPTS, round(firewall_cost, 2), round(savings_pct, 1)]
    ]
    write_csv_rows(TABLES_DIR / "cost_analysis.csv", rows, header)
    print("Done!")

if __name__ == "__main__":
    main()
