$ErrorActionPreference = "Stop"

Write-Host "Starting OpenRouter N=2000 evaluation suite..."

Write-Host "1. Evaluating GPT-4o-mini"
python semantic_firewall\benchmarks\research\experiments\12_enterprise_comparison.py --model "openai/gpt-4o-mini" --label "gpt_4o_mini" --max-samples 2000

Write-Host "2. Evaluating Claude 3.5 Haiku"
python semantic_firewall\benchmarks\research\experiments\12_enterprise_comparison.py --model "anthropic/claude-3-5-haiku" --label "claude_3_5_haiku" --max-samples 2000

Write-Host "3. Evaluating Gemini Flash Lite"
python semantic_firewall\benchmarks\research\experiments\12_enterprise_comparison.py --model "google/gemini-2.5-flash" --label "gemini_flash_lite" --max-samples 2000

Write-Host "4. Evaluating Security Models (Llama Guard 4, GPT-OSS-Safeguard)"
python semantic_firewall\benchmarks\research\experiments\13_security_model_comparison.py --max-samples 2000

Write-Host "ALL OPENROUTER EXPERIMENTS FINISHED."
