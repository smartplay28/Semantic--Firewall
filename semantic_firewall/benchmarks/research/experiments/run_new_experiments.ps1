# Run New Experiments Queue
# ==========================
# Experiment 18: Llama Guard on ToxicChat & BeaverTails (real head-to-head)
# Experiment 19: Gate Swap Comparison (GPT-4o-mini, Claude, Gemini as LLM Gate)

Write-Host "========================================"
Write-Host "  NEW EXPERIMENTS QUEUE"
Write-Host "========================================"
Write-Host ""

$experimentDir = "c:\Users\Aksha\OneDrive\Desktop\semantic_firewall\semantic_firewall\benchmarks\research\experiments"

# --- Experiment 18: Llama Guard Cross-Dataset ---
Write-Host "[1/2] Starting Experiment 18: Llama Guard on ToxicChat & BeaverTails..."
Write-Host "  Estimated time: 1-2 hours (depends on API rate limits)"
python "$experimentDir\18_llamaguard_crossdataset.py" --max-samples 2000 --sleep 0.5
if ($LASTEXITCODE -ne 0) {
    Write-Host "  [WARNING] Experiment 18 had issues. Continuing..."
}
Write-Host "[1/2] Experiment 18 Complete!"
Write-Host ""

# --- Experiment 19: Gate Swap Comparison ---
Write-Host "[2/2] Starting Experiment 19: Gate Swap Comparison..."
Write-Host "  Estimated time: 1-2 hours (3 models x 500 samples)"
python "$experimentDir\19_gate_swap_comparison.py" --max-samples 2000 --workers 5
if ($LASTEXITCODE -ne 0) {
    Write-Host "  [WARNING] Experiment 19 had issues. Continuing..."
}
Write-Host "[2/2] Experiment 19 Complete!"
Write-Host ""

Write-Host "========================================"
Write-Host "  ALL NEW EXPERIMENTS COMPLETE!"
Write-Host "========================================"
