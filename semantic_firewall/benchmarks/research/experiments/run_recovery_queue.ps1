# run_recovery_queue.ps1
Write-Host "Starting Recovery Queue..."

$scripts = @(
    "semantic_firewall\benchmarks\research\experiments\07c_chunked_ablation_recovery2.py",
    "semantic_firewall\benchmarks\research\experiments\09_benign_degradation.py",
    "semantic_firewall\benchmarks\research\experiments\11_multi_turn_hf.py",
    "semantic_firewall\benchmarks\research\experiments\08_ood_warmed_cache.py",
    "semantic_firewall\benchmarks\research\experiments\14_toxicchat_warm_cache_eval.py",
    "semantic_firewall\benchmarks\research\experiments\15_multidataset_eval.py"
)

foreach ($script in $scripts) {
    Write-Host "================================================="
    Write-Host "Executing $script ..."
    Write-Host "================================================="
    python $script
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Script $script failed with exit code $LASTEXITCODE."
        exit $LASTEXITCODE
    }
}

Write-Host "ALL QUEUED TASKS RECOVERED AND COMPLETED SUCCESSFULLY!"
