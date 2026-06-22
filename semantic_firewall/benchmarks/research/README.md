# Official Research Experiments & Results

This folder contains the experiment scripts and outputs for the Semantic Firewall paper.

## Folder Structure

```text
semantic_firewall/benchmarks/research/
  README.md
  run_all_experiments.py
  experiments/
    01_baseline_comparison.py
    02_ablation_study.py
    03_latency_benchmark.py
    04_pii_scaled.py
    05_unsafe_scaled.py
    06_red_team_extended.py
    07_llm_gate_efficiency.py
  results/
    baselines/
    ablation/
    latency/
    pii/
    unsafe/
    red_team/
    llm_gate/
    tables/
    figures/
```

## How to Run

### Run everything
```bash
python semantic_firewall/benchmarks/research/run_all_experiments.py
```

### Run individual experiments
```bash
# Fast experiments (no API calls)
python semantic_firewall/benchmarks/research/experiments/03_latency_benchmark.py
python semantic_firewall/benchmarks/research/experiments/04_pii_scaled.py

# API-dependent experiments (rate-limited)
python semantic_firewall/benchmarks/research/experiments/01_baseline_comparison.py
python semantic_firewall/benchmarks/research/experiments/05_unsafe_scaled.py
python semantic_firewall/benchmarks/research/experiments/06_red_team_extended.py
```

## Results for Paper

After running, the key paper artifacts will be:
- `semantic_firewall/benchmarks/research/results/tables/main_comparison.csv`
- `semantic_firewall/benchmarks/research/results/tables/ablation.csv`
- `semantic_firewall/benchmarks/research/results/tables/latency_summary.csv`
- `semantic_firewall/benchmarks/research/results/tables/llm_gate_efficiency.csv`
- `semantic_firewall/benchmarks/research/results/figures/`
