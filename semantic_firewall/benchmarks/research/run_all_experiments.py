"""
Master Runner â€” Official Research Experiments
================================================
Runs all experiments in sequence with proper ordering.

Usage:
  python semantic_firewall/benchmarks/research/run_all_experiments.py                    # Run everything
  python semantic_firewall/benchmarks/research/run_all_experiments.py --fast-only        # Only regex/PII (no API)
  python semantic_firewall/benchmarks/research/run_all_experiments.py --experiment 1     # Run specific experiment
  python semantic_firewall/benchmarks/research/run_all_experiments.py --experiment 1 3 4 # Run multiple
"""
import os
import sys
import subprocess
import argparse
import time
from pathlib import Path
from datetime import datetime

PROJECT_ROOT = Path(__file__).resolve().parents[3]
EXPERIMENTS_DIR = Path(__file__).resolve().parent / "experiments"

# Experiment registry: (script, name, needs_api, estimated_minutes)
EXPERIMENTS = [
    ("04_pii_scaled.py",           "Scaled PII Detection (500 samples)",       False, 2),
    ("01_baseline_comparison.py",  "Baseline Comparison (Regex vs LLM vs Full)", True, 30),
    ("02_ablation_study.py",       "Ablation Study",                            True, 45),
    ("03_latency_benchmark.py",    "Latency Benchmark",                         True, 10),
    ("05_unsafe_scaled.py",        "Scaled Unsafe Content (200 samples)",       True, 15),
    ("06_red_team_extended.py",    "Extended Red Team (56 attacks)",            True, 40),
    ("07_llm_gate_efficiency.py",  "LLM Gate Efficiency",                      True, 25),
]


def run_experiment(script: str, name: str, extra_args: list[str] = None) -> bool:
    """Run a single experiment script. Returns True on success."""
    script_path = EXPERIMENTS_DIR / script
    if not script_path.exists():
        print(f"  âŒ Script not found: {script_path}")
        return False

    cmd = [sys.executable, str(script_path)] + (extra_args or [])
    print(f"\n{'='*70}")
    print(f"  RUNNING: {name}")
    print(f"  Script:  {script}")
    print(f"  Time:    {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'='*70}\n")

    try:
        result = subprocess.run(
            cmd,
            cwd=str(EXPERIMENTS_DIR),
            timeout=7200,  # 2-hour timeout per experiment
        )
        if result.returncode == 0:
            print(f"\n  âœ… {name} â€” PASSED")
            return True
        else:
            print(f"\n  âŒ {name} â€” FAILED (exit code {result.returncode})")
            return False
    except subprocess.TimeoutExpired:
        print(f"\n  â° {name} â€” TIMED OUT")
        return False
    except Exception as e:
        print(f"\n  âŒ {name} â€” ERROR: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Master research experiment runner")
    parser.add_argument("--fast-only", action="store_true",
                        help="Only run experiments that don't need API calls")
    parser.add_argument("--experiment", type=int, nargs="+",
                        help="Run specific experiment(s) by number (1-7)")
    parser.add_argument("--max-samples", type=int, default=200,
                        help="Override max-samples for baseline/ablation experiments")
    args = parser.parse_args()

    print("\n" + "â–ˆ" * 70)
    print("â–ˆ  SEMANTIC FIREWALL â€” OFFICIAL RESEARCH EXPERIMENT SUITE")
    print("â–ˆ" * 70)
    print(f"\n  Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Determine which experiments to run
    if args.experiment:
        indices = [i - 1 for i in args.experiment if 1 <= i <= len(EXPERIMENTS)]
        selected = [(i, *EXPERIMENTS[i]) for i in indices]
    elif args.fast_only:
        selected = [(i, *exp) for i, exp in enumerate(EXPERIMENTS) if not exp[2]]
    else:
        selected = [(i, *exp) for i, exp in enumerate(EXPERIMENTS)]

    total_time_est = sum(exp[4] for exp in selected)
    print(f"  Experiments to run: {len(selected)}")
    print(f"  Estimated time:     ~{total_time_est} minutes\n")

    # Show plan
    print("  Plan:")
    for i, script, name, needs_api, est_min in selected:
        api_tag = "ðŸŒ API" if needs_api else "âš¡ Local"
        print(f"    {i+1}. [{api_tag}] {name} (~{est_min} min)")
    print()

    # Run experiments
    results = {}
    start_time = time.time()

    for i, script, name, needs_api, est_min in selected:
        extra_args = []
        if script in ("01_baseline_comparison.py", "02_ablation_study.py", "07_llm_gate_efficiency.py"):
            extra_args = ["--max-samples", str(args.max_samples)]

        success = run_experiment(script, name, extra_args)
        results[name] = "âœ… PASSED" if success else "âŒ FAILED"

    elapsed = time.time() - start_time

    # â”€â”€ Final Report â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    print("\n" + "â–ˆ" * 70)
    print("â–ˆ  EXPERIMENT SUITE COMPLETE")
    print("â–ˆ" * 70)
    print(f"\n  Total time: {elapsed/60:.1f} minutes\n")
    print("  Results:")
    for name, status in results.items():
        print(f"    {status}  {name}")

    print(f"\n  All outputs saved to: semantic_firewall/benchmarks/research/results/")
    print(f"  Paper tables at:      semantic_firewall/benchmarks/research/results/tables/")
    print()


if __name__ == "__main__":
    main()





