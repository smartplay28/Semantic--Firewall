"""
Pilot benchmark runner for the fixed 50-sample local dataset.

Usage:
  python semantic_firewall/benchmarks/research/run_pilot_benchmark.py
  python semantic_firewall/benchmarks/research/run_pilot_benchmark.py --skip-ablation
"""
import argparse
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]
EXPERIMENTS_DIR = Path(__file__).resolve().parent / "experiments"
PILOT_DATASET = PROJECT_ROOT / "data" / "datasets" / "firewall_benchmark_pilot_50.jsonl"


def run_step(label: str, args: list[str]) -> int:
    print("\n" + "=" * 70)
    print(f"  {label}")
    print("=" * 70)
    print("  Command:", " ".join(args))
    print()
    completed = subprocess.run(args, cwd=str(EXPERIMENTS_DIR), check=False)
    return completed.returncode


def main():
    parser = argparse.ArgumentParser(description="Run pilot benchmark on local 50-sample dataset")
    parser.add_argument("--skip-ablation", action="store_true", help="Only run the baseline comparison")
    parser.add_argument("--include-llm-only", action="store_true", help="Include the LLM-only baseline")
    parser.add_argument("--sleep", type=float, default=0.0, help="Sleep between LLM-backed samples")
    args = parser.parse_args()

    dataset_arg = str(PILOT_DATASET)

    baseline_cmd = [
        sys.executable,
        str(EXPERIMENTS_DIR / "01_baseline_comparison.py"),
        "--dataset-jsonl",
        dataset_arg,
        "--max-samples",
        "50",
        "--sleep",
        str(args.sleep),
    ]
    if not args.include_llm_only:
        baseline_cmd.append("--skip-llm-only")

    exit_code = run_step("Pilot Baseline Comparison", baseline_cmd)
    if exit_code != 0:
        raise SystemExit(exit_code)

    if not args.skip_ablation:
        ablation_cmd = [
            sys.executable,
            str(EXPERIMENTS_DIR / "02_ablation_study.py"),
            "--dataset-jsonl",
            dataset_arg,
            "--max-samples",
            "50",
            "--sleep",
            str(args.sleep),
        ]
        exit_code = run_step("Pilot Ablation Study", ablation_cmd)
        if exit_code != 0:
            raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
