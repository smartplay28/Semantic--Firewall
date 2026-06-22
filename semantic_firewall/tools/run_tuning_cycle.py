import argparse
import subprocess
import sys


def run_step(cmd: list[str]):
    print(f"[tuning] running: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)


def main():
    parser = argparse.ArgumentParser(description="Run one full tuning cycle (datasets, benchmark, recommendations, history).")
    parser.add_argument("--dataset", default="data/datasets/golden_eval_set.jsonl")
    parser.add_argument("--policy-profiles", default="balanced,strict,developer_assistant,customer_support,research")
    parser.add_argument("--max-samples", type=int, default=80)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    py = sys.executable
    run_step([py, "semantic_firewall/benchmarks/extract_dataset_from_tests.py"])
    run_step([py, "semantic_firewall/benchmarks/build_golden_eval_set.py"])

    benchmark_cmd = [
        py,
        "semantic_firewall/benchmarks/run_market_benchmark.py",
        "--dataset",
        args.dataset,
        "--policy-profiles",
        args.policy_profiles,
        "--max-samples",
        str(args.max_samples),
    ]
    if args.quiet:
        benchmark_cmd.append("--quiet")
    run_step(benchmark_cmd)

    run_step(
        [
            py,
            "semantic_firewall/tools/suggest_threshold_tuning.py",
            "--db-path",
            "data/var/audit.db",
            "--output",
            "data/results/threshold_tuning_recommendations.json",
        ]
    )
    run_step([py, "semantic_firewall/tools/suggest_calibration_from_benchmark.py", "--results", "data/results/benchmark_results.json"])
    run_step([py, "semantic_firewall/tools/suggest_ensemble_from_benchmark.py", "--results", "data/results/benchmark_results.json"])
    run_step([py, "semantic_firewall/tools/append_benchmark_history.py", "--results", "data/results/benchmark_results.json", "--history", "data/results/benchmark_history.jsonl"])

    print("[tuning] cycle complete.")


if __name__ == "__main__":
    main()


