import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def append_history(results: dict, history_path: Path):
    history_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "dataset": results.get("dataset"),
        "sample_count": results.get("sample_count"),
        "tools": [],
    }
    for tool in results.get("tools", []):
        if tool.get("status") != "ok":
            continue
        payload["tools"].append(
            {
                "tool": tool.get("tool"),
                "precision": tool.get("metrics", {}).get("precision"),
                "recall": tool.get("metrics", {}).get("recall"),
                "f1_score": tool.get("metrics", {}).get("f1_score"),
                "p95_latency_ms": tool.get("latency_ms", {}).get("p95"),
                "timeout_rate": tool.get("latency_ms", {}).get("timeout_rate", 0.0),
                "degraded_rate": tool.get("degraded_rate", 0.0),
            }
        )

    with history_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=True) + "\n")
    print(f"Appended benchmark history to {history_path}")


def main():
    parser = argparse.ArgumentParser(description="Append benchmark metrics snapshot to history JSONL.")
    parser.add_argument("--results", default="results/benchmark_results.json")
    parser.add_argument("--history", default="results/benchmark_history.jsonl")
    args = parser.parse_args()

    results_path = Path(args.results)
    if not results_path.exists():
        raise FileNotFoundError(f"Missing benchmark results file: {results_path}")
    append_history(read_json(results_path), Path(args.history))


if __name__ == "__main__":
    main()

