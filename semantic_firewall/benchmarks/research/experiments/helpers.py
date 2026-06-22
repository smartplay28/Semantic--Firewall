"""
Shared utilities for all research experiment scripts.
"""
import csv
import json
import sys
import os
import time
from pathlib import Path
from datetime import datetime, timezone

# Repo root: .../semantic_firewall
PROJECT_ROOT = Path(__file__).resolve().parents[4]
PACKAGE_ROOT = PROJECT_ROOT / "semantic_firewall"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# All results go into semantic_firewall/benchmarks/research/results/
RESULTS_ROOT = PACKAGE_ROOT / "benchmarks" / "research" / "results"
TABLES_DIR = RESULTS_ROOT / "tables"
FIGURES_DIR = RESULTS_ROOT / "figures"

# Standard sub-directories
for _d in [
    RESULTS_ROOT, TABLES_DIR, FIGURES_DIR,
    RESULTS_ROOT / "baselines",
    RESULTS_ROOT / "ablation",
    RESULTS_ROOT / "latency",
    RESULTS_ROOT / "pii",
    RESULTS_ROOT / "unsafe",
    RESULTS_ROOT / "red_team",
    RESULTS_ROOT / "llm_gate",
]:
    _d.mkdir(parents=True, exist_ok=True)


def safe_div(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def compute_metrics(tp: int, fp: int, tn: int, fn: int) -> dict:
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    f1 = safe_div(2 * precision * recall, precision + recall)
    accuracy = safe_div(tp + tn, tp + tn + fp + fn)
    fpr = safe_div(fp, fp + tn)
    fnr = safe_div(fn, fn + tp)
    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
    }


def format_pct(value: float) -> str:
    return f"{value * 100:5.1f}%"


def write_csv_rows(path: Path, header: list, rows: list[list]) -> None:
    """Write a simple CSV file."""
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)
    print(f"  â†’ Saved: {path}")


def write_json(path: Path, data) -> None:
    """Write JSON output."""
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    print(f"  â†’ Saved: {path}")


def normalize_binary_label(value) -> int:
    """Normalize common label formats into {0,1}."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return 1 if value != 0 else 0
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "threat", "attack", "malicious", "unsafe"}:
            return 1
        if normalized in {"0", "false", "clean", "benign", "safe"}:
            return 0
    raise ValueError(f"Unsupported label format: {value!r}")


def load_local_jsonl_dataset(path: Path) -> list[dict]:
    """Load a local JSONL benchmark file into a list of dict rows."""
    rows: list[dict] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def experiment_metadata() -> dict:
    """Standard metadata block to include in every result file."""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "python_version": sys.version,
        "cwd": os.getcwd(),
    }


def rate_limit_sleep(seconds: float = 3.5) -> None:
    """Sleep to avoid Groq API rate limits."""
    time.sleep(seconds)


def print_header(title: str) -> None:
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70 + "\n")


def print_section(title: str) -> None:
    print("\n" + "-" * 50)
    print(f"  {title}")
    print("-" * 50)





