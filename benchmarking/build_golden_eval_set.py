import argparse
import json
import random
from pathlib import Path


def read_jsonl(path: Path) -> list[dict]:
    rows = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path, rows: list[dict]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=True) + "\n")


def build_balanced_set(rows: list[dict], per_bucket: int, seed: int) -> list[dict]:
    grouped: dict[tuple[str, str], list[dict]] = {}
    for row in rows:
        category = row.get("category", "unknown")
        label = row.get("label", "clean")
        grouped.setdefault((category, label), []).append(dict(row))

    random.seed(seed)
    selected: list[dict] = []
    for key, bucket in sorted(grouped.items()):
        random.shuffle(bucket)
        selected.extend(bucket[:per_bucket])

    for idx, row in enumerate(selected, start=1):
        row["golden_id"] = f"golden-{idx:04d}"
        row["source"] = row.get("source", "tests")
    return selected


def main():
    parser = argparse.ArgumentParser(description="Build balanced golden evaluation set.")
    parser.add_argument("--input", default="datasets/benchmark_from_tests.jsonl")
    parser.add_argument("--canary", default="datasets/canary_prompts.jsonl")
    parser.add_argument("--output", default="datasets/golden_eval_set.jsonl")
    parser.add_argument("--per-bucket", type=int, default=12)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    base_rows = read_jsonl(Path(args.input))
    if not base_rows:
        raise RuntimeError("Input dataset is empty. Run extract_dataset_from_tests.py first.")

    golden_rows = build_balanced_set(base_rows, per_bucket=args.per_bucket, seed=args.seed)
    canary_rows = read_jsonl(Path(args.canary))
    for idx, row in enumerate(canary_rows, start=1):
        enriched = dict(row)
        enriched["golden_id"] = f"canary-{idx:04d}"
        enriched["source"] = "canary"
        golden_rows.append(enriched)

    write_jsonl(Path(args.output), golden_rows)
    print(f"Saved {len(golden_rows)} rows to {args.output}")


if __name__ == "__main__":
    main()

