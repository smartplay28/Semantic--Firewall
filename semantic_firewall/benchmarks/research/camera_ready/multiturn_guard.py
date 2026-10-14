"""Llama Guard 4 as a multi-turn judge, on the same sessions as multiturn_eval.py.

After every turn the guard sees all user turns so far, either joined into one message ("joined") or as
consecutive user messages ("messages"). A session is detected when any prefix is classified "unsafe",
mirroring how the firewall's Session Judge is evaluated.

  python multiturn_guard.py --part dev
Output: results_camera_ready/multiturn/guard-<part>-<model>-<format>/{sessions.jsonl, summary.json}
"""

import argparse
import json
from collections import Counter

from common import OUT_ROOT, run_metadata, write_json
from multiturn_eval import load_split
from run_baselines import call_with_retry, openrouter_client


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--part", choices=["dev", "heldout"], required=True)
    parser.add_argument("--model", default="meta-llama/llama-guard-4-12b")
    parser.add_argument("--format", choices=["joined", "messages"], default="joined")
    args = parser.parse_args()

    sessions, split = load_split()
    sessions = [s for s in sessions if split[s["id"]] == args.part]
    client = openrouter_client()

    def unsafe(turns):
        if args.format == "joined":
            msgs = [{"role": "user", "content": "\n".join(f"[Turn {i}] {t}" for i, t in enumerate(turns, 1))}]
        else:
            msgs = [{"role": "user", "content": t} for t in turns]
        resp = call_with_retry(lambda: client.chat.completions.create(model=args.model, temperature=0.0, messages=msgs))
        raw = (resp.choices[0].message.content or "").strip()
        return raw.lower().startswith("unsafe"), raw[:60]

    name = f"guard-{args.part}-{args.model.split('/')[-1]}-{args.format}"
    out_dir = OUT_ROOT / "multiturn" / name
    out_dir.mkdir(parents=True, exist_ok=True)
    records = []
    with (out_dir / "sessions.jsonl").open("w", encoding="utf-8") as fh:
        for n, s in enumerate(sessions, 1):
            first, raws, err = None, [], None
            try:
                for t in range(1, len(s["turns"]) + 1):
                    flag, raw = unsafe(s["turns"][:t])
                    raws.append(raw)
                    if flag:
                        first = t
                        break
            except Exception as exc:  # recorded, never counted silently
                err = str(exc)[:200]
            r = {"id": s["id"], "label": s["label"], "category": s["category"], "detected": first is not None,
                 "first_detection_turn": first, "raw": raws, "error": err}
            records.append(r)
            fh.write(json.dumps(r) + "\n")
            fh.flush()
            if n % 20 == 0:
                print(f"  {n}/{len(sessions)}")

    att = [r for r in records if r["label"] == 1]
    ben = [r for r in records if r["label"] == 0]
    tp, fp = sum(r["detected"] for r in att), sum(r["detected"] for r in ben)
    rec, fpr = tp / len(att), fp / len(ben)
    prec = tp / (tp + fp) if tp + fp else 0.0
    summary = {"part": args.part, "model": args.model, "format": args.format, "sessions_attack": len(att),
               "sessions_benign": len(ben), "tp": tp, "fp": fp, "session_recall": rec, "session_fpr": fpr,
               "precision": prec, "f1": 2 * prec * rec / (prec + rec) if prec + rec else 0.0,
               "errors": sum(1 for r in records if r["error"]),
               "detected_by_category": dict(Counter(r["category"] for r in att if r["detected"])),
               "attacks_by_category": dict(Counter(r["category"] for r in att)), "meta": run_metadata()}
    write_json(out_dir / "summary.json", summary)
    print({k: (round(v, 4) if isinstance(v, float) else v) for k, v in summary.items() if k != "meta"})


if __name__ == "__main__":
    main()
