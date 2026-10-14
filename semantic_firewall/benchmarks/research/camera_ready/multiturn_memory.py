"""Conversation memory for the Session Judge: seeds and threshold selection.

Seeds are ActorAttack conversations (user turns only) that are NOT part of the multi-turn evaluation:
  - SafeMTData_1K (1,680 multi-turn conversations released for safety training), and
  - Attack_600 sessions whose harmful query is in neither the dev nor the held-out part.
Every seed whose harmful goal (`plain_query`) has cosine similarity >= --dedup to the goal of any dev or held-out
session is removed. Each seed contributes its prefixes of 2..n turns, in the same "[Turn i] ..." format the Session
Judge uses, so a conversation can be matched while it is still unfolding.

  python multiturn_memory.py tune --run multiturn-dev-full_all_unresolved-warm_frozen-e2-fullwindow-goal
      exact offline sweep on the dev part: detection = pipeline detection OR max similarity of some prefix (t >= 2)
      to the memory >= tau; tau is selected by the highest dev F1 (ties: larger tau). Writes
      results_camera_ready/multiturn/memory_tuning.json
"""

import argparse
import ast
import json

import numpy as np

from common import OUT_ROOT, run_metadata, write_json

GOAL_DEDUP = 0.80
TAUS = [0.55, 0.58, 0.60, 0.62, 0.65, 0.70, 0.75, 0.80]


def _embed(texts):
    from semantic_firewall.core.orchestrator.semantic_cache import shared_embedder

    emb = shared_embedder()
    out = []
    for i in range(0, len(texts), 64):
        out.extend(emb(texts[i:i + 64]))
    m = np.asarray(out, dtype=np.float32)
    return m / np.linalg.norm(m, axis=1, keepdims=True)


def joined(turns):
    return "\n".join(f"[Turn {i}] {t}" for i, t in enumerate(turns, 1))


def memory_seeds(dedup: float = GOAL_DEDUP):
    """(seed prefix texts, info). Never contains a dev/held-out query or a near-duplicate of its goal."""
    from datasets import load_dataset
    from multiturn_eval import load_split

    sessions, _ = load_split()
    eval_qid = {s["query_id"] for s in sessions if s["label"] == 1}
    a600 = load_dataset("SafeMTData/SafeMTData", "Attack_600")["Attack_600"]
    k1 = load_dataset("SafeMTData/SafeMTData", "SafeMTData_1K")["SafeMTData_1K"]
    eval_goals = sorted({r["plain_query"] for r in a600 if r["query_id"] in eval_qid})

    seeds = [(r["plain_query"], [t for t in r["multi_turn_queries"] if t and t.strip()])
             for r in a600 if r["query_id"] not in eval_qid]
    for r in k1:
        conv = ast.literal_eval(r["conversations"]) if isinstance(r["conversations"], str) else r["conversations"]
        seeds.append((r["plain_query"], [m["content"] for m in conv if m["role"] == "user" and m["content"].strip()]))
    n_before = len(seeds)
    goals = sorted({g for g, _ in seeds})
    max_sim = (_embed(goals) @ _embed(eval_goals).T).max(axis=1)
    banned = {g for g, s in zip(goals, max_sim) if s >= dedup}
    seeds = [(g, t) for g, t in seeds if g not in banned]
    texts = list(dict.fromkeys(joined(t[:k]) for _, t in seeds for k in range(2, len(t) + 1)))
    info = {"seed_conversations_before_dedup": n_before, "goals_removed": len(banned), "goal_dedup_cosine": dedup,
            "seed_conversations": len(seeds), "seed_prefixes": len(texts),
            "sources": ["SafeMTData/SafeMTData:SafeMTData_1K", "SafeMTData/SafeMTData:Attack_600 (non-eval queries)"]}
    return texts, info


def tune(run: str, dedup: float):
    from multiturn_eval import load_split

    texts, info = memory_seeds(dedup)
    S = _embed(texts)
    sessions, split = load_split()
    by_id = {s["id"]: s for s in sessions}
    recs = [json.loads(l) for l in open(OUT_ROOT / "multiturn" / run / "sessions.jsonl", encoding="utf-8")]
    if any(split[r["id"]] != "dev" for r in recs):
        raise SystemExit("tuning must use a dev run")
    rows = []
    for r in recs:
        turns = by_id[r["id"]]["turns"]
        sims = (_embed([joined(turns[:k]) for k in range(2, len(turns) + 1)]) @ S.T).max(axis=1)
        rows.append({"id": r["id"], "label": r["label"], "pipeline_detected": r["detected"], "max_sim": float(sims.max())})
    table = []
    for tau in TAUS:
        tp = sum(1 for x in rows if x["label"] and (x["pipeline_detected"] or x["max_sim"] >= tau))
        fp = sum(1 for x in rows if not x["label"] and (x["pipeline_detected"] or x["max_sim"] >= tau))
        pos, neg = sum(x["label"] for x in rows), sum(1 - x["label"] for x in rows)
        p = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / pos
        table.append({"tau": tau, "recall": rec, "fpr": fp / neg, "precision": p,
                      "f1": 2 * p * rec / (p + rec) if p + rec else 0.0, "tp": tp, "fp": fp})
    best = max(table, key=lambda t: (round(t["f1"], 10), t["tau"]))
    base_tp = sum(1 for x in rows if x["label"] and x["pipeline_detected"])
    base_fp = sum(1 for x in rows if not x["label"] and x["pipeline_detected"])
    out = {"dev_run": run, "seeds": info, "pipeline_only": {"tp": base_tp, "fp": base_fp},
           "sweep": table, "selected_tau": best["tau"], "selection_rule": "highest dev F1; ties -> larger tau",
           "attack_max_sim": sorted(x["max_sim"] for x in rows if x["label"]),
           "benign_max_sim": sorted(x["max_sim"] for x in rows if not x["label"]), "meta": run_metadata()}
    write_json(OUT_ROOT / "multiturn" / "memory_tuning.json", out)
    print("seeds:", info)
    print(f"pipeline only: recall {base_tp}/{sum(x['label'] for x in rows)}, benign flagged {base_fp}")
    for t in table:
        print(f"  tau {t['tau']:.2f}: recall {t['recall']:.3f} FPR {t['fpr']:.3f} F1 {t['f1']:.3f} (tp {t['tp']}, fp {t['fp']})")
    print("selected tau:", best["tau"])


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["tune"])
    parser.add_argument("--run", required=True)
    parser.add_argument("--dedup", type=float, default=GOAL_DEDUP)
    args = parser.parse_args()
    tune(args.run, args.dedup)


if __name__ == "__main__":
    main()
