"""Which component detects each multi-turn session, computed exactly from one multiturn_eval run.

For every turn the run records the decision before the Session Judge (policy_action and ensemble_risk) and the
components that raised the final decision (triggered_agents). Three nested systems are evaluated on the same sessions:
  per_turn        the per-turn pipeline only (no Session Judge): policy action != ALLOW or ensemble risk >= flag band
  judge_no_memory per-turn pipeline + Session Judge without the conversation memory
  full            everything (the run as recorded)
McNemar tests (continuity-corrected; exact binomial below 25 discordant sessions) compare consecutive systems.

  python multiturn_breakdown.py --run multiturn-heldout-full_all_unresolved-warm_frozen-final-memory
"""

import argparse
import json
from collections import Counter
from math import comb, erfc, sqrt

from common import OUT_ROOT, run_metadata, write_json

FLAG_BAND = 1.8  # ensemble FLAG threshold (SEMANTIC_FIREWALL_ENSEMBLE_FLAG_THRESHOLD)
MEMORY = "Conversation Memory"


def per_turn_flag(t):
    return (t.get("policy_action") not in (None, "ALLOW")) or (t.get("ensemble_risk") or 0.0) >= FLAG_BAND


def no_memory_flag(t):
    others = [a for a in t["triggered_agents"] if a != MEMORY]
    return per_turn_flag(t) or (t["pred"] == 1 and (others or MEMORY not in t["triggered_agents"]))


def mcnemar(a, b, labels):
    ok_a = [x == y for x, y in zip(a, labels)]
    ok_b = [x == y for x, y in zip(b, labels)]
    n01 = sum(1 for p, q in zip(ok_a, ok_b) if not p and q)
    n10 = sum(1 for p, q in zip(ok_a, ok_b) if p and not q)
    n = n01 + n10
    if n == 0:
        return {"b_only_correct": n01, "a_only_correct": n10, "p": 1.0}
    if n < 25:
        k = min(n01, n10)
        p = min(1.0, 2 * sum(comb(n, i) for i in range(k + 1)) / 2 ** n)
        return {"b_only_correct": n01, "a_only_correct": n10, "p": p, "test": "exact binomial"}
    chi2 = (abs(n01 - n10) - 1) ** 2 / n
    return {"b_only_correct": n01, "a_only_correct": n10, "chi2": chi2, "p": erfc(sqrt(chi2 / 2)),
            "test": "chi-square, continuity-corrected"}


def rates(detected, labels):
    tp = sum(d and l for d, l in zip(detected, labels))
    fp = sum(d and not l for d, l in zip(detected, labels))
    pos, neg = sum(labels), len(labels) - sum(labels)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / pos
    return {"recall": rec, "fpr": fp / neg, "precision": prec,
            "f1": 2 * prec * rec / (prec + rec) if prec + rec else 0.0, "tp": tp, "fp": fp}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run", required=True)
    args = parser.parse_args()
    run_dir = OUT_ROOT / "multiturn" / args.run
    sessions = [json.loads(l) for l in open(run_dir / "sessions.jsonl", encoding="utf-8")]
    labels = [s["label"] for s in sessions]
    systems = {
        "per_turn": [any(per_turn_flag(t) for t in s["turns"]) for s in sessions],
        "judge_no_memory": [any(no_memory_flag(t) for t in s["turns"]) for s in sessions],
        "full": [s["detected"] for s in sessions],
    }
    out = {"run": args.run, "n_sessions": len(sessions), "systems": {k: rates(v, labels) for k, v in systems.items()},
           "mcnemar": {"judge_no_memory_vs_per_turn": mcnemar(systems["per_turn"], systems["judge_no_memory"], labels),
                       "full_vs_judge_no_memory": mcnemar(systems["judge_no_memory"], systems["full"], labels),
                       "full_vs_per_turn": mcnemar(systems["per_turn"], systems["full"], labels)},
           "first_detection_agent_attacks": dict(Counter(a for s in sessions if s["label"] and s["detected"]
                                                         for a in s["first_detection_agents"])),
           "first_detection_agent_benign": dict(Counter(a for s in sessions if not s["label"] and s["detected"]
                                                        for a in s["first_detection_agents"])),
           "meta": run_metadata()}
    write_json(run_dir / "breakdown.json", out)
    for k, v in out["systems"].items():
        print(f"{k:16} recall {100*v['recall']:5.1f}  FPR {100*v['fpr']:4.1f}  P {100*v['precision']:5.1f}  F1 {100*v['f1']:5.1f}")
    for k, v in out["mcnemar"].items():
        print(k, v)
    print("first detection (attacks):", out["first_detection_agent_attacks"])
    print("first detection (benign):", out["first_detection_agent_benign"])


if __name__ == "__main__":
    main()
