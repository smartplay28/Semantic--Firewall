"""Per-detector ablation on MIXED-1000 (Table 6): each detector removed in turn, as on neuralchemy.

The LLM-assisted detectors are removed from the full system (C8), the deterministic ones from the fast layers (C7);
all runs use the warm cache (derived exactly, derive_warm_mixed.py). For each detector the table gives F1, FPR and the
number of changed decisions, plus how many prompts the detector flags in the reference run (attacks / benign) and its
recall on each threat type of the set.

  python table6_mixed.py
Output: results_camera_ready/mixed/table6_mixed.json (+ printed table)
"""

import json
from collections import Counter

from common import OUT_ROOT, RUNS_DIR, load_samples, read_jsonl, write_json

TAU = "0.65"
LLM = ["Injection Detector", "Unsafe Content Detector"]
DET = ["Abuse Detector", "PII Detector", "Secrets Detector", "Threat Intel Detector", "Custom Rules Detector",
       "Context Flooding Detector"]
THREATS = ["injection", "pii", "secret", "flooding", "threat_intel", "custom_rule"]


def recs(name):
    path = RUNS_DIR / name / "predictions.jsonl"
    r = read_jsonl(path)
    if len(r) != 1000:
        raise SystemExit(f"{name}: {len(r)} records (expected 1000)")
    return {x["id"]: x for x in r}


def metrics(rs):
    tp = sum(r["label"] == 1 and r["pred"] == 1 for r in rs)
    fp = sum(r["label"] == 0 and r["pred"] == 1 for r in rs)
    fn = sum(r["label"] == 1 and r["pred"] == 0 for r in rs)
    tn = len(rs) - tp - fp - fn
    p, rc = tp / (tp + fp), tp / (tp + fn)
    return {"f1": 100 * 2 * p * rc / (p + rc), "fpr": 100 * fp / (fp + tn), "recall": 100 * rc, "precision": 100 * p}


def main():
    samples = {s["id"]: s for s in load_samples("mixed", "all")}
    warm = lambda base: recs(f"mixed-all-{base}-warm_frozen-tau{TAU}")
    none = lambda base: recs(f"mixed-all-{base}-none")
    c8, c7 = warm("full_all_unresolved"), warm("fast_layers")
    c8n, c7n = none("full_all_unresolved"), none("fast_layers")

    def per_threat_recall(rs):
        out = {}
        for t in THREATS:
            ids = [i for i, s in samples.items() if t in s["threats"]]
            out[t] = round(100 * sum(rs[i]["pred"] for i in ids) / len(ids), 1)
        return out

    rows = [{"removed": "none", "reference": "C8", **{k: round(v, 2) for k, v in metrics(list(c8.values())).items()},
             "changed": None, "per_threat_recall": per_threat_recall(c8)}]
    for det, ref, ref_none, base in [(d, c8, c8n, "loo_" + d.replace(" ", "_")) for d in LLM] + \
                                    [("none (fast layers)", c7, c7n, None)] + \
                                    [(d, c7, c7n, "loo_fast_" + d.replace(" ", "_")) for d in DET]:
        if base is None:
            rows.append({"removed": "none", "reference": "C7",
                         **{k: round(v, 2) for k, v in metrics(list(c7.values())).items()}, "changed": None,
                         "per_threat_recall": per_threat_recall(c7)})
            continue
        run = warm(base)
        flags = Counter(samples[i]["label"] for i, r in ref_none.items() if det in r["triggered_agents"])
        caught = {t: sum(det in ref_none[i]["triggered_agents"] for i, s in samples.items() if t in s["threats"])
                  for t in THREATS}
        rows.append({"removed": det, "reference": "C8" if det in LLM else "C7",
                     **{k: round(v, 2) for k, v in metrics(list(run.values())).items()},
                     "changed": sum(run[i]["pred"] != ref[i]["pred"] for i in ref),
                     "flags_attacks": flags.get(1, 0), "flags_benign": flags.get(0, 0),
                     "flags_by_threat": caught, "per_threat_recall": per_threat_recall(run)})

    out = {"dataset": "data/datasets/mixed_coverage_1000.jsonl", "tau": float(TAU), "rows": rows,
           "threat_counts": {t: sum(t in s["threats"] for s in samples.values()) for t in THREATS},
           "n": len(samples), "n_label_1": sum(s["label"] for s in samples.values())}
    write_json(OUT_ROOT / "mixed" / "table6_mixed.json", out)
    print(f"{'removed':28s}{'ref':5s}{'F1':>7s}{'FPR':>7s}{'chg':>5s}{'flags a/b':>11s}  per-threat recall")
    for r in rows:
        fl = f"{r.get('flags_attacks', '')}/{r.get('flags_benign', '')}" if "flags_attacks" in r else ""
        print(f"{r['removed']:28s}{r['reference']:5s}{r['f1']:7.2f}{r['fpr']:7.2f}{str(r['changed'] or '-'):>5s}{fl:>11s}  "
              + " ".join(f"{t}:{v}" for t, v in r["per_threat_recall"].items()))
    print("threat counts:", out["threat_counts"])


if __name__ == "__main__":
    main()
