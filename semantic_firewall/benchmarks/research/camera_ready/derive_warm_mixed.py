"""Warm-cache versions of the MIXED-1000 runs, derived exactly as derive_warm.py does (Eq. 9):
pred_warm = 1 if cosine(prompt, nearest train-split attack) >= tau else the no-cache prediction.

The similarities are computed once for all runs from MiniLM embeddings (the same embedder as the cache; embeddings
are stored in _work/), by exact cosine against the 2,650 train-split attacks.

  python derive_warm_mixed.py            # every runs/mixed-all-*-none run
"""

import argparse
import json

import numpy as np

from cache_safeguards_replay import load_or_embed
from common import RUNS_DIR, load_samples, read_jsonl, run_metadata, summarize, train_attack_texts, write_json


class _Ids:
    @staticmethod
    def _generate_id(text):
        import hashlib
        return hashlib.md5(text.encode("utf-8")).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--tau", type=float, default=0.65)
    args = parser.parse_args()

    samples = {s["id"]: s for s in load_samples("mixed", "all")}
    seeds = train_attack_texts()
    vec = load_or_embed(_Ids(), list(dict.fromkeys([s["text"] for s in samples.values()] + seeds)))
    unit = lambda texts: (lambda m: m / np.linalg.norm(m, axis=1, keepdims=True))(
        np.asarray([vec[t] for t in texts], dtype=np.float32))
    seed_m = unit(seeds)
    ids = list(samples)
    sims = dict(zip(ids, (unit([samples[i]["text"] for i in ids]) @ seed_m.T).max(axis=1).tolist()))

    for src in sorted(p.name for p in RUNS_DIR.glob("mixed-all-*-none")):
        recs = read_jsonl(RUNS_DIR / src / "predictions.jsonl")
        derived = []
        for r in recs:
            d = dict(r)
            d["semantic_similarity"] = round(sims[r["id"]], 4)
            d["cache_hit"] = sims[r["id"]] >= args.tau
            if d["cache_hit"]:
                d["pred"] = 1
            derived.append(d)
        name = f"{src.removesuffix('-none')}-warm_frozen-tau{args.tau}"
        out = RUNS_DIR / name
        out.mkdir(parents=True, exist_ok=True)
        with open(out / "predictions.jsonl", "w", encoding="utf-8", newline="\n") as fh:
            for d in derived:
                fh.write(json.dumps(d, ensure_ascii=False) + "\n")
        summary = summarize(derived, with_ci=False)
        summary.update({"derived_from": src, "tau": args.tau,
                        "rule": "pred = 1 if cosine(prompt, nearest train attack) >= tau else no-cache pred",
                        "meta": run_metadata()})
        write_json(out / "summary.json", summary)
        print(f"{name}: F1 {summary['f1']:.4f} FPR {summary['fpr']:.4f} cache hits {sum(d['cache_hit'] for d in derived)}")


if __name__ == "__main__":
    main()
