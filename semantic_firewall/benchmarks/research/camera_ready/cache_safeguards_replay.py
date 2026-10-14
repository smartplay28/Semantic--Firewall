"""Cost of the cache write-back safeguards on normal traffic (no attacker), by exact replay.

The pipeline's verdict on a cache miss does not depend on the cache, so a run with online write-back can be
replayed exactly from one run without a cache (writeback_verdicts.py): a prompt that hits the cache is blocked
(all 151 hits of the cold run C9 were BLOCK), and a prompt that misses gets its recorded verdict and, when that
verdict is write-back eligible, is written to the cache. The replay uses the real SemanticCache, with each
safeguard switched on through its constructor arguments.

Stream: the neuralchemy test split, in dataset order and in 4 random orders. Held-out: after the stream, the
cache is frozen (no write-back, no re-validation, no further expiry) and the validation split is evaluated.
Start: "warm" (seeded with the 2,650 train attacks, the deployed configuration) or "cold" (empty, as in C9).
Benign reference set: train-split benign prompts (disjoint from test and validation).

  python cache_safeguards_replay.py
Output: results_camera_ready/cache_safeguards/replay.json (+ a printed summary)
"""

import argparse
import random
import statistics
import time

from common import OUT_ROOT, WORK_DIR, load_samples, quiet_stdout, read_jsonl, run_metadata, write_json

OUT = OUT_ROOT / "cache_safeguards"
TAU = 0.65
ORDERS = ["dataset", 1, 2, 3, 4]


def configs():
    """name -> SemanticCache keyword arguments (+ "ref": size of the benign reference set)."""
    c = {"frozen": {"writeback": False}, "writeback": {}}
    for n in (100, 500, "all"):
        c[f"overlap-ref{n}"] = {"overlap_check": True, "ref": n}
    for d in (0.03, 0.05, 0.10):
        c[f"probation-tau{TAU + d:.2f}"] = {"probation_threshold": round(TAU + d, 2)}
    for t in (100, 250, 500):
        c[f"ttl{t}"] = {"ttl_requests": t}
    for r in (0.01, 0.05, 0.10):
        c[f"revalidate{int(r * 100)}"] = {"revalidate_rate": r}
    c["all-four"] = {"overlap_check": True, "ref": "all", "probation_threshold": 0.70, "ttl_requests": 250,
                     "revalidate_rate": 0.05}
    return c


def load_verdicts(split):
    recs = {r["id"]: r for r in read_jsonl(OUT / f"verdicts_neuralchemy-{split}.jsonl")}
    samples = load_samples("neuralchemy", split)
    missing = [s["id"] for s in samples if s["id"] not in recs]
    if missing:
        raise SystemExit(f"{len(missing)} {split} prompts have no recorded verdict; finish writeback_verdicts.py first")
    errors = sum(1 for r in recs.values() if r.get("error"))
    if errors:
        print(f"  warning: {errors} {split} verdicts are errors (pred 0, not eligible)")
    return [{**s, **{k: recs[s["id"]][k] for k in ("pred", "llm_called", "writeback_eligible", "max_llm_confidence")}}
            for s in samples]


def rate(a, b):
    return a / b if b else 0.0


def confusion_metrics(rows):
    tp = sum(1 for r in rows if r["label"] == 1 and r["served"] == 1)
    fp = sum(1 for r in rows if r["label"] == 0 and r["served"] == 1)
    fn = sum(1 for r in rows if r["label"] == 1 and r["served"] == 0)
    tn = len(rows) - tp - fp - fn
    p, rc = rate(tp, tp + fp), rate(tp, tp + fn)
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "recall": rc, "fpr": rate(fp, fp + tn), "precision": p,
            "f1": rate(2 * p * rc, p + rc)}


def replay(cache, stream, heldout, seeds, reference, kwargs, order, vec):
    from semantic_firewall.core.orchestrator.semantic_cache import TRUSTED

    cache.reset()
    cache.writeback = kwargs.get("writeback", True)
    cache.overlap_check = kwargs.get("overlap_check", False)
    cache.probation_threshold = kwargs.get("probation_threshold")
    cache.promote_after = kwargs.get("promote_after", 2)
    cache.ttl_requests = kwargs.get("ttl_requests", 0)
    cache.revalidate_rate = kwargs.get("revalidate_rate", 0.0)
    cache._rng = random.Random(0 if order == "dataset" else order)
    if seeds:
        cache.seed_threats(seeds, origin="train_seed", embeddings=[vec[t] for t in seeds])
    if cache.overlap_check:
        ref = reference if kwargs["ref"] == "all" else random.Random(0).sample(reference, kwargs["ref"])
        cache.add_benign_reference(ref, embeddings=[vec[t] for t in ref])

    rows = list(stream)
    if order != "dataset":
        random.Random(order).shuffle(rows)
    label_of = {cache._generate_id(r["text"]): r["label"] for r in rows}
    ev = {k: 0 for k in ("hits_seed", "hits_online", "gate_calls", "revalidations", "fp_from_seed",
                         "fp_from_online_benign_entry", "fp_from_online_attack_entry", "attacks_only_cache_caught",
                         "attacks_lost_to_revalidation", "candidates_attack", "candidates_benign",
                         "rejected_overlap_attack", "rejected_overlap_benign", "written_attack", "written_benign",
                         "evicted_attack_entry", "evicted_benign_entry",
                         "variants", "variants_cache_blocked", "variants_served_blocked")}
    written = set()
    served_rows = []
    for r in rows:
        v = vec[r["text"]]
        _, hit = cache.lookup_threat(r["text"], embedding=v)
        # a variant of a cached attack: an attack within tau of a live entry written online from an attack
        variant = r["label"] == 1 and any(
            n["metadata"].get("online") and label_of.get(n["id"]) == 1 and n["similarity_score"] >= TAU
            for n in cache._neighbours(cache.collection, v, k=10))
        ev["variants"] += variant
        ev["variants_cache_blocked"] += variant and hit is not None
        if hit and not cache.should_revalidate(hit):
            served = 1
            if hit["online"]:
                ev["hits_online"] += 1
                if r["label"] == 0 and r["pred"] == 0:
                    ev["fp_from_online_benign_entry" if label_of.get(hit["id"]) == 0 else "fp_from_online_attack_entry"] += 1
            else:
                ev["hits_seed"] += 1
                if r["label"] == 0 and r["pred"] == 0:
                    ev["fp_from_seed"] += 1
            if r["label"] == 1 and r["pred"] == 0:
                ev["attacks_only_cache_caught"] += 1
        else:
            served = r["pred"]
            ev["gate_calls"] += int(r["llm_called"])
            if hit:  # sampled for re-validation: the pipeline's verdict is served
                ev["revalidations"] += 1
                if r["label"] == 1 and r["pred"] == 0:
                    ev["attacks_lost_to_revalidation"] += 1
                if r["pred"] == 0 and cache.evict(hit["id"]):
                    ev["evicted_attack_entry" if label_of.get(hit["id"]) == 1 else "evicted_benign_entry"] += 1
            if r["writeback_eligible"]:
                kind = "attack" if r["label"] == 1 else "benign"
                ev[f"candidates_{kind}"] += 1
                before = cache.stats["writes_rejected_overlap"]
                ok = cache.add_threat(r["text"], "INJECTION", "HIGH", "replay", confidence=r["max_llm_confidence"],
                                      llm_confirmed=True, embedding=v)
                if cache.stats["writes_rejected_overlap"] > before:
                    ev[f"rejected_overlap_{kind}"] += 1
                if ok:
                    ev[f"written_{kind}"] += 1
                    written.add(cache._generate_id(r["text"]))
        ev["variants_served_blocked"] += variant and served == 1
        served_rows.append({"label": r["label"], "served": served})

    expired_now = cache.purge_expired()
    assert cache.stats["evictions"] == 0, "capacity eviction is not modelled in the label accounting"
    alive = cache.collection.get(include=["metadatas"])
    online_alive = {i: m for i, m in zip(alive["ids"], alive["metadatas"]) if (m or {}).get("online")}
    evicted = cache.stats["revalidation_evictions"]
    removed = written - set(online_alive)
    final = {
        "online_alive_attack": sum(1 for i in online_alive if label_of.get(i) == 1),
        "online_alive_benign": sum(1 for i in online_alive if label_of.get(i) == 0),
        "promoted_attack": sum(1 for i, m in online_alive.items() if m.get("tier") == TRUSTED and label_of.get(i) == 1),
        "promoted_benign": sum(1 for i, m in online_alive.items() if m.get("tier") == TRUSTED and label_of.get(i) == 0),
        "expired_total": cache.stats["expirations"],
        "expired_at_end": expired_now,
        "removed_attack": sum(1 for i in removed if label_of.get(i) == 1),
        "removed_benign": sum(1 for i in removed if label_of.get(i) == 0),
        "revalidation_evictions": evicted,
        "confirmations": cache.stats["confirmations"],
    }
    if not (cache.probation_threshold or cache.ttl_requests):  # online entries are written trusted: no promotion
        final["promoted_attack"] = final["promoted_benign"] = 0

    online = confusion_metrics(served_rows)
    online.update({"n": len(rows), "cache_hit_rate": rate(ev["hits_seed"] + ev["hits_online"], len(rows)),
                   "gate_calls_per_1000": 1000 * rate(ev["gate_calls"], len(rows)),
                   "variant_cache_recall": rate(ev["variants_cache_blocked"], ev["variants"]),
                   "variant_recall": rate(ev["variants_served_blocked"], ev["variants"]), **ev})

    # held-out: frozen final cache
    cache.writeback, cache.revalidate_rate, cache.ttl_requests = False, 0.0, 0
    ho_rows, ho = [], {"hits_seed": 0, "hits_online": 0, "gate_calls": 0, "fp_cache_seed": 0, "fp_cache_online": 0,
                       "attacks_only_cache_caught": 0}
    for r in heldout:
        _, hit = cache.lookup_threat(r["text"], embedding=vec[r["text"]])
        if hit:
            ho["hits_online" if hit["online"] else "hits_seed"] += 1
            if r["label"] == 0 and r["pred"] == 0:
                ho["fp_cache_online" if hit["online"] else "fp_cache_seed"] += 1
            if r["label"] == 1 and r["pred"] == 0:
                ho["attacks_only_cache_caught"] += 1
        else:
            ho["gate_calls"] += int(r["llm_called"])
        ho_rows.append({"label": r["label"], "served": 1 if hit else r["pred"]})
    held = confusion_metrics(ho_rows)
    n_benign = sum(1 for r in heldout if r["label"] == 0)
    held.update({"n": len(heldout), "cache_hit_rate": rate(ho["hits_seed"] + ho["hits_online"], len(heldout)),
                 "gate_calls_per_1000": 1000 * rate(ho["gate_calls"], len(heldout)),
                 "cache_induced_fpr": rate(ho["fp_cache_seed"] + ho["fp_cache_online"], n_benign),
                 "cache_induced_fpr_online_entries": rate(ho["fp_cache_online"], n_benign), **ho})
    return {"stream": online, "heldout": held, "final_cache": final}


def entry_reach(stream, heldout, vec):
    """Reach of one entry written back from a recorded verdict, by matching radius: the share of the other
    split's benign prompts it would block (wrong entries: write-back-eligible benign prompts, i.e. gate false
    positives) and of its attacks it would catch (correct entries: eligible attacks)."""
    import numpy as np

    def unit(texts):
        m = np.asarray([vec[t] for t in texts], dtype=np.float32).reshape(len(texts), -1)
        return m / np.linalg.norm(m, axis=1, keepdims=True) if len(texts) else m

    def share(sims, radius):
        return float((sims >= radius).mean()) if sims.size else None

    out = {}
    for src_name, src, dst in (("test->validation", stream, heldout), ("validation->test", heldout, stream)):
        wrong = unit([r["text"] for r in src if r["writeback_eligible"] and r["label"] == 0])
        right = unit([r["text"] for r in src if r["writeback_eligible"] and r["label"] == 1])
        # for comparison: any benign prompt, and any benign prompt the pipeline flags, as if it had been cached
        any_benign = unit([r["text"] for r in src if r["label"] == 0])
        flagged_benign = unit([r["text"] for r in src if r["label"] == 0 and r["pred"] == 1])
        dst_b = unit([r["text"] for r in dst if r["label"] == 0])
        dst_a = unit([r["text"] for r in dst if r["label"] == 1])
        rows = []
        for radius in (0.65, 0.68, 0.70, 0.75, 0.80, 0.90):
            rows.append({"radius": radius,
                         "benign_blocked_per_wrong_entry": share(dst_b @ wrong.T, radius) if len(wrong) else None,
                         "attacks_caught_per_correct_entry": share(dst_a @ right.T, radius) if len(right) else None,
                         "benign_blocked_per_correct_entry": share(dst_b @ right.T, radius) if len(right) else None,
                         "benign_blocked_per_any_benign_prompt": share(dst_b @ any_benign.T, radius),
                         "benign_blocked_per_flagged_benign_prompt":
                             share(dst_b @ flagged_benign.T, radius) if len(flagged_benign) else None})
        out[src_name] = {"n_wrong_entries": len(wrong), "n_correct_entries": len(right),
                         "n_flagged_benign": len(flagged_benign),
                         "max_sim_wrong_entry_to_unseen_benign": float((dst_b @ wrong.T).max()) if len(wrong) else None,
                         "rows": rows}
    return out


def load_or_embed(cache, texts):
    """MiniLM embeddings keyed by the cache's own id (MD5 of the text), kept in _work/ (git-ignored) so that
    the replay embeds each text once. Train attacks already embedded in the warm-cache index are reused."""
    import numpy as np

    path = WORK_DIR / "embeddings" / "minilm_neuralchemy.npz"
    path.parent.mkdir(parents=True, exist_ok=True)
    store = {}
    if path.exists():
        data = np.load(path)
        store = dict(zip(data["keys"].tolist(), data["vectors"]))

    def save():
        keys = sorted(store)
        np.savez(path, keys=np.asarray(keys), vectors=np.asarray([store[k] for k in keys], dtype=np.float32))

    ids = {t: cache._generate_id(t) for t in texts}
    missing = [t for t in texts if ids[t] not in store]
    index = WORK_DIR / "caches" / "similarity_index"
    if missing and index.exists():
        import chromadb
        from chromadb.config import Settings

        col = chromadb.PersistentClient(path=str(index), settings=Settings(anonymized_telemetry=False)) \
            .get_collection("threat_intel_cache")
        for start in range(0, len(missing), 500):
            got = col.get(ids=[ids[t] for t in missing[start:start + 500]], include=["embeddings"])
            store.update({i: np.asarray(e, dtype=np.float32) for i, e in zip(got["ids"], got["embeddings"])})
        save()
        missing = [t for t in texts if ids[t] not in store]
    started = time.time()
    if missing:  # the ONNX embedder uses about one core, so embed in parallel processes
        from concurrent.futures import ProcessPoolExecutor, as_completed

        chunks = [missing[i:i + 64] for i in range(0, len(missing), 64)]
        done = 0
        with ProcessPoolExecutor(max_workers=6) as pool:
            futures = {pool.submit(_embed_chunk, c): c for c in chunks}
            for n, future in enumerate(as_completed(futures), 1):
                chunk = futures[future]
                store.update({ids[t]: np.asarray(v, dtype=np.float32) for t, v in zip(chunk, future.result())})
                done += len(chunk)
                if n % 8 == 0 or n == len(chunks):
                    save()
                    print(f"  embedded {done}/{len(missing)} ({time.time() - started:.0f}s)", flush=True)
    return {t: [float(x) for x in store[ids[t]]] for t in texts}


def _embed_chunk(texts):
    from semantic_firewall.core.orchestrator.semantic_cache import shared_embedder

    return [[float(x) for x in v] for v in shared_embedder()(texts)]


def paper_table(results):
    """The numbers reported in the paper, rounded, per configuration (means over the stream orders)."""
    rows = {}
    for key, block in results["configs"].items():
        s, h, f = block["mean"]["stream"], block["mean"]["heldout"], block["mean"]["final_cache"]
        g = lambda part, k: part[k]["mean"]
        # variant recall is pooled over the orders (some orders have no variant at all)
        per = block["per_order"].values()
        n_var = sum(r["stream"]["variants"] for r in per)
        pooled = lambda k: round(100 * sum(r["stream"][k] for r in per) / n_var, 1) if n_var else None
        rows[key] = {
            "stream_recall_pct": round(100 * g(s, "recall"), 2),
            "stream_fpr_pct": round(100 * g(s, "fpr"), 2),
            "stream_f1_pct": round(100 * g(s, "f1"), 2),
            "cache_hit_pct": round(100 * g(s, "cache_hit_rate"), 1),
            "gate_calls_per_1000": round(g(s, "gate_calls_per_1000"), 1),
            "benign_blocked_by_learned_entries": round(g(s, "fp_from_online_benign_entry") + g(s, "fp_from_online_attack_entry"), 1),
            "attacks_only_the_cache_caught": round(g(s, "attacks_only_cache_caught"), 1),
            "written_attack": round(g(s, "written_attack"), 1),
            "written_benign": round(g(s, "written_benign"), 1),
            "true_attacks_rejected_by_overlap": round(g(s, "rejected_overlap_attack"), 1),
            "gate_fps_rejected_by_overlap": round(g(s, "rejected_overlap_benign"), 1),
            "true_attack_entries_evicted": round(g(s, "evicted_attack_entry"), 1),
            "gate_fp_entries_evicted": round(g(s, "evicted_benign_entry"), 1),
            "attacks_lost_to_revalidation": round(g(s, "attacks_lost_to_revalidation"), 1),
            "variants_total_over_orders": n_var,
            "variant_cache_recall_pct": pooled("variants_cache_blocked"),
            "variant_recall_pct": pooled("variants_served_blocked"),
            "removed_attack_entries": round(g(f, "removed_attack"), 1),
            "removed_benign_entries": round(g(f, "removed_benign"), 1),
            "alive_learned_attack": round(g(f, "online_alive_attack"), 1),
            "alive_learned_benign": round(g(f, "online_alive_benign"), 1),
            "promoted_attack": round(g(f, "promoted_attack"), 1),
            "promoted_benign": round(g(f, "promoted_benign"), 1),
            "heldout_recall_pct": round(100 * g(h, "recall"), 2),
            "heldout_fpr_pct": round(100 * g(h, "fpr"), 2),
            "heldout_cache_fpr_learned_pct": round(100 * g(h, "cache_induced_fpr_online_entries"), 2),
            "heldout_cache_hit_pct": round(100 * g(h, "cache_hit_rate"), 1),
            "heldout_gate_calls_per_1000": round(g(h, "gate_calls_per_1000"), 1),
        }
    return rows


def mean_over_orders(runs):
    out = {}
    for part in ("stream", "heldout", "final_cache"):
        keys = runs[0][part].keys()
        out[part] = {k: {"mean": statistics.mean(r[part][k] for r in runs),
                         "min": min(r[part][k] for r in runs), "max": max(r[part][k] for r in runs)} for k in keys}
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--start", choices=["warm", "cold", "both"], default="both")
    parser.add_argument("--only", default="", help="comma-separated config names (default: all)")
    parser.add_argument("--embed-only", action="store_true", help="only compute and store the embeddings")
    parser.add_argument("--fresh", action="store_true", help="start replay.json over instead of updating it")
    parser.add_argument("--refresh", action="store_true",
                        help="recompute entry_reach and the paper table in replay.json without replaying")
    args = parser.parse_args()

    from semantic_firewall.core.orchestrator.semantic_cache import SemanticCache

    stream, heldout = load_verdicts("test"), load_verdicts("validation")
    train = load_samples("neuralchemy", "train")
    seeds = [r["text"] for r in train if r["label"] == 1]
    reference = [r["text"] for r in train if r["label"] == 0]
    print(f"stream {len(stream)}  held-out {len(heldout)}  seeds {len(seeds)}  benign reference pool {len(reference)}")

    with quiet_stdout():
        cache = SemanticCache(db_path=str(WORK_DIR / "caches" / "safeguard_replay"), similarity_threshold=TAU)
    # same Chroma library and SemanticCache code, but the collections live in memory (no disk I/O per write)
    import chromadb
    from chromadb.config import Settings

    cache.client = chromadb.EphemeralClient(settings=Settings(anonymized_telemetry=False))
    cache._open_collections()
    texts = list(dict.fromkeys([r["text"] for r in stream + heldout] + seeds + reference))
    vec = load_or_embed(cache, texts)
    print(f"embeddings ready for {len(texts)} texts", flush=True)
    if args.embed_only:
        return
    if args.refresh:
        import json

        results = json.loads((OUT / "replay.json").read_text(encoding="utf-8"))
        results["entry_reach"] = entry_reach(stream, heldout, vec)
        results["table"] = paper_table(results)
        write_json(OUT / "replay.json", results)
        print(json.dumps(results["entry_reach"], indent=1))
        return

    wanted = [c for c in args.only.split(",") if c]
    starts = ["warm", "cold"] if args.start == "both" else [args.start]
    import json

    previous = {} if args.fresh or not (OUT / "replay.json").exists() else \
        json.loads((OUT / "replay.json").read_text(encoding="utf-8"))["configs"]  # keep configs not re-run
    results = {"tau": TAU, "orders": ORDERS, "promote_after": 2, "configs": previous, "meta": run_metadata(),
               "entry_reach": entry_reach(stream, heldout, vec)}
    for direction, block in results["entry_reach"].items():
        pct = lambda x: "n/a" if x is None else f"{100 * x:.2f}%"
        print(f"reach {direction}: {block['n_wrong_entries']} wrong / {block['n_correct_entries']} correct entries; " +
              "  ".join(f"r={row['radius']}: benign {pct(row['benign_blocked_per_wrong_entry'])} / "
                        f"attacks {pct(row['attacks_caught_per_correct_entry'])}" for row in block["rows"]))
    for start in starts:
        for name, kwargs in configs().items():
            if wanted and name not in wanted:
                continue
            if start == "cold" and not wanted and name not in {"frozen", "writeback", "all-four"}:
                continue  # by default only the reference rows from an empty cache (cold/frozen = no cache)
            key = f"{start}/{name}"
            runs = []
            for order in ORDERS:
                with quiet_stdout():
                    runs.append(replay(cache, stream, heldout, seeds if start == "warm" else [], reference, kwargs,
                                       order, vec))
            results["configs"][key] = {"kwargs": kwargs, "per_order": dict(zip(map(str, ORDERS), runs)),
                                       "mean": mean_over_orders(runs)}
            m = results["configs"][key]["mean"]
            s, h, f = m["stream"], m["heldout"], m["final_cache"]
            print(f"{key:28s} stream R {100 * s['recall']['mean']:5.2f} FPR {100 * s['fpr']['mean']:5.2f} "
                  f"hit {100 * s['cache_hit_rate']['mean']:5.1f}% gate/1k {s['gate_calls_per_1000']['mean']:6.1f} | "
                  f"held-out R {100 * h['recall']['mean']:5.2f} FPR {100 * h['fpr']['mean']:5.2f} "
                  f"cacheFPR {100 * h['cache_induced_fpr']['mean']:4.2f} | written a/b "
                  f"{s['written_attack']['mean']:.1f}/{s['written_benign']['mean']:.1f} "
                  f"rej a/b {s['rejected_overlap_attack']['mean']:.1f}/{s['rejected_overlap_benign']['mean']:.1f} "
                  f"alive a/b {f['online_alive_attack']['mean']:.1f}/{f['online_alive_benign']['mean']:.1f}")
            results["table"] = paper_table(results)
            write_json(OUT / "replay.json", results)
    print(f"wrote {OUT / 'replay.json'}")


if __name__ == "__main__":
    main()
