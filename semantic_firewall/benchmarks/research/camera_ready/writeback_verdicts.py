"""Cache-miss verdicts and write-back eligibility on normal traffic (for the cache-safeguard evaluation).

Runs the full system (all unresolved prompts to the LLM gate) with the semantic cache DISABLED, so every prompt gets
the verdict it would receive on a cache miss, and records whether the firewall would write it to the threat cache:
an LLM-assisted detector found a threat, the finding is LLM-confirmed and its confidence is >= the write-back floor
(0.85), exactly the rule in SemanticCache.writeback_allowed.

  python writeback_verdicts.py --dataset neuralchemy --split test
  python writeback_verdicts.py --dataset neuralchemy --split validation
Output: results_camera_ready/cache_safeguards/verdicts_<dataset>-<split>.jsonl
"""

import argparse
import time

from common import CONFIGS, OUT_ROOT, build_firewall, load_samples, run_samples

OUT = OUT_ROOT / "cache_safeguards"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dataset", default="neuralchemy")
    parser.add_argument("--split", default="test")
    parser.add_argument("--workers", type=int, default=3)
    args = parser.parse_args()

    name = f"{args.dataset}-{args.split}"
    fw, _, _ = build_firewall(CONFIGS["full_all_unresolved"], f"writeback-verdicts-{name}", cache_protocol="none",
                              overrides={"SEMANTIC_FIREWALL_SEMANTIC_CACHE_ENABLED": "0"})
    floor = fw.semantic_cache.writeback_min_confidence

    def predict(sample):
        started = time.perf_counter()
        try:
            d = fw.analyze(sample["text"])
            eligible, best = False, 0.0
            for res in d.agent_results:
                if res.threat_found and res.agent_name in fw.llm_agents and res.threat_type not in {"NONE", "SYSTEM_UNAVAILABLE"}:
                    conf = fw._confidence_from_result(res)
                    confirmed = int((res.meta or {}).get("llm_match_count", 0) or 0) > 0
                    best = max(best, conf)
                    eligible = eligible or (confirmed and conf >= floor)
            return {"id": sample["id"], "label": sample["label"], "pred": int(d.action in {"BLOCK", "FLAG", "REDACT"}),
                    "action": d.action, "llm_called": bool(getattr(d, "llm_called", False)),
                    "writeback_eligible": eligible, "max_llm_confidence": best,
                    "latency_ms": (time.perf_counter() - started) * 1000, "error": None}
        except Exception as exc:
            return {"id": sample["id"], "label": sample["label"], "pred": 0, "action": "ERROR", "llm_called": False,
                    "writeback_eligible": False, "max_llm_confidence": 0.0,
                    "latency_ms": (time.perf_counter() - started) * 1000, "error": str(exc)[:300]}

    recs = run_samples(predict, load_samples(args.dataset, args.split), OUT / f"verdicts_{name}.jsonl",
                       workers=args.workers)
    print(f"{name}: {len(recs)} records, blocked {sum(r['pred'] for r in recs)}, "
          f"write-back eligible {sum(r['writeback_eligible'] for r in recs)}, errors {sum(1 for r in recs if r['error'])}")


if __name__ == "__main__":
    main()
