"""Per-request latency of an API-hosted baseline, measured without rate-limit waits.

Calls are made one at a time and spaced out (--gap seconds) so that free-tier rate limits are never hit; the
first --warmup calls are excluded. Used for Prompt Guard 2 on Groq, whose accuracy run (run_baselines.py) was
slowed by rate-limit back-off and therefore does not give a usable latency.

  python api_latency.py --kind groq_guard --model meta-llama/llama-prompt-guard-2-86m --n 100
Output: results_camera_ready/latency/api_latency_<model>.json
"""

import argparse
import time

from common import OUT_ROOT, load_samples, percentile, run_metadata, write_json
from run_baselines import groq_guard_predictor


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--kind", choices=["groq_guard"], default="groq_guard")
    parser.add_argument("--model", required=True)
    parser.add_argument("--n", type=int, default=100)
    parser.add_argument("--warmup", type=int, default=5)
    parser.add_argument("--gap", type=float, default=2.5, help="seconds between calls (stay under rate limits)")
    args = parser.parse_args()

    predict = groq_guard_predictor(args.model)
    samples = load_samples("neuralchemy", "test", max_samples=args.n + args.warmup, seed=0)
    lat, errors = [], 0
    for i, s in enumerate(samples):
        r = predict(s)
        if r["error"]:
            errors += 1
        elif i >= args.warmup:
            lat.append(r["latency_ms"])
        time.sleep(args.gap)
    out = {"model": args.model, "n": len(lat), "warmup_excluded": args.warmup, "errors": errors,
           "mean_ms": sum(lat) / len(lat), "p50_ms": percentile(lat, 50), "p95_ms": percentile(lat, 95),
           "p99_ms": percentile(lat, 99), "meta": run_metadata()}
    write_json(OUT_ROOT / "latency" / f"api_latency_{args.model.replace('/', '__')}.json", out)
    print({k: (round(v, 1) if isinstance(v, float) else v) for k, v in out.items() if k != "meta"})


if __name__ == "__main__":
    main()
