# Raw results (camera-ready)

Every run folder in `runs/` contains:
- `predictions.jsonl`: one record per prompt, with id, label, prediction, action, resolution stage, LLM called/failed, LLM host, latency and per-stage latency, ensemble risk, triggered detectors, and cache similarity/hit for warm runs;
- `summary.json`: the metrics, plus a code fingerprint and run metadata.

Prompt texts are not stored. Records refer to the public datasets by id.

Run names follow `<dataset>-<split>-<config>-<cache>`. Runs ending in `-warm_frozen-tau0.65` are derived exactly
from the matching `-none` run with `camera_ready/derive_warm.py`.

## Runs reported in the paper

| Paper | Run(s) |
|---|---|
| Table 2a, ours (warm) / Table 4 C8 | `neuralchemy-test-full_all_unresolved-warm_frozen-tau0.65` (from `…-none`) |
| Table 2a, ours (cold) / Table 4 C9 | `neuralchemy-test-full_all_unresolved-cold` (complete, single sequential run; `significance/cold_cache.json`) |
| Table 2a, baselines | `neuralchemy-test-baseline-llm-openai__gpt-4o`, `…-google__gemini-2.5-flash`, `…-anthropic__claude-haiku-4.5`, `…-hf-protectai__deberta-v3-base-prompt-injection-v2`, `…-llama_guard-meta-llama__llama-guard-4-12b`, `…-hf-leolee99__PIGuard` (provenance: `runs/BASELINES_PROVENANCE.md`) |
| Table 2b BeaverTails | `beavertails-test-full_all_unresolved-warm_frozen-tau0.65`, `beavertails-test-baseline-llama_guard-meta-llama__llama-guard-4-12b` |
| Table 2b deepset | `deepset-all-full_all_unresolved-warm_frozen-tau0.65` (Rebuff row is the published number of Palit & Woods) |
| Table 2c PII | `pii/pii_eval_ai4privacy.json` (all rows; `pii_eval_dev*`/`pii_eval_heldout*` are the dev/held-out halves, `pii_eval.json` the default profile) |
| Table 2c no_robots | `no_robots-test-full_all_unresolved-warm_frozen-tau0.65` (from `…-none`; 14 blocked = 2.80%, 37 flagged/redacted = 7.4%) |
| Table 2c multi-turn + Session Judge breakdown | `multiturn/multiturn-heldout-full_all_unresolved-warm_frozen-final-memory` (held-out 100+100, run once) and its `breakdown.json` (`camera_ready/multiturn_breakdown.py`); memory threshold selected on dev in `multiturn/memory_tuning.json` from the dev run `…-dev-…-e2-fullwindow-goal`. Earlier held-out runs `…-final` and `…-final-no-session` used a cache threshold of 0.90 and are not reported |
| Table 3a | `threshold/tau_sweep_neuralchemy_validation_neuralchemy-validation-full_all_unresolved-none.*` from `neuralchemy-validation-full_all_unresolved-none` |
| Table 3b | `threshold/tau_sweep_ood500_all_ood500-all-full_all_unresolved-none.*` from `ood500-all-full_all_unresolved-none` |
| Table 4 C1–C7 | `neuralchemy-test-injection_llm_only-none`, `…-regex_only-none`, `…-cache_only-warm_frozen`, `…-detectors_only-none`, `…-regex_cache-warm_frozen`, `…-deterministic_only-none`, `…-fast_layers-warm_frozen` |
| Table 2a, Prompt Guard 2 | `neuralchemy-test-baseline-groq_guard-meta-llama__llama-prompt-guard-2-86m` (Groq API; 30 rate-limit/length failures re-run, 0 errors); latency `latency/api_latency_meta-llama__llama-prompt-guard-2-86m.json` (`camera_ready/api_latency.py`) |
| Per-detector ablation (Table 6) | MIXED-1000, see "Per-detector ablation on MIXED-1000" below. The earlier neuralchemy runs `neuralchemy-test-loo_*` are kept but no longer in the paper |
| Table 4 latency | `neuralchemy-test-latency-<config>` (210 prompts, one at a time, first 10 are warm-up) |
| Latency, Eq. 8, prevalence | `latency/latency_neuralchemy-test-latency-groq.json` from `neuralchemy-test-latency-groq` |
| McNemar | `significance/significance.json` (vs baselines), `significance/ablation.json` (vs C1, C7) |
| Warm-cache check | `significance/novel_subset.json` |
| Levenshtein study | `levenshtein_study.json` |
| All table numbers | `final_tables.json` (`camera_ready/final_tables.py`) |

## Additional analyses (run 2026-10-06)

| Analysis | Files |
|---|---|
| Policy profiles (strict, developer_assistant), in Sec. 5.3 | `runs/neuralchemy-test-full_all_unresolved-none-profile_*`, derived `…-warm_frozen-tau0.65-profile_*`, `significance/policy_profiles.json` |
| Parallel LLM agents only, no deterministic stage (Table 4, C1b) | `runs/neuralchemy-test-llm_agents_only-none`, `significance/llm_agents_only.json` |
| Cache robustness: allowlist abuse (in Security Considerations), growth/eviction (in Sec. 3.2) and error propagation (not in the paper) | `cache_robustness/{allowlist_abuse,growth,error_propagation}.json` (`camera_ready/cache_robustness.py`) |
| Explainability example under three profiles, in Sec. 5.3 | `explainability_example.json` (`camera_ready/explain_example.py`) |

## Per-detector ablation on MIXED-1000 (Table 6, run 2026-10-12)

| Analysis | Files |
|---|---|
| MIXED-1000: 1,000 prompts (neuralchemy test prompts + personal data, generated credentials, oversized inputs, threat-intel signatures, a workspace rule term, benign look-alikes) | `data/datasets/mixed_coverage_1000.jsonl` (`camera_ready/build_mixed_set.py`) |
| Full system and each detector removed (no cache; LLM answers cached on disk and reused across the ablation runs, temperature 0) | `runs/mixed-all-*-none` |
| Warm-cache versions (exact rule of Eq. 9) | `runs/mixed-all-*-warm_frozen-tau0.65` (`camera_ready/derive_warm_mixed.py`) |
| Table 6 numbers | `mixed/table6_mixed.json` (`camera_ready/table6_mixed.py`) |

## Cache write-back safeguards (run 2026-10-11)

| Analysis | Files |
|---|---|
| Cache-miss verdicts with write-back eligibility (full system, no cache; 0 errors; 99.26% / 99.68% agreement with the `…-none` runs) | `cache_safeguards/verdicts_neuralchemy-{test,validation}.jsonl` (`camera_ready/writeback_verdicts.py`) |
| Cost of the four safeguards on normal traffic (no attacker): exact replay of write-back through `SemanticCache`, test split streamed in 5 orders, final cache evaluated on validation; per-entry reach by radius; numbers used in the paper under `table` | `cache_safeguards/replay.json` (`camera_ready/cache_safeguards_replay.py`) |

## Other runs kept as logs (not reported)

| Run(s) | Why it is not in the paper |
|---|---|
| `*-no_cache-none`, `neuralchemy-validation-deterministic_only-none*`, `deepset-all-deterministic_only-none`, matching `threshold/` sweeps | Earlier design in which a keyword gate decided whether to call the LLM (recall 14% on deepset, 6% on BeaverTails); replaced by `full_all_unresolved` |
| `neuralchemy-test-baseline-llm-openai__gpt-4o-mini`, `…-gpt-oss-120b`, `deepset-all-baseline-*` | Extra baselines run but not reported (author decision) |
| `beavertails-test-full_all_unresolved-none`, `deepset-all-full_all_unresolved-none`, `ood500-all-full_all_unresolved-none`, `neuralchemy-test-full_all_unresolved-none` | No-cache sources of the derived warm runs |
| `multiturn/multiturn-dev-*` | Development runs of the multi-turn check (dev part only) |

`_work/` (git-ignored) holds the per-run vector stores and can be deleted.
