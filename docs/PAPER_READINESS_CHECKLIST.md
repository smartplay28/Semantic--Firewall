# Paper Readiness Checklist

Use this checklist to move from project demo quality to research-paper quality.

## 1) Research Framing
- [ ] Finalize one-sentence research claim.
- [ ] Define threat model (input attacks, output leakage, multi-turn attacks).
- [ ] Define scope boundaries (what is out-of-scope).

Deliverable:
- [ ] `docs/research_claim.md` (claim + threat model + assumptions).

## 2) Dataset Preparation
- [ ] Build fixed benchmark dataset with categories:
  - injection
  - jailbreak
  - pii
  - secrets
  - unsafe_content
  - benign
- [ ] Include both `input` and `output` samples.
- [ ] Add metadata columns: `id`, `category`, `direction`, `label`, `source`, `difficulty`.
- [ ] Split into `dev` and `test` sets.

Deliverables:
- [ ] `datasets/firewall_benchmark_dev.jsonl`
- [ ] `datasets/firewall_benchmark_test.jsonl`
- [ ] `datasets/DATASET_CARD.md`

## 3) Baseline Comparisons
- [ ] Define baseline systems (at least 3):
  - simple regex baseline
  - existing open-source guardrail tool(s)
  - your full system
- [ ] Ensure same dataset and evaluation settings for all methods.
- [ ] Run and store raw outputs for reproducibility.

Deliverables:
- [ ] `results/baselines/*.json`
- [ ] `results/tables/main_comparison.csv`

## 4) Core Metrics
- [ ] Compute per-category metrics:
  - precision
  - recall
  - F1
  - false positive rate
  - false negative rate
- [ ] Compute system-level latency:
  - p50
  - p95
  - p99
- [ ] Report throughput under fixed load.

Deliverables:
- [ ] `results/metrics/metrics_summary.json`
- [ ] `results/figures/confusion_matrix_*.png`
- [ ] `results/figures/latency_curve.png`

## 5) Ablation Study (Most Important)
- [ ] Full system.
- [ ] Without LLM-gating.
- [ ] Without threat-intel detector.
- [ ] Without session/multi-turn logic.
- [ ] Without custom rules.

Deliverables:
- [ ] `results/tables/ablation.csv`
- [ ] `results/figures/ablation_bar.png`

## 6) Robustness Evaluation
- [ ] Obfuscated attacks (spacing, unicode, punctuation tricks).
- [ ] Paraphrased attacks.
- [ ] Multi-turn escalation prompts.
- [ ] Mixed benign + attack text.

Deliverables:
- [ ] `results/tables/robustness.csv`
- [ ] `results/error_analysis/robustness_failures.md`

## 7) Error Analysis
- [ ] Top 20 false positives with explanation.
- [ ] Top 20 false negatives with explanation.
- [ ] Proposed fixes linked to each failure class.

Deliverables:
- [ ] `results/error_analysis/false_positives.md`
- [ ] `results/error_analysis/false_negatives.md`

## 8) Reproducibility
- [ ] One command to run full evaluation from scratch.
- [ ] Fixed random seeds/config.
- [ ] Pin dependency versions.
- [ ] Store exact commit hash in result metadata.

Deliverables:
- [ ] `scripts/run_full_benchmark.(sh|ps1)`
- [ ] `results/reproducibility_manifest.json`

## 9) Paper Writing Structure
- [ ] Abstract (problem, method, key results).
- [ ] Introduction (why current guardrails are insufficient).
- [ ] Method (architecture + policy + gating).
- [ ] Experimental setup (dataset + baselines + metrics).
- [ ] Results (main + ablation + robustness).
- [ ] Limitations and ethics.
- [ ] Conclusion and future work.

Deliverables:
- [ ] `paper/outline.md`
- [ ] `paper/figures/`
- [ ] `paper/tables/`

## 10) Submission Readiness Gate
Before submission, all must be true:
- [ ] Results are reproducible on a clean machine.
- [ ] Metrics are consistent across 3 reruns.
- [ ] Ablation supports your main claim.
- [ ] Error analysis is honest and includes limitations.
- [ ] Code/data links are ready for reviewers.

---

## Recommended Execution Order
1. Dataset + metrics pipeline
2. Baselines
3. Ablation
4. Robustness + error analysis
5. Writing + final reproducibility pass
