# Final Review — HardenCTL

Mapped to the Final Review checklist in *M.Tech Project Review Checklists —
AIML & CyberSecurity (2026)*. **Status is honest:** "pending" means it needs
root on the VM or something only you can do.

| Checklist item | Where | Status |
|---|---|---|
| Full system implemented and demonstrated end-to-end | `hardenctl` v1.0.0 (CLI + `hardenctl gui` dashboard); testbed in `lab/` | done in code; **real-host run as root pending** (see `run_baselines.sh hardenctl`) |
| Final results with statistical rigour (multiple runs/seeds, CIs) | [01_results](01_results.md) | done: 30 seeded runs per suite, Wilson/bootstrap 95% CIs, Fisher exact test on the headline comparison (p = 4.3 × 10⁻¹¹) |
| Comparison table against 2–3 baselines | [02_baseline_comparison](02_baseline_comparison.md) | gate v1 vs v2 vs v2.1 and rules vs LLM: done. **OpenSCAP and dev-sec CIS delta: pending** (`eval/run_baselines.sh`, root) |
| Robustness and evasion testing (CyberSec) | [04_robustness_and_evasion](04_robustness_and_evasion.md) | done: held-out corpus v2, 438-case ablation, poisoned LLM runs |
| Limitations honestly discussed | [05_limitations](05_limitations.md) | done |
| Contribution restated (what, how much better) | [06_contribution](06_contribution.md) | done |
| Complete thesis in institute format | [../thesis](../thesis/README.md) | **outline with the content and figures for each chapter; you write it** |
| Code repository finalised, documented, reproducible | [07_reproducibility](07_reproducibility.md), `requirements.txt`, `tests/`, CI | done; **needs one run by another person** |
| Plagiarism report within threshold | — | **yours** (institute tool) |
| Publication status | [../thesis/paper_outline.md](../thesis/paper_outline.md) | outline done; **venue and submission are yours** |
| All prior panel feedback addressed and traceable | [09_feedback_tracker](09_feedback_tracker.md) | self-commitments traced; **panel comments must be copied in** |
| Ethical compliance | `docs/review0/03_threat_model_scope_ethics.md` | documented: lab VM only, no third-party targets, no PII; no vulnerabilities in third-party software found, so no disclosure needed. **Guide sign-off still blank** in `docs/review1/README.md` |
| Viva readiness: defend every design choice | [08_viva_defence](08_viva_defence.md) | 19 questions with plain and technical answers, including the dashboard |
| Future work: genuine next steps | [10_future_work](10_future_work.md) | done |
| Error analysis (carried from Review 2) | [03_error_analysis](03_error_analysis.md) | 12 real failures, with cause and fix or limitation |

## The numbers in one screen

| | Result |
|---|---|
| Held-out weakening actions reaching apply | gate v1 **35/44** → gate v2 **5/44** (first run) → v2.1 1/44 |
| Fail-closed components, held-out | **0/22** leaked |
| Persuasive justifications changing a verdict | **0/438** |
| Rollback byte-exact (sandbox) | **30/30**; auto-revert on injected failure **30/30** |
| Rules remediation on seeded labs | 87.4% → **100%** (325/325) |
| Intent detection / false positives | **100%** each type / **0/160** |
| LLM plan validity | **95.4%**; all 6 errors refused by the gate |
| Explainer prompt saved by intent | **37%** |

## What only you can do before the review

1. Re-point root's install at the repo:
   `cd ~/Desktop/HardenCTL/hardenctl && sudo pip install -e . --break-system-packages --ignore-installed`
   (right now `sudo hardenctl` runs an old copy in `~/hardenctl`, F12).
2. Run the baselines on the VM ([02, section B](02_baseline_comparison.md#how-to-fill-section-b-on-the-vm-as-root)) and fill the table from `results/baselines/summary.json`.
3. Ask a classmate to follow [07](07_reproducibility.md) and record it in [09](09_feedback_tracker.md).
4. Copy the panel's Review 0/1/2 comments into [09](09_feedback_tracker.md).
5. Push the `final-review` branch and check that CI is green.
6. Write the thesis and paper in your own words from [../thesis](../thesis/README.md), then run the plagiarism check.
7. Rehearse [08](08_viva_defence.md) out loud.
