# Final — Feedback Tracker (Review 0 → Final)

The checklist asks for all prior panel feedback to be "addressed and
traceable". **The panel's actual comments are not in this repository.** Add
each one as a row, word for word from your review sheet, with the commit or
document that answers it. Do not paraphrase a comment into one you have
already answered.

## Panel feedback (fill from your review sheets)

| # | Review | Panel comment (verbatim) | Response | Evidence (commit / doc) | Status |
|---|---|---|---|---|---|
| P0 | Final | *Paraphrased by the student; replace with the panel's exact words:* provide a GUI and a better presentation/demo | Added `hardenctl gui`, a local web dashboard (scan, intent, plan/apply/rollback with a fingerprint check, Gate Lab, results charts). It is secured as root-facing software and tested over HTTP | `hardenctl/gui/`, `tests/test_gui.py`, README "Dashboard" | done |
| P1 | 0 | | | | |
| P2 | 1 | | | | |
| P3 | 2 | | | | |

## Commitments made in our own review documents

| # | Where promised | Commitment | What happened | Evidence |
|---|---|---|---|---|
| S1 | Review 0, O1 | Intent verdicts: 100% detection, 0 FP on seeded scenarios | Met: 30/30 per type, 0/160 FP | `results/*v1.0-release-intent.json` |
| S2 | Review 0, O2(a) | LLM plan validity ≥ 98% | **Not met:** 95.4%. All misses refused by the gate (F9) | `results/*llm-rerun-llm.json` |
| S3 | Review 0, O2(b) | 0% of corpus payloads reach apply | Met on v1 (0/29); **not met** on held-out v2 (5/44 first run) | `docs/final/04` |
| S4 | Review 0, O3(a) | Rollback fidelity 100% over ≥ 30 runs | Met in the sandbox (30/30); real-VM check in `run_baselines.sh` | `results/*rollback.json` |
| S5 | Review 0, O3(b) | ≥ 95% service preservation | **Pending** VM run | `eval/run_baselines.sh` |
| S6 | Review 0, O4 | CIS delta ≥ +25 (rules), vs OpenSCAP and dev-sec | **Pending** VM run; target likely missed (see `02`) | `docs/final/02` |
| S7 | Review 1, 03 | Close the gate 3 gap with design option C | Done: gate v2 (`f847481`), v2.1 (`3b45cfe`) | `hardenctl/validator.py` |
| S8 | Review 1, 04 | Held-out corpus v2, ideally by another author | Done (55 cases, frozen `197e4d3`), same author | `corpus/injection_v2.json` |
| S9 | Review 1, 05 R5 | Confirm an Ubuntu 24.04 CIS profile | Not in Ubuntu's package; upstream SSG 0.1.82 has it | `eval/run_baselines.sh` |
| S10 | Review 1, 05 R7 | Persist sysctls with rollback | Done, 112/112 | `executor.persist_sysctl` |
| S11 | Master backlog P0 | Tests in pytest, CI | Done: 25 tests, GitHub Actions | `tests/`, `.github/workflows/ci.yml` |
| S12 | Review 0 | Network-namespace reachability probing | **Deferred** (stated in Review 1 and here) | `05_limitations.md` |
| S13 | Review 0 | Blast radius | **Deferred** | `10_future_work.md` |
| S14 | Review 1, 04 | Attribution accuracy on a labelled ground-truth VM | **Not done** | `05_limitations.md` |
| S15 | Review 1 | Token site (no billing) | **Cut**: first to go under time pressure; not on any checklist | `10_future_work.md` |

## Reproducibility check by another person

| Who | Machine | Date | Result |
|---|---|---|---|
| | | | |
