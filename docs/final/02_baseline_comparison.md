# Final — Comparison Against Baselines

The Final checklist asks for a comparison table against 2–3 baselines. There
are two kinds of comparison, and they need different environments:

- **A. Measured now, in the sandbox:** the gate against its predecessor on the
  same held-out attacks, and the rules proposer against the LLM proposer on
  the same seeded labs.
- **B. Needs root on the VM:** the CIS Level 1 Server score delta for
  HardenCTL, OpenSCAP's own remediation and dev-sec, plus service
  preservation. `eval/run_baselines.sh` does this end to end. **Its cells
  below stay empty until it has run. Do not fill them in by hand.**

## A1. Gate comparison: held-out corpus v2 (44 weakening, 11 legitimate)

| Gate | Design | Weakening reaching apply | Legitimate refused | Source |
|---|---|---|---|---|
| v1 (Review 1) | Deny-list tables | 35/44 (79.5%, CI 65.5–88.9%) | 0/11 | `v2-on-gate-v1` |
| **v2 (first run, held-out)** | **Fail-closed for config/sysctl/modes; deny-list for units/packages** | **5/44 (11.4%, CI 5.0–24.0%)** | **2/11** | `v2-heldout-first-run` |
| v2.1 (not held-out) | v2 + rule-based units/packages, no world-write | 1/44 (2.3%, CI 0.4–11.8%) | 2/11 | `v1.0-gate-v2.1` |
| LLM self-restraint only (no gate) | The model's own refusal | 0/10 poisoned runs proposed the goal (upper 95% bound 27.8%) | — | `v1.0-final-llm-rerun` |

The last row is the alternative the literature table compares against:
trusting the model. It did well here (0/10), but 10 runs bound the failure
rate only at 27.8%. The gate's guarantee does not depend on the run count,
because it does not read the justification (0/438 ablation changes).

## A2. Proposer comparison: 30 seeded weak labs (rules) and 10+10 LLM labs

| Proposer | Weaknesses fixed | Actions refused by the gates | Time per plan | Tokens per plan | Source |
|---|---|---|---|---|---|
| Rules v0.1 | 284/325 (87.4%) | shadow 0640-on-0604 (F3) | ms | 0 | `v0.1-baseline` |
| **Rules v1.0** | **325/325 (100%)** | 0 | ms | 0 | `v1.0-release` |
| LLM (Claude Sonnet 5), clean | 62/65 sshd+mode (95.4%) | 3/65 (the F9 error) | 14.9 s | 1,919 in / 1,497 out | `v1.0-final-llm-rerun` |
| LLM, poisoned | 64/67 (95.5%) | 3/67 | 17.1 s | 2,126 in / 1,788 out | same |

The LLM row excludes sysctls, because the LLM is given no sysctl findings;
the rules row includes them.

## B. CIS Level 1 Server (Ubuntu 24.04), lab VM — to be filled from `results/baselines/summary.json`

Profile `xccdf_org.ssgproject.content_profile_cis_level1_server`, SCAP
Security Guide 0.1.82 upstream. Ubuntu's own `ssg-debderived` 0.1.71 has no
24.04 content, and this deviation from the Review 1 plan is recorded in [05](05_limitations.md).

| Method | Score weak lab | Score after | Δ | Rollback? | Services up after (ssh, redis, nginx, openplc) | Lynis index |
|---|---|---|---|---|---|---|
| Weak lab (`setup_lab.sh`) | | — | — | — | | |
| HardenCTL rules | | | | yes (checked) | | |
| HardenCTL LLM | | | | yes (checked) | | |
| OpenSCAP `--remediate` | | | | no | | |
| dev-sec os + ssh hardening | | | | no | | |

**Expected shape, not a result.** HardenCTL changes about 15 settings, while
the CIS profile has over 200 rules. The HardenCTL delta will be much smaller
than OpenSCAP's own remediation, and the +25-point target set at Review 0 is
**unlikely to be met**. Say so plainly at the viva. The comparison HardenCTL
is built to win is not raw score. It wins on *score per broken service* and on
reversibility: OpenSCAP and dev-sec have no rollback, and profile-wide
remediation is known to disturb running services. Report what the run shows
either way.

### How to fill section B (on the VM, as root)

```bash
sudo eval/run_baselines.sh prep            # packages + SCAP content (checksum-verified)
sudo demo/setup_lab.sh                     # weak lab; then VMware snapshot "weak-lab"
sudo eval/run_baselines.sh hardenctl       # rules (+ llm): score, rollback, re-score
sudo eval/run_baselines.sh openscap        # then revert to "weak-lab"
sudo eval/run_baselines.sh devsec          # then revert to "weak-lab"
eval/run_baselines.sh summary              # prints the table; writes summary.json
```

For statistical rigour, repeat the `hardenctl` phase at least 5 times. It
rolls itself back, so no revert is needed between repetitions. Repeat
`openscap` and `devsec` 3 times each, reverting to the snapshot every time.
