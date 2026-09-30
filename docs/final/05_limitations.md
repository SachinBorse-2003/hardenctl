# Final — Limitations (no overclaiming)

Say these before the panel finds them.

## What the claims do and do not cover

| Claim you may make | Claim you may NOT make |
|---|---|
| "No weakening action in the development corpus reached apply; on the held-out corpus, 5/44 did with gate v2, and every leak was in a deny-list component." | "HardenCTL is provably safe" or "0% injection success" without qualification |
| "The validator never reads the justification: 0/438 persuasion variants changed a verdict." | "The LLM cannot be manipulated": the model was not manipulated in 20 runs, which bounds its failure rate only at about 28% |
| "Rollback was byte-exact in 30/30 sandbox runs." | "Rollback is byte-exact on any host": services and packages are reverted by re-enabling or reinstalling, which is not byte-exact |
| "Intent verdicts were 100% correct on seeded scenarios." | "Intent is 100% accurate on real hosts": the scenarios are synthetic |

## Limitations

1. **Held-out corpus authorship.** Gate v2 and corpus v2 have the same author.
   v2 is held out in time, not authorship.
2. **Deny-list remainder.** Disabling services and removing packages are still
   judged against protected sets plus rules. A security agent not covered
   (e.g. osquery, an EDR) can be disabled by a plan. Mitigation today: declare
   it in intent and review the plan. Future: an operator-declared `protect:`
   list in `intent.yaml`.
3. **Narrow remediation coverage.** Rules cover 5 sshd directives, 5 file
   modes and 5 sysctls. The CIS Level 1 profile has more than 200 rules, so the
   CIS score delta will be modest (see [02](02_baseline_comparison.md)).
4. **Fail-closed has a cost.** 2/11 legitimate held-out changes are refused.
   Wider policies (Banner, pwquality, auditd rules) would need new ordering
   rules, each a new part of the trusted code.
5. **Reachability is inferred, not probed.** Exposure comes from the bind
   address, not from a probe in a network namespace (a Review 0 promise that
   stays deferred). Firewall rules are not considered, so a 0.0.0.0 service
   behind a DROP rule is still reported as PUBLIC.
6. **Attribution accuracy is unmeasured.** No labelled ground-truth VM was built.
7. **Sandbox vs real host.** The seeded suites run in a sandbox that emulates
   `/etc` and `/proc/sys`. The sandbox cannot exercise `systemctl`, `apt-get`
   or `sshd -t`. `run_baselines.sh` covers the real host for the rules and LLM
   path, but only once it has been run.
8. **TOCTOU.** `apply` re-validates, but a file can change between validation
   and its write. An attacker able to do that already has write access to
   `/etc`, which is outside the threat model.
9. **sshd changes take effect on reload.** The executor edits the config and
   checks it with `sshd -t`. It does not reload sshd, so a change applies at the
   next restart.
10. **`Match` blocks.** The collector evaluates global settings only. A weak
    value inside `Match` is not reported.
11. **Scoring content deviation.** Review 1 planned Ubuntu's SCAP package; it
    has no 24.04 content, so the upstream SSG 0.1.82 release is used, verified
    by its published SHA-512.
12. **One distribution.** Ubuntu 24.04 only (Debian-family by design).
13. **LLM sample.** 10 runs per condition, one model (Claude Sonnet 5), one
    temperature (provider default). No local-model (Ollama) runs.
14. **Token site / relay.** Not built. It was the first item to cut if time
    ran short, and it is not on either review checklist.
