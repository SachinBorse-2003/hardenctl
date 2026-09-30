# Final — Contribution, Restated

**One sentence.** HardenCTL shows that an LLM can be put in the remediation
loop of a root-level hardening tool *without being trusted*. A deterministic,
fail-closed monotonicity gate decides what runs, and every applied change can
be reverted exactly.

## What is new

1. **Monotonicity as the safety property for agentic remediation.** Prior
   system-level defences (CaMeL, IsolateGPT, the design-pattern paper) bound
   *which* tools an agent may call. HardenCTL bounds *what an allowed action
   may do*: it may not make the host weaker. Weaker is decided by ordering
   rules that read the disk, never the model's justification.
2. **Fail-closed beats deny-list, measured.** On a held-out corpus the
   Review 1 deny-list gate let 35/44 weakening actions through; the fail-closed
   gate let 5/44 through: 4 in its remaining deny-list parts, 1 in the
   absent-file branch, and 0 of 22 in the fail-closed parts.
3. **Intent as a deterministic filter in front of the model.** Declared
   services never reach the model: 37% smaller explainer prompts on the seeded
   hosts, and the model cannot propose disabling what it never sees.
4. **Reversibility as a first-class, measured property.** Byte-exact rollback in
   30/30 seeded runs, exact auto-revert in 30/30 injected failures, and
   persisted sysctls reverted with the run.

## By how much

| | Before (Review 1 code) | After (release) |
|---|---|---|
| Held-out weakening actions reaching apply | 35/44 | 5/44 (v2), 1/44 (v2.1, no longer held-out) |
| Weaknesses fixed on seeded labs (rules) | 87.4% | 100% |
| DRIFT detected when a port is dual-bound | 62.5% | 100% |
| sysctls surviving reboot | 0 | 112/112 persisted |
| LLM errors reaching the host | not measured | 0 of 6 (all refused by the gate) |

## What it is not

Not a better CIS scanner. OpenSCAP covers far more rules, and its
remediation will move the CIS score further. HardenCTL's contribution is the
*safety envelope* around an agent: intent, gates, reversibility. It is not
breadth of hardening.
