# Final — Viva Defence

"The student can defend every design choice, not just describe it." Each
question has a short answer in plain words, then the technical version to
use when pressed. Learn the *why*; the numbers are in [01](01_results.md).

---

**Q1. Why not just ask a second LLM to check the first one's plan?**
Plain: the checker reads the same poisoned input, so whatever fooled the first
model can fool the second.
Technical: an LLM judge is a probabilistic classifier over attacker-influenced
context. The best published defences report a residual attack success rate
above zero (Spotlighting <2%, InjecAgent 24% undefended). Gate 3 is a pure
function of the action's fields and the disk state; its output cannot depend
on the justification. The ablation shows it: 0/438 verdicts changed.

**Q2. Your gate still leaked 5/44 on the held-out set. So it doesn't work?**
Plain: it works where it fails closed and leaks where it is still a list, and
that is exactly what the experiment was designed to find out.
Technical: every leak was in a deny-list component (4/7) or the absent-file
branch (1/8). The fail-closed parts leaked 0/22, against 35/44 for the v1 gate
on the same cases. The remaining deny-list (service and package removal) is a
known limitation with a stated mitigation.

**Q3. Why fail closed, if it rejects legitimate fixes?**
Plain: for a tool running as root, refusing a good change costs one manual
step; accepting a bad one costs the host.
Technical: an asymmetric loss. 2/11 legitimate held-out changes were refused;
each can be added later as an explicit ordering rule, a reviewable change to
the trusted code.

**Q4. Why is plan validity 95.4% when your target was 98%?**
Plain: the model made the same mistake six times, the gate caught it six
times, and none of it touched the host.
Technical: all six are `/etc/shadow` 0604 → 0640, which adds S_IRGRP. The
target measured model quality; the result shows the gate compensating for
the model. Below target, reported as such.

**Q5. What does "monotonicity" mean here?**
Plain: an action can only move the host towards more secure, never less.
Technical: a partial order per setting (enum sets, integer ceilings compared
with the on-disk value, algorithm sets, mode bits as subsets). A change is
accepted only if it is comparable and no weaker. Incomparable or unknown
means reject.

**Q6. Why does the validator read the disk? Isn't the plan enough?**
Plain: the plan's claims about the current state come from the model, and the
model can be wrong or lying.
Technical: `current_mode` in the plan is untrusted input. The corpus v2 case
with `current_mode: "0777"` and the model's F9 errors are both caught only
because the on-disk mode is authoritative.

**Q7. Is rollback really byte-exact?**
Plain: for files and sysctls, yes, measured 30/30. For services and packages
it re-enables or reinstalls, which is a functional undo, not a byte-exact one.
Technical: files are backed up on first touch (including an "absent" marker,
so created files are deleted on rollback), inverses are captured from live
state before each change, and the snapshot compared hashes, modes and file
existence.

**Q8. Why is there no shell action?**
Plain: a shell command can do anything, so no gate could check it and no
undo could reverse it.
Technical: each of the six typed actions has a known inverse and a
monotonicity rule. A shell action has neither, which would make both
guarantees impossible.

**Q9. Gate 2 (allowlist) never rejected anything in your results. Is it useless?**
Plain: it is a safety net that currently never gets reached, because gate 1
already refuses unknown action types.
Technical: the discriminated union in the schema only admits the six
`Literal` action types, so gate 2 is unreachable through `Plan` parsing. It
guards against a future schema change that adds a model without updating the
frozen set. `test_action_set_is_frozen` enforces that set.

**Q10. How do you know the oracle that scores remediation isn't just your
collector again?**
Plain: it was written separately, inside the harness, before the collector
was fixed.
Technical: `evaluate.oracle_sshd` was committed at `7ba8438`, before the
collector fix at `f847481`. It was the oracle that *found* F1 and F2.

**Q11. Your held-out corpus was written by the same author as the gate.**
Plain: yes. It is held out in time, not in authorship, and that is stated as a
limitation.
Technical: the corpus was frozen and committed (`197e4d3`) before its first
run, and v2 gaps were not patched until after they were recorded. An
independent v3 is the recommended next step.

**Q12. Why does intent matter if you have the gates?**
Plain: the gates stop bad changes; intent decides what should be looked at
and what the model even sees.
Technical: INTENDED services are removed before any model call (37% smaller
prompts here), so the model cannot propose disabling a declared service and
the injection surface shrinks.

**Q13. Why is the LLM worth it, if the rules proposer fixed 100%?**
Plain: in this testbed it isn't, for remediation. Its value is explaining
services nobody declared.
Technical: the rules proposer covers the CIS mappings it was written for.
The LLM matters where there is no rule, which is also where the gate matters
most. That is the design point: the model's usefulness grows exactly where
trust in it must not.

**Q14. Why will your CIS score delta be much lower than OpenSCAP's?**
Plain: HardenCTL changes about 15 settings and OpenSCAP about 200, and
OpenSCAP has no undo.
Technical: the contribution is the safety envelope, not coverage. Compare on
score per broken service and on reversibility (see [02](02_baseline_comparison.md)).

**Q15. What happens if the model returns garbage?**
Plain: nothing runs.
Technical: `llm.parse_json` salvages complete objects from truncated output.
Every action then goes through the schema individually. A malformed action is
refused, and the rest of the plan is still judged on its own merits.

**Q16. Could an attacker change `intent.yaml` to mark their backdoor INTENDED?**
Plain: only if they can write to the operator's home directory, and then they
already own the operator.
Technical: out of scope (write access to the operator's state implies an
equal- or higher-privilege attacker). Intent affects only what is *reported
and explained*. It never lets a weakening action past gate 3.
