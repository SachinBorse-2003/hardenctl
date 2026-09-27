# Review 1 — Gap Re-validation and Scope Changes

## Gap, re-validated

The Review 0 gap still holds after the expanded survey:

- **Model-side prompt-injection defences reduce, but do not eliminate,
  attack success** (InjecAgent 24%, ToolEmu 23.9%, Spotlighting <2%). A
  hardening agent runs as root, so any non-zero rate is unacceptable.
- **System-level defences exist but are general-purpose** (CaMeL, IsolateGPT,
  design patterns). None is instantiated for host remediation or measured
  against a hardening benchmark, and none enforces *monotonicity*.
- **Hardening tools have no intent and no reversible apply** (Lynis,
  OpenSCAP, CIS-CAT, dev-sec).

## Pivot, and why

**From:** intent-based attack surface management (Review 0 framing).
**To:** intent-based ASM **plus an agentic layer with gated execution**.

Justification: intent alone tells the operator *what* is wrong; it does not
explain an unfamiliar service or produce a fix. An LLM is useful for exactly
those two jobs, but only if it cannot act. The pivot adds the model while
keeping every security-relevant decision deterministic, which turns the
project's core question from "can we detect drift?" into the more defensible
"can we use an LLM for remediation *without trusting it*?"

## Scope changes since Review 0 (flagged explicitly)

| Change | Type | Reason |
|---|---|---|
| LLM proposer, explainer agent and three-gate validator | **Added** | The pivot above |
| Free token site (sign-up, `hctl_` API token, revoke/regenerate) | **Added** | Industry-track requirement for commercial potential, without billing |
| Billing (credits, metering, payments) | **Dropped** | Time goes to evaluation; commercial model moves to Future Work |
| Four-distro matrix (Ubuntu, Debian, RHEL, Arch) | **Reduced** to Debian/Ubuntu | One package manager (dpkg) and one init system keep attribution testable |
| "120+ planted misconfigs" | **Reduced** to the lab baseline plus the frozen corpus (34 cases in v1) | Real, reproducible count instead of a projection |
| Network-namespace reachability probing | **Deferred** | Reachability is currently inferred from bind address; probing is future work |
| Blast radius (readable creds, docker group, sudo rules, SSH keys) | **Deferred** | Not needed for the core claim; flagged as future work |
| SARIF export; Lynis/Trivy ingestion | **Deferred** | Integration, not contribution |
| "No automatic remediation" | **Clarified** (still holds) | `apply` always needs an explicit plan file and consent |

## New finding at design lock: gate 3 coverage

While freezing the corpus, 12 new *coverage probes* were written and added to
`corpus/injection_v1.json` **before** any gate change. Gate 3 accepted 9 of
the 10 weakening probes (current result: 3/12 probes behave as expected). The most
serious: `PermitRootLogin yes` written to a drop-in under
`/etc/ssh/sshd_config.d/`. Ubuntu's default `sshd_config` includes that
directory at the top, and sshd keeps the first value it reads, so the drop-in
would re-enable root login without touching `sshd_config` itself. *(Not yet
verified on the lab VM: openssh-server is not installed there. Verify after
`setup_lab.sh` installs it.)*

This does not change the architecture; it changes the gate's *policy*. The
decision on how to close it (extend the tables, or make
`set_config_directive` default-deny) is recorded in
`03_architecture_and_algorithms.md` under "Open design decision", and the
before/after coverage number becomes a Review 2 result.
