# Review 1 — Risk Register

Likelihood (L) and impact (I): H / M / L.

| # | Risk | L | I | Mitigation | Status |
|---|---|---|---|---|---|
| R1 | **Gate 3 coverage gaps** let a weakening action through (9/10 weakening probes accepted today) | H | H | Close with design option C (default-deny config/sysctl + extended unit/package tables); measure on held-out corpus v2 | **open, top priority** |
| R2 | LLM output drift: invalid JSON, wrong fields, or truncated output | M | M | Schema gate; truncated-JSON salvage in `llm.py`; rules proposer fallback; plan validity is a metric | mitigated, to measure |
| R3 | Model API cost or availability | M | M | Rules proposer and Ollama need no key or network; LLM experiments run in small fixed batches | mitigated |
| R4 | Attribution failures (containers, short-lived PIDs, non-dpkg binaries) | M | M | Labelled ground-truth VM; report failures as error analysis | open |
| R5 | OpenSCAP has no maintained CIS profile for Ubuntu 24.04 | M | H | Check SCAP Security Guide releases early; fall back to the closest Ubuntu profile or Lynis index, and state the deviation | **check this week** |
| R6 | Service breakage on apply | M | H | Intent keeps declared services out of the model; dry run; transactional rollback; service preservation is a metric | mitigated, to measure |
| R7 | sysctl changes do not persist across reboot | H | M | P4: write `/etc/sysctl.d/99-hardenctl.conf` with rollback; until then, state it as a limitation | open |
| R8 | Token leakage (P5) | L | M | `hctl_` prefix for secret scanning, shown once, argon2-hashed, revocable | design only |
| R9 | Time overrun | M | H | Cut order: relay → rest of token site → enrichment. `hardenctl eval` is never cut | planned |
| R10 | Edits that silently fail to apply (seen in past sessions) | M | M | After every change: grep/import check and both test suites; commit only when green | process in place |
| R11 | Overclaiming at viva ("provably safe") | M | H | State the claim precisely: gates are a deny-list whose coverage is measured, not a proof | in docs |
| R12 | Lab VM damage (the VM also hosts the OT lab) | L | H | Snapshot before every weakening step; `setup_lab.sh --restore` | in place |
| R13 | Unverified citations | L | H | All rows checked against arXiv/Crossref; [?] venues confirmed before the report | 3 venues pending |
