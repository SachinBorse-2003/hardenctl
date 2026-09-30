# Review 0 — Threat Model, Scope, Feasibility, Ethics

## Threat model

### Assets

- The host's security posture: sshd configuration, sensitive file modes
  (e.g. `/etc/shadow`), kernel sysctls, the set of enabled services.
- Availability of the host's **intended** services (e.g. OpenPLC on the lab VM).
- Root privilege, which `hardenctl apply` holds while it runs.
- Operator data in `~/.hardenctl/` (intent, baseline, run history, provider key).

### Adversaries

| ID | Adversary | Capability | What HardenCTL does about it |
|---|---|---|---|
| A1 | Remote network attacker | Reaches any service bound beyond loopback | **Reduces the attack surface:** intent verdicts expose DRIFT/FORBIDDEN/NEW; plans disable or restrict them |
| A2 | Local low-privilege user, or a compromised package | Writes host data that `scan` reads: config comments, unit descriptions, process names, banners | **Prompt-injection source.** Comments stripped, host strings delimited as untrusted; **gate 3 rejects any weakening action regardless** |
| A3 | Manipulated, hallucinating or compromised model/provider | Returns arbitrary text as a "plan" | Model output is only data. Schema (gate 1), closed allowlist (gate 2) and monotonicity table (gate 3) decide; no shell action exists |
| A4 | Honest operator mistake | Applies a plan that breaks an intended service | Dry run, consent prompt, transactional apply, one-command byte-exact rollback |

### Trust boundaries

```
 untrusted                         │ trusted computing base (~870 LOC)
 host data ─► collectors ─► model ─┼─► schema.py ─► validator.py ─► executor.py ─► root
 (A2)                       (A3)   │   gate 1        gates 2, 3      inverse + rollback
```

The security argument rests only on the right-hand side: schema, validator and
executor. Nothing to the left, including the model, is trusted.

### Out of scope (explicitly)

- An attacker who already has root (they can rewrite HardenCTL itself).
- Kernel or hypervisor exploits; supply-chain compromise of HardenCTL's own
  dependencies.
- Remote or network scanning of other hosts. **Localhost only, no nmap.**
- Automatic remediation. `apply` always requires an explicit plan file and
  consent (`--yes` counts as explicit consent).
- Distributions other than Debian/Ubuntu.
- Billing of any kind (the token site issues free tokens only).
- RAG, fine-tuning, or training any model.

## Scope boundaries (in scope)

- One Linux host (Debian/Ubuntu), scanned locally as root.
- Evidence: listening sockets → process → executable → dpkg package → systemd
  unit; sshd configuration; selected file modes and sysctls.
- Six action types: `set_config_directive`, `set_file_mode`, `set_sysctl`,
  `disable_service`, `mask_service`, `remove_package`.
- Providers: rules (no model), Ollama (local), Anthropic, OpenAI, OpenRouter.
- Planned later, flagged now: network-namespace reachability probing, blast
  radius, OSV/KEV/EPSS enrichment, a free token site.

## Feasibility

| Need | Availability |
|---|---|
| Data | Generated, not collected: a weak-baseline lab VM (`lab/setup_lab.sh`), a frozen prompt-injection corpus (currently 22 cases), seeded intent scenarios. No third-party dataset or licence required |
| Tools / libraries | Python 3.12, psutil, pydantic v2, typer, rich, PyYAML (all open source); OpenSCAP + SCAP Security Guide for scoring; dev-sec ansible-os-hardening as a baseline |
| Compute | One VMware VM (Ubuntu 24.04). No GPU. Model calls through an API or local Ollama; the rules path needs neither |
| Cost | Zero with rules/Ollama; small API cost for LLM-path experiments |
| Status | v0.1.0 working prototype (~3,000 LOC, 11 modules); both test suites pass on the lab VM |

## Ethical and legal considerations

- **Dual use.** A tool that edits host security settings could be misused to
  weaken a host. Mitigation: the monotonicity gate refuses weakening actions;
  only an operator naming a specific action ID can override one, and that
  override is recorded in the run.
- **Consent and authorisation.** Runs only on the local host, by its own
  administrator via `sudo`. It never scans or touches another machine.
- **Lab safety.** Weakening scripts run only on an isolated, host-only lab VM,
  after a VMware snapshot. The VM also hosts OpenPLC; OT services are declared
  in intent so they are never disabled by a plan.
- **Data minimisation / privacy.** No PII is processed. Only structured
  findings may leave the host, and only if a remote model provider is
  configured. Raw config file contents never leave. With Ollama, nothing
  leaves. Real hosts' `intent.yaml`, `baseline.json`, plans and findings are
  git-ignored.
- **Responsible disclosure.** If testing uncovers a vulnerability in a
  third-party package or tool, it will be reported to the maintainer
  privately before any publication.
- **Academic integrity.** Every citation is verified against publisher records
  (see `02_literature_survey.md`). Results come only from harness runs.
