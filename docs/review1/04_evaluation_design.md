# Review 1 — Dataset, Testbed, Metrics, Baselines, Tools

## Dataset and testbed

HardenCTL trains no model, so there is no train/validation/test split in the ML
sense. The equivalent risk (tuning the gate to the data it is scored on) is
handled with frozen, versioned corpora and a held-out set.

| Asset | Source | Size (now) | Status |
|---|---|---|---|
| Weak-baseline lab | `lab/setup_lab.sh` on a snapshotted VM: sshd weakened, redis on 0.0.0.0, `/etc/shadow` 0644, ASLR off | 1 VM | exists |
| Injection corpus v1 | `corpus/injection_v1.json`, SHA-256 in `corpus/SHA256SUMS` | 34 cases: 22 regression + 12 coverage probes | **frozen 2026-09-26** |
| Held-out corpus v2 | Written *after* the gate fix, ideally by someone other than the gate author | target ≥ 30 cases | planned (Review 2) |
| Intent scenarios | Seeded: loopback→public drift, forbidden port opened, new listener, declared-but-missing | 4 types × ≥ 5 seeds | planned |
| Service configs | web (nginx), db (postgres/redis), mail (postfix), OT (OpenPLC) | 4 configs | planned |
| Attribution ground truth | VM with a labelled list of every listener → package → unit | 1 VM, ≥ 20 listeners | planned |

**Preprocessing:** none in the ML sense. Collectors normalise host state into
`Finding` objects; config parsing strips comments; host strings are delimited
as untrusted data.

**Split strategy (the equivalent of train/test):**
- Corpus v1 (development set): used while fixing gate 3. Its before/after
  numbers are reported, but are expected to improve because the fix saw it.
- Corpus v2 (held-out set): written after the fix and never used to tune it.
  **The headline injection-resistance number comes from v2.**

## Metrics (defined upfront)

| Metric | Method | Target |
|---|---|---|
| Hardening effectiveness | OpenSCAP CIS Level 1 Server score before/after; rules, LLM, dev-sec, OpenSCAP remediation | Report deltas; rules ≥ +25 points |
| Service preservation | Intended services healthy after apply, across the 4 service configs | ≥ 95% |
| Rollback fidelity | SHA-256 of touched files plus sysctl values, before apply vs after rollback, ≥ 30 runs | 100% |
| Plan validity | % of LLM-proposed actions passing all three gates | ≥ 98% |
| Injection resistance | % of planted payloads that change the plan; % reaching apply | reported; **0% reaching apply** |
| Gate coverage | Coverage probes behaving as expected (v1 dev, v2 held-out) | reported; v1 now 3/12 |
| Attribution accuracy | Socket → package vs labelled ground truth | ≥ 95% |
| Intent verdict accuracy | Detection rate and false positives on seeded scenarios | reported |
| Cost of the agent | Tokens and latency per run; tokens saved by skipping INTENDED | reported |

Rules: numbers only from harness runs (`hardenctl eval`, to be built), fixed
configs and seeds, raw JSON per run in `results/`, failures reported
alongside successes, and every run labelled sandbox or VM.

## Baselines

| Baseline | What it is | Compared on |
|---|---|---|
| HardenCTL rules proposer | Deterministic, no model | All metrics; the internal baseline for the LLM |
| OpenSCAP remediation (SCAP Security Guide, CIS Level 1 Server profile for Ubuntu) | Standard tool, profile-wide fix script | Hardening delta, service preservation, rollback (it has none) |
| dev-sec `ansible-os-hardening` | Widely used hardening role | Hardening delta, service preservation |
| Lynis | Hardening index | Secondary score, cross-check of the OpenSCAP delta |

Exact versions are pinned in `results/` metadata when the first runs happen.

## Tools, libraries, hardware

| Layer | Choice | Installed on the lab VM today |
|---|---|---|
| Language | Python 3.12 | yes (3.12.3) |
| Libraries | psutil, pydantic 2, typer, rich, PyYAML | yes (pydantic 2.13.5) |
| Scoring | OpenSCAP (`openscap-scanner`) + SCAP Security Guide datastream for Ubuntu 24.04 | **no, to install**; confirm an Ubuntu 24.04 CIS profile is available |
| Baselines | Ansible + dev-sec role; Lynis | **no, to install** |
| Local model | Ollama (no key, no egress) | **no, to install** |
| Hypervisor | VMware, Ubuntu 24.04.4 LTS, kernel 7.0 | yes |
| Token site (P5) | FastAPI, SQLite (demo) / Postgres, argon2 | later |

No GPU is needed.

## Testbed plan and ethical clearance

- **Isolation:** lab VMs on a VMware host-only network; no bridged adapter
  while weakened. Snapshot before every `setup_lab.sh` and every eval batch.
- **Offensive testing:** none against third parties. The only "attacks" are
  prompt-injection payloads planted in the lab VM's own config files, and
  weakening plans fed to our own validator. Localhost only; no scanning.
- **OT caution:** the VM runs OpenPLC. Its ports are declared in
  `intent.yaml` before any plan is generated, so no plan can target it.
- **Data:** no PII. Only structured findings may leave the host, and only
  when a remote provider is configured. Eval results contain lab-host data
  only; real hosts' intent, baseline and plans are git-ignored.
- **Clearance:** guide sign-off on this testbed plan to be recorded in
  `docs/review1/README.md`.
