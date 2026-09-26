# Review 0 — Problem, Motivation, Gap, Novelty, Objectives

## Title

**HardenCTL: Intent-Based Attack Surface Management and Agentic, Rollback-Safe
Remediation for Linux Hosts**

## Problem statement

Linux hosts expose services that nobody explicitly decided to expose, and
existing hardening tools can report or blindly enforce a benchmark but cannot
tell *intended* exposure from *drift*, nor fix the gap without risking the
services the host exists to run. HardenCTL lets an operator declare what a
host should expose, measures what it actually exposes, and closes the gap with
reversible changes that a language model may propose but can never execute.

## Motivation

- **Who it affects.** Small teams, labs and OT/edge operators who run Linux
  hosts without a dedicated security engineer. A typical example is this
  project's own lab VM, which runs OpenPLC on `0.0.0.0:8080/8443`: one tool
  says "port open", another says "CIS fail", but neither can say whether that
  exposure was *meant*.
- **Why benchmarks alone fall short.** CIS/SCAP tooling (Lynis, OpenSCAP,
  CIS-CAT) scores a host against a generic profile. It has no notion of this
  host's purpose, so its findings are either ignored as noise or remediated
  wholesale, and wholesale remediation breaks services.
- **Why an LLM is tempting, and dangerous.** LLM agents are good at explaining
  an unfamiliar service and ranking fixes, but a hardening agent reads
  attacker-controllable host data (config comments, banners, process names).
  Indirect prompt injection (Greshake et al., 2023) means a persuaded agent
  with root could *weaken* the host it was asked to protect. OWASP's LLM Top 10
  lists both prompt injection and excessive agency for this reason.
- **Why reversibility matters.** Operators do not run remediation they cannot
  undo. A transactional apply with byte-exact rollback removes the main
  reason hardening gets postponed.

## Gap (and why it matters)

| Existing work does | What is missing | Why it matters |
|---|---|---|
| Benchmark scanners score against a fixed profile (Lynis, OpenSCAP, CIS-CAT) | No per-host declaration of *intended* exposure; no DRIFT/FORBIDDEN/NEW distinction | Without intent, every open port is either noise or a blind fix |
| IaC hardening roles (dev-sec) enforce a profile | No measurement of what is actually listening, no attribution to process/package, no per-change rollback | Enforcement without measurement breaks services silently |
| Prompt-injection defences mostly make the *model* more robust (StruQ, Spotlighting, instruction hierarchy, guardrail models) | Few systems put a deterministic, domain-specific policy between the model and a privileged action | A defence that depends on the model resisting persuasion fails the first time it doesn't |
| System-level agent defences (CaMeL, IsolateGPT, design patterns) are general-purpose | No instantiation for root-level host remediation with a *monotonicity* (never-weaken) property | Host hardening is exactly the high-privilege case those papers warn about |
| LLM security agents (PentestGPT, LLM privilege-escalation work) are offensive | Defensive, remediating agents with measured safety guarantees are rare | The defensive side needs the same autonomy, with bounds |

## Novelty / contribution

HardenCTL combines three ideas that existing tools keep separate:

1. **Intent as a first-class, deterministic input.** `intent.yaml` plus six
   deterministic verdicts (INTENDED, DRIFT, FORBIDDEN, NEW, UNDECLARED,
   MISSING). INTENDED services never reach the model, so model effort (and
   cost) is spent only on what nobody declared.
2. **"The model proposes, it never executes."** The model emits a JSON plan
   over a closed set of six action types (there is no shell action). Three
   gates (schema, allowlist, table-driven *monotonicity*) decide what runs.
   The validator never reads the model's justification, so a persuaded model
   still cannot weaken the host.
3. **Transactional, reversible apply.** The inverse of each change is captured
   from live state before it runs, files are backed up on first touch, and any
   failure reverts the whole run. Rollback is byte-exact.

The contribution is the **combination and its measurement**: a working tool,
a frozen injection corpus, and numbers (hardening delta, service preservation,
rollback fidelity, injection resistance) against standard baselines.

## SMART objectives

| # | Objective | Measure | Target | By |
|---|---|---|---|---|
| O1 | Build a deterministic intent engine that classifies every listening socket against a declared `intent.yaml` | Detection rate and false positives on seeded scenarios (loopback→public drift, forbidden port opened, new listener) | 100% of seeded scenarios detected, 0 false positives on the unchanged baseline | Review 2 |
| O2 | Build gated agentic remediation: an LLM proposer constrained to 6 action types behind 3 deterministic gates | (a) % of LLM actions passing all gates; (b) % of frozen-corpus injection payloads that reach `apply` | (a) ≥ 98%; (b) **0%** | Review 2 |
| O3 | Make every change transactional and reversible without breaking intended services | (a) Rollback fidelity: hash of touched files and sysctl values before vs after rollback; (b) intended services still healthy after apply | (a) 100% over ≥ 30 runs; (b) ≥ 95% across the service configs | Review 2 |
| O4 | Show measurable hardening against standard baselines | OpenSCAP CIS Level 1 Server score before/after, for HardenCTL (rules, LLM), dev-sec ansible-os-hardening and OpenSCAP's own remediation; ≥ 5 runs each | Rules proposer ≥ +25 points; comparison table with confidence intervals | Final |

Supporting measure (reported, no target): socket → package attribution
accuracy against a labelled ground-truth VM (goal ≥ 95%), and model tokens
saved by skipping INTENDED services.
