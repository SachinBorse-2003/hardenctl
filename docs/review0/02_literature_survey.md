# Review 0 — Literature Survey

**Verification rule:** every row below was checked on 2026-09-26 against arXiv
(title and first author, via the abstract page) or Crossref (DOI). The venue
column says where that venue came from: **[C]** confirmed by Crossref,
**[A]** stated on the arXiv page, **[?]** from memory and *not yet confirmed*.
Confirm every [?] against the publisher before citing it in a report.

**Count:** 25 papers: 20 recent (2022 onward), **18 from 2023 onward**, plus
5 foundational/context papers; 2 standards; 6 tools.

## A. Prompt injection: attacks and benchmarks

| # | Reference | Year | Venue | Relevance to HardenCTL |
|---|---|---|---|---|
| 1 | K. Greshake, S. Abdelnabi, et al. "Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection." DOI 10.1145/3605764.3623985 | 2023 | ACM AISec '23 [C] | Defines indirect injection via retrieved data; our `sshd_config` comment attack is exactly this |
| 2 | F. Perez, I. Ribeiro. "Ignore Previous Prompt: Attack Techniques For Language Models." arXiv:2211.09527 | 2022 | NeurIPS ML Safety Workshop [A] | Early goal-hijacking taxonomy |
| 3 | Y. Liu, Y. Jia, et al. "Formalizing and Benchmarking Prompt Injection Attacks and Defenses." arXiv:2310.12815 | 2023 | USENIX Security 2024 [A] | Formal framework; shows prevention/detection defences are incomplete |
| 4 | Q. Zhan, Z. Liang, et al. "InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated LLM Agents." arXiv:2403.02691 | 2024 | Findings of ACL 2024 [A] | Tool-using agents are vulnerable to injected tool output: our threat model |
| 5 | E. Debenedetti, J. Zhang, et al. "AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents." arXiv:2406.13352 | 2024 | NeurIPS 2024 Datasets & Benchmarks [?] | Benchmark methodology (utility vs attack success) that our corpus mirrors |
| 6 | Y. Ruan, H. Dong, et al. "Identifying the Risks of LM Agents with an LM-Emulated Sandbox" (ToolEmu). arXiv:2309.15817 | 2023 | ICLR 2024 [?] | Catalogues risky agent actions; motivates a closed action set |

## B. Prompt-injection defences

| # | Reference | Year | Venue | Relevance / contrast |
|---|---|---|---|---|
| 7 | S. Chen, J. Piet, et al. "StruQ: Defending Against Prompt Injection with Structured Queries." arXiv:2402.06363 | 2024 | USENIX Security 2025 [A] | Model-side defence (fine-tuning). We need no fine-tuning (invariant 14) |
| 8 | K. Hines, G. Lopez, et al. "Defending Against Indirect Prompt Injection Attacks With Spotlighting." arXiv:2403.14720 | 2024 | arXiv preprint | Delimiting untrusted data; our `<untrusted_host_data>` tags. Defence in depth only |
| 9 | E. Wallace, K. Xiao, et al. "The Instruction Hierarchy: Training LLMs to Prioritize Privileged Instructions." arXiv:2404.13208 | 2024 | arXiv preprint | Model-side privilege ordering; not a guarantee |
| 10 | H. Inan, K. Upasani, et al. "Llama Guard: LLM-based Input-Output Safeguard for Human-AI Conversations." arXiv:2312.06674 | 2023 | arXiv preprint | Guardrail-model baseline: a second model judging the first. We use a table instead |
| 11 | T. Rebedea, R. Dinu, et al. "NeMo Guardrails: A Toolkit for Controllable and Safe LLM Applications with Programmable Rails." arXiv:2310.10501 | 2023 | EMNLP 2023 (Demo) [A] | Programmable rails around dialogue; not domain policy over privileged actions |
| 12 | E. Debenedetti, I. Shumailov, et al. "Defeating Prompt Injections by Design" (CaMeL). arXiv:2503.18813 | 2025 | arXiv preprint | Closest idea: system-level policy outside the model. We specialise it to host hardening with monotonicity |
| 13 | L. Beurer-Kellner, B. Buesser, et al. "Design Patterns for Securing LLM Agents against Prompt Injections." arXiv:2506.08837 | 2025 | arXiv preprint | Plan-then-execute and action-selector patterns; HardenCTL is an instance |
| 14 | Y. Wu, F. Roesner, et al. "IsolateGPT: An Execution Isolation Architecture for LLM-Based Agentic Systems." arXiv:2403.04960 | 2024 | NDSS 2025 [A] | Execution isolation for agents; complementary to our gating |

## C. LLM agents in offensive and systems security

| # | Reference | Year | Venue | Relevance |
|---|---|---|---|---|
| 15 | S. Yao, J. Zhao, et al. "ReAct: Synergizing Reasoning and Acting in Language Models." arXiv:2210.03629 | 2022 | ICLR 2023 [A] | The reason-act loop our proposer deliberately does *not* close (no execution) |
| 16 | G. Deng, Y. Liu, et al. "PentestGPT: An LLM-empowered Automatic Penetration Testing Tool." arXiv:2308.06782 | 2023 | USENIX Security 2024 [?] | Offensive counterpart; shows LLMs reason well about host state |
| 17 | A. Happe, J. Cito. "Getting pwn'd by AI: Penetration Testing with Large Language Models." DOI 10.1145/3611643.3613083 | 2023 | ESEC/FSE 2023 [C] | LLMs driving Linux commands; motivates bounding what they may run |
| 18 | A. Happe, A. Kaplan, et al. "LLMs as Hackers: Autonomous Linux Privilege Escalation Attacks." arXiv:2310.11409 | 2023 | arXiv preprint | Linux privesc by agents: the attacker side of blast radius |
| 19 | R. Fang, R. Bindu, et al. "LLM Agents can Autonomously Exploit One-day Vulnerabilities." arXiv:2404.08144 | 2024 | arXiv preprint | Raises urgency of closing known exposure quickly |
| 20 | X. Lian, Y. Chen, et al. "Configuration Validation with Large Language Models" (Ciri). arXiv:2310.09690 | 2023 | arXiv preprint | LLMs judging config files; reports hallucination, so we keep facts deterministic |

## D. Attack surface, configuration hardening, vulnerability prioritisation

| # | Reference | Year | Venue | Relevance |
|---|---|---|---|---|
| 21 | P. K. Manadhata, J. M. Wing. "An Attack Surface Metric." DOI 10.1109/TSE.2010.60 | 2011 | IEEE TSE [C] | Foundational definition of attack surface (entry points, channels) |
| 22 | A. Rahman, C. Parnin, L. Williams. "The Seven Sins: Security Smells in Infrastructure as Code Scripts." DOI 10.1109/ICSE.2019.00033 | 2019 | ICSE 2019 [C] | Hardening-as-code is itself error-prone |
| 23 | A. Rahman, et al. "Security Smells in Ansible and Chef Scripts." DOI 10.1145/3408897 | 2021 | ACM TOSEM [C] | Same, for the Ansible ecosystem that dev-sec hardening uses |
| 24 | J. Jacobs, S. Romanosky, et al. "Exploit Prediction Scoring System (EPSS)." DOI 10.1145/3436242 | 2021 | ACM DTRAP [C] | Prioritisation signal for planned OSV/KEV/EPSS enrichment |
| 25 | J. Jacobs, S. Romanosky, et al. "Enhancing Vulnerability Prioritization: Data-Driven Exploit Predictions with Community-Driven Insights." arXiv:2302.14172 | 2023 | arXiv preprint | EPSS v3 model |

Rows 21–25 fall outside the "last 3–5 years" window or are foundational; they
are context, not part of the 15–20 recent-paper count. **Recent (2022+) papers:
rows 1–20. From 2023 onward: 18 of them** (all except rows 2 and 15).

## E. Standards and grey literature

| Reference | Year | Use |
|---|---|---|
| D. Waltermire, et al. NIST SP 800-126 Rev. 3, "The Technical Specification for the Security Content Automation Protocol (SCAP) Version 1.3." DOI 10.6028/NIST.SP.800-126r3 [C] | 2018 | Basis for OpenSCAP scoring in evaluation |
| OWASP Top 10 for LLM Applications (2025 edition): prompt injection, excessive agency | 2024/25 | Threat categories we mitigate. *Confirm edition and URL before citing* |

## F. Tools and baselines (industry state of the art)

| Tool | Method | Metric it reports | Limitation relative to HardenCTL |
|---|---|---|---|
| Lynis | Local shell-based audit | Hardening index (0–100) | Audit only; no intent; no remediation |
| OpenSCAP + SCAP Security Guide (CIS Ubuntu profile) | XCCDF/OVAL rule evaluation; can generate remediation scripts | Rule pass/fail, score | Remediation is profile-wide shell/Ansible; no rollback; no intent |
| CIS-CAT | CIS benchmark assessor | Benchmark score | Assessment only; commercial Pro edition |
| dev-sec ansible-os-hardening | Idempotent Ansible role | None built in | Enforces a fixed profile; no measurement, attribution or rollback |
| osquery | SQL over host state | Query results | Excellent visibility; no intent verdicts or remediation |
| Trivy / Grype | Package and image vulnerability scanning | CVE list | Vulnerabilities, not exposure or config posture |

## Survey takeaway

Model-side defences (rows 7–11) lower injection success but none guarantees
it; system-level designs (rows 12–14) are general-purpose and not measured on
privileged host remediation. Hardening tools (section F) measure or enforce a
profile but have no intent and no reversible, per-change apply. HardenCTL sits
at the intersection: a deterministic policy (monotonicity gate) between the
model and root, driven by declared intent, with transactional rollback.
