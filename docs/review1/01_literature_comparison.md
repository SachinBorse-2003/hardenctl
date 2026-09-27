# Review 1 — Literature Comparison Table

Expanded from `docs/review0/02_literature_survey.md`. Numbers in the
**Dataset** and **Metric / result** columns are quoted from each paper's
arXiv abstract (fetched 2026-09-26). "—" means the abstract gives no number;
check the full paper before adding one. Venue tags: [C] Crossref, [A] arXiv
page, [?] unconfirmed.

## Research papers

| # | Paper (year, venue) | Method | Dataset / testbed | Metric / result | Limitation w.r.t. HardenCTL |
|---|---|---|---|---|---|
| 1 | Greshake et al. (2023, AISec [C]) | Indirect prompt injection via retrieved data; attack taxonomy | Bing Chat (GPT-4), code-completion engines, synthetic GPT-4 apps | Qualitative demonstrations; states effective mitigations are lacking | Attack paper; no defence for privileged actions |
| 2 | Perez & Ribeiro (2022, NeurIPS MLSW [A]) | PromptInject: iterative adversarial prompt composition | GPT-3 | Goal hijacking and prompt leaking shown | Direct injection only; no agents or tools |
| 3 | Liu et al. (2023, USENIX Sec '24 [A]) | Formal framework for prompt injection; new combined attack | 5 attacks × 10 defences × 10 LLMs × 7 tasks | Benchmark (Open-Prompt-Injection) | Text tasks, not tool actions; defences remain model-side |
| 4 | Zhan et al. (2024, ACL Findings [A]) | InjecAgent benchmark for indirect injection in tool agents | 1,054 cases, 17 user tools, 62 attacker tools, 30 agents | ReAct GPT-4 vulnerable 24% of the time; ~2× with a hacking prompt | Measures vulnerability; proposes no enforcement layer |
| 5 | Debenedetti et al. (2024, NeurIPS D&B [?]) | AgentDojo: extensible environment for attacks and defences | 97 tasks, 629 security test cases | Utility and attack success; LLMs fail many tasks even unattacked | General-purpose domains (email, banking, travel); no root actions |
| 6 | Ruan et al. (2023, ICLR '24 [?]) | ToolEmu: LM-emulated tools plus LM safety evaluator | 36 high-stakes tools, 144 cases | 68.8% of flagged failures valid; safest agent fails 23.9% | Evaluator is itself an LM; detection, not prevention |
| 7 | Chen et al. (2024, USENIX Sec '25 [A]) | StruQ: separate prompt/data channels plus fine-tuned model | Augmented instruction-tuning data | "Significantly improves" injection resistance, little utility loss | Needs fine-tuning (excluded by invariant 14); probabilistic |
| 8 | Hines et al. (2024, arXiv) | Spotlighting: input transformations marking provenance | GPT-family models | ASR from >50% to <2% | Still probabilistic; <2% ≠ 0% when the action is root-level |
| 9 | Wallace et al. (2024, arXiv) | Instruction hierarchy via synthetic training data | GPT-3.5 | "Drastically" increased robustness | Model-side training; not available for arbitrary providers |
| 10 | Inan et al. (2023, arXiv) | Llama Guard: Llama2-7B safety classifier | OpenAI Moderation, ToxicChat | Matches or beats moderation tools | Content-safety taxonomy, not host-security semantics |
| 11 | Rebedea et al. (2023, EMNLP Demo [A]) | NeMo Guardrails: programmable dialogue rails | — | Initial results only | Dialogue control; no domain policy over system actions |
| 12 | Debenedetti et al. (2025, arXiv) | CaMeL: control/data-flow extraction plus capability policies | AgentDojo | 77% of tasks solved with provable security (84% undefended) | General framework; no monotonicity notion for hardening |
| 13 | Beurer-Kellner et al. (2025, arXiv) | Design patterns for provable injection resistance | Case studies | Qualitative trade-off analysis | Patterns only; HardenCTL is a measured instance of plan-then-execute |
| 14 | Wu et al. (2024, NDSS '25 [A]) | IsolateGPT: execution isolation between LLM apps | Attack scenarios on LLM app ecosystems | <30% overhead for ¾ of queries | Isolates apps from each other; does not bound what an allowed action does |
| 15 | Yao et al. (2022, ICLR '23 [A]) | ReAct: interleaved reasoning and acting | QA and interactive decision benchmarks | — (task success) | The loop HardenCTL deliberately breaks: the model never acts |
| 16 | Deng et al. (2023, USENIX Sec '24 [?]) | PentestGPT: three-module LLM pentest tool | Benchmark of test machines | +228.6% task completion vs GPT-3.5 | Offensive; operator executes commands |
| 17 | Happe & Cito (2023, ESEC/FSE [C]) | LLM as a pentest sparring partner, executing commands | Vulnerable Linux VM | Qualitative | Offensive; unbounded shell |
| 18 | Happe et al. (2023, arXiv) | hackingBuddyGPT: autonomous Linux privilege escalation | Public Linux privesc benchmark | GPT-4-Turbo exploits 33–83% (humans 75%) | Offensive; shows the blast-radius side of misconfiguration |
| 19 | Fang et al. (2024, arXiv) | GPT-4 agent exploiting one-day CVEs | 15 one-day vulnerabilities | 87% with CVE text, 7% without | Offensive; motivates fast closure of known exposure |
| 20 | Lian et al. (2023, arXiv) | Ciri: LLM few-shot configuration validation | Configs of 10 open-source systems, 8 LLMs | Feasible, but misses some misconfig types, biased to popular params | Model judges facts: exactly what HardenCTL keeps deterministic |

## Tools and industry baselines

| Tool | Method | Data it uses | Metric | Limitation w.r.t. HardenCTL |
|---|---|---|---|---|
| Lynis | Shell-based local audit | Local host | Hardening index 0–100 | No intent, no remediation |
| OpenSCAP + SCAP Security Guide | XCCDF/OVAL evaluation; generates remediation scripts | CIS / STIG profiles | Rule pass/fail, score | Profile-wide remediation; no rollback; no intent |
| CIS-CAT | Benchmark assessment | CIS benchmarks | Score | Assessment only |
| dev-sec ansible-os-hardening | Idempotent Ansible role | Fixed hardening profile | None built in | No measurement, attribution or rollback |
| osquery | SQL over host state | Local host | Query results | Visibility only |
| Trivy / Grype | Vulnerability scanning | Package/image SBOMs | CVE list | Vulnerabilities, not exposure or config |

## What the table shows

1. **Measured injection success never reaches zero** with model-side defences
   (rows 4, 6, 8). For a text summariser that is acceptable; for an agent
   holding root it is not.
2. **The strongest defences are system-level** (rows 12–14), not model-level.
   HardenCTL applies this idea to host hardening and adds a property those
   papers do not have: *monotonicity* (a plan can never make the host weaker).
3. **Hardening tools lack intent and reversibility.** None of the six tools
   distinguishes intended from drifted exposure, and none offers per-change
   transactional rollback.
