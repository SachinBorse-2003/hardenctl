# Paper — Outline (6–8 pages, workshop format)

**Working title:** *"The Model Proposes, It Never Executes": Fail-Closed
Monotonicity Gates for LLM-Driven Host Hardening*

**Venue:** choose with your guide. Candidates are in
`docs/review1/06_publication_plan.md` (AISec at CCS, ICISS, an LLM/agent
security workshop). **Check the live CFP for page limits and deadlines;
nothing here was verified against a 2027 CFP.** Post an arXiv preprint
alongside the submission. Write the text yourself.

1. **Introduction.** A root-level agent reads attacker-controlled host data.
   Model-side defences leave a non-zero residual rate, and for root actions
   that is unacceptable. Our approach: a deterministic gate over a closed
   action set that enforces "never weaker".
2. **Threat model.** A2 (host-data writer) and A3 (manipulated model); root
   attackers out of scope.
3. **Design.** Intent filter; six typed actions; schema → allowlist →
   monotonicity; the ordering rules (enum, integer bounds against disk,
   algorithm sets, mode subsets); fail-closed by default; transactional apply.
4. **Evaluation.**
   - Setup: sandbox harness, seeds, independent oracle, frozen corpora
   - RQ1, injection resistance: v1 vs v2 on held-out v2 (35/44 → 5/44);
     per-category table; 0/438 ablation
   - RQ2, reversibility: 30/30 rollback, 30/30 auto-revert
   - RQ3, utility: rules 100% vs LLM 95.4%; gate refusals of model errors
     (F9); CIS delta vs OpenSCAP and dev-sec (from the VM run)
   - RQ4, cost: 37% prompt saved by intent
5. **Lessons.** Deny-lists leak and fail-closed components did not; "set it
   to the CIS value" is not monotone; the model's claims about current state
   must not be trusted.
6. **Limitations.** Same-author held-out set; synthetic labs; one model;
   narrow coverage.
7. **Related work.** Condensed from the literature table; position against
   CaMeL, IsolateGPT and the design-patterns paper (these bound *which*
   actions run, we bound *what an allowed action may do*).
8. **Conclusion.**

**Artefact:** the repository, `hardenctl eval`, both corpora and `results/`,
which fits an artefact-evaluation badge if the venue offers one.
