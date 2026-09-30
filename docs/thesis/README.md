# Thesis — Chapter Outline

**Write the prose yourself.** This is a map of what each chapter must
contain, where the material already is, and which figures and tables to use.
Submitting generated text as your own is an academic-integrity problem, it
will fail an AI and plagiarism check, and you have to defend every sentence
at the viva anyway. Format (fonts, margins, front matter, citation style)
follows the KIIT template, which is not in this repo.

## Front matter
- Title: *HardenCTL: Intent-Based Attack Surface Management and Gated,
  Reversible LLM Remediation for Linux Hosts*
- Certificate, declaration, acknowledgements (institute templates)
- **Abstract (about 250 words).** Cover the problem (hardening agents read
  attacker-controlled data while holding root), the approach (intent, a
  fail-closed monotonicity gate, transactional rollback), the evaluation
  (seeded sandbox labs, held-out injection corpus, LLM runs, CIS baseline), and
  the headline numbers (35/44 → 5/44 held-out, 0/22 in fail-closed parts,
  0/438 ablation, 30/30 rollback, 37% prompt saving). End with the one-sentence
  contribution from `docs/final/06`.

## Chapter 1 — Introduction
- Motivation and problem: `docs/review0/01_problem_and_objectives.md`
- The OpenPLC example on the lab VM (a real, intended-but-public service)
- Objectives O1–O4 (SMART table), with their final status from `docs/final/09` S1–S6
- Contributions: the four points from `docs/final/06`
- Thesis organisation

## Chapter 2 — Literature Review
- Comparison table: `docs/review1/01_literature_comparison.md` (20 papers, 6 tools)
- Three themes: (a) prompt injection and agent attacks; (b) model-side vs
  system-level defences; (c) hardening and compliance tooling
- The gap, re-validated: `docs/review1/02_gap_and_scope_changes.md`
- **Before submission:** confirm the three venues marked [?] and read the full
  papers you cite, not just their abstracts

## Chapter 3 — Methodology
- Threat model, assets, adversaries A1–A4, trust boundary: `docs/review0/03`
- Architecture diagram: `docs/review1/03` (Mermaid; export to an image)
- Design choices with rejected alternatives: `docs/review1/03`
- **New since Review 1:** gate v2 fail-closed ordering rules (the policy table
  in `hardenctl/validator.py`, docstring "Gate v2"). Formalise monotonicity as a
  partial order per setting type (enum, integer ceiling/floor, algorithm set,
  mode-bit subset)
- Evaluation design: metrics, datasets, split (v1 development, v2 held-out),
  sandbox, independent oracle, statistics (Wilson, bootstrap, rule of three):
  `docs/review1/04` and the `hardenctl/evaluate.py` module docstring
- Scope changes since Review 0: `docs/review1/02`

## Chapter 4 — Implementation
- Module map (one paragraph each): collectors, intent, hardener, validator,
  executor, explain, llm, evaluate, cli
- sshd resolution (Include, case, first value, Match), with a figure of the
  drop-in override (F2)
- Transactional apply: inverse capture, first-touch backup, absent markers,
  sysctl persistence, `sshd -t`
- Testing: 25 pytest tests, CI, frozen corpora with checksums
- Figure: one real `hardenctl scan` table and one `plan` table from the VM

## Chapter 5 — Results and Discussion
- Everything in `docs/final/01_results.md`, as tables plus 3 figures:
  1. Bar chart: held-out weakening reaching apply, gates v1 / v2 / v2.1, per category
  2. Before/after bar chart: remediation effectiveness and DRIFT detection, v0.1 vs release
  3. The CIS score table from `docs/final/02` section B (after you run it)
- Error analysis: `docs/final/03` (pick the 5 most instructive: F2, F3, F5, F7, F9)
- Robustness and evasion: `docs/final/04`
- Discussion: why fail-closed beat deny-list; why the LLM adds little for
  remediation here but matters exactly where the gate matters most (viva Q13)

## Chapter 6 — Conclusion and Future Work
- Contribution restated with numbers: `docs/final/06`
- Limitations: `docs/final/05` (all 14; do not trim the uncomfortable ones)
- Future work: `docs/final/10`

## References
- Only sources you have read. Every entry is verified against the publisher
  (Crossref or the venue's site); arXiv-only entries are labelled as preprints.

## Appendices
- A: action schema (six types) and the gate policy tables
- B: corpus v1/v2 case lists (generated from the JSON)
- C: how to reproduce (`docs/final/07`)
