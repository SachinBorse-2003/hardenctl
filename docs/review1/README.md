# Review 1 — Literature Survey + Design / Methodology

| Checklist item (M.Tech guidelines 2026) | Where | Status |
|---|---|---|
| Literature survey as a comparison table (method, dataset, metric, limitation, year) | [01](01_literature_comparison.md) | done: 20 papers + 6 tools |
| Gap re-validated; pivot justified | [02](02_gap_and_scope_changes.md) | done |
| Detailed architecture diagram | [03](03_architecture_and_algorithms.md#system-architecture) | done (Mermaid) |
| Algorithms selected with justification | [03](03_architecture_and_algorithms.md#algorithm-and-design-choices-with-the-alternatives-rejected) | done; one open decision (gate 3 coverage) |
| Dataset finalised: source, size, preprocessing, split | [04](04_evaluation_design.md#dataset-and-testbed) | done; corpus v1 frozen |
| Evaluation metrics defined upfront | [04](04_evaluation_design.md#metrics-defined-upfront) | done |
| Baselines identified | [04](04_evaluation_design.md#baselines) | done |
| Tools, frameworks, hardware finalised | [04](04_evaluation_design.md#tools-libraries-hardware) | done; OpenSCAP, Ansible, Lynis, Ollama still to install |
| CyberSec testbed plan; ethical clearance | [04](04_evaluation_design.md#testbed-plan-and-ethical-clearance) | done; guide sign-off pending |
| Risk register | [05](05_risk_register.md) | done |
| Publication plan (tentative) | [06](06_publication_plan.md) | done; CFPs to verify |
| Updated timeline with buffer for Review 2 | [Review 0 Gantt](../review0/04_timeline.md) + below | done |

## Freeze record

| Item | Frozen as | Enforced by |
|---|---|---|
| Action set (6 types) | `ALLOWED_ACTIONS` in `hardenctl/schema.py` | `test_injection.py` fails if it changes |
| Injection corpus v1 | `corpus/injection_v1.json` (34 cases) | SHA-256 in `corpus/SHA256SUMS`, checked by `test_injection.py` |

Test status at freeze (on the lab VM): regression **22/22**, coverage probes
**3/12**, `test_e2e.py` rollback **byte-exact**.

## Timeline update (weeks to Review 2)

| Weeks | Work | Buffer |
|---|---|---|
| 1–2 | Close gate 3 gap (decision C); install OpenSCAP, Ansible, Lynis, Ollama; confirm the Ubuntu 24.04 CIS profile | |
| 3–5 | `hardenctl eval`; ground-truth VM; service configs; held-out corpus v2 | |
| 6–7 | First runs: rules vs LLM vs OpenSCAP vs dev-sec; sysctl persistence | |
| 8 | Error analysis (≥ 3 real failures), abstract + methodology draft | 1 week |
| 9–10 | Token site (cut first if late) | 1 week |

## Sign-off

| Field | Value |
|---|---|
| Review 1 date | [ ] |
| Guide sign-off on testbed plan | [ ] |
| Panel feedback | [ ] |
