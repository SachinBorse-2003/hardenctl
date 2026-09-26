# Review 0 — Tentative Timeline

> **Dates are tentative.** The Review 0 deck listed Review 1 in Nov 2026 and
> Review 2 in Feb 2027; the Final date is not fixed yet. Update this file when
> the department confirms the schedule.

```mermaid
gantt
    title HardenCTL — M.Tech project timeline (tentative)
    dateFormat  YYYY-MM-DD
    axisFormat  %b %Y

    section Review 0
    Topic, survey, threat model          :done,    r0a, 2026-08-01, 2026-09-15
    MVP v0.1.0 (intent, gates, rollback) :done,    r0b, 2026-08-15, 2026-09-26
    Review 0                             :milestone, m0, 2026-09-15, 0d

    section Review 1 (design lock)
    Repo, README, runbook refresh        :active,  r1a, 2026-09-27, 7d
    Literature comparison table          :         r1b, after r1a, 14d
    Architecture, metrics, baselines     :         r1c, after r1a, 14d
    Freeze action set + injection corpus :         r1d, after r1c, 5d
    Testbed plan, risk register          :         r1e, after r1c, 7d
    Buffer                               :         r1f, after r1e, 7d
    Review 1                             :milestone, m1, 2026-11-15, 0d

    section Review 2 (results)
    hardenctl eval + OpenSCAP automation :         r2a, 2026-11-16, 21d
    Ground-truth VM, service configs     :         r2b, 2026-11-16, 21d
    First runs vs baselines              :         r2c, after r2a, 14d
    sysctl persistence, LLM path, pytest :         r2d, after r2a, 14d
    OSV / KEV / EPSS enrichment          :         r2e, after r2c, 10d
    Token site (no billing)              :         r2f, after r2c, 14d
    Error analysis, report draft         :         r2g, after r2e, 10d
    Buffer                               :         r2h, after r2g, 7d
    Review 2                             :milestone, m2, 2027-02-15, 0d

    section Final
    Repeated runs, CIs, robustness tests :         f1, 2027-02-16, 21d
    Paper writing and submission         :         f2, 2027-02-16, 35d
    Thesis, plagiarism check             :         f3, after f1, 21d
    Buffer                               :         f4, after f3, 10d
    Final review                         :milestone, mf, 2027-04-30, 0d
```

## Milestone summary

| Milestone | Tentative date | Exit criterion |
|---|---|---|
| Review 0 | Sep 2026 (held) | Topic approved; MVP working |
| Review 1 | Nov 2026 | Design locked: action set and injection corpus frozen; metrics and baselines defined |
| Review 2 | Feb 2027 | `hardenctl eval` produces real numbers vs at least one baseline; live demo |
| Final | Apr–May 2027 | Repeated runs with CIs, 2–3 baselines, thesis, paper submitted |

**Cut order if time runs short:** token-site relay → rest of token site →
enrichment. Evaluation (`hardenctl eval`) is never cut.
