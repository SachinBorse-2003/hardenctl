# Final — Reproducibility

The checklist question: *can another person re-run the pipeline from the
repo?* Yes. For the sandboxed results they need no root, no VM and no API key.

## 1. Every sandboxed number (any Ubuntu/Debian machine, about 1 minute)

```bash
git clone https://github.com/SachinBorse-2003/hardenctl && cd hardenctl
git checkout f636c6f                     # the release commit behind results/*v1.0-release*
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
pip install --no-deps -e .
python -m pytest -q                      # 36 tests
hardenctl eval --runs 30 --seed 1        # writes results/<timestamp>-*.json
```

Same seed, same code, same numbers: the labs, intent hosts and corpora are
deterministic. Only `timestamp`, `wall_s` and the temporary path names
differ. Compare a new `*-summary.json` with `results/20260930-225748-v1.0-release-summary.json`.

## 2. The LLM suite (needs a model provider)

```bash
hardenctl configure                      # Anthropic, OpenAI, OpenRouter or Ollama
hardenctl eval -s llm --llm-runs 10
```

This is not bit-reproducible: model output varies between calls. Report it as
a distribution with its interval, as in `01_results.md`.

## 3. The CIS scoring and baselines (lab VM, root, snapshots)

See [02, section B](02_baseline_comparison.md#how-to-fill-section-b-on-the-vm-as-root).
SCAP content is pinned (SSG 0.1.82) and checksum-verified by the script.

## 4. The pre-fix numbers

```bash
git worktree add ../hardenctl-v01 7ba8438
cd ../hardenctl-v01 && PYTHONPATH=. python3 -c \
  "from hardenctl import evaluate; evaluate.run(['injection','rollback','transactional','intent','cost'])"
```

## What a second person should check (the reproducibility test)

| Step | Expected |
|---|---|
| `sha256sum -c corpus/SHA256SUMS` | both corpora OK |
| `python -m pytest -q` | 36 passed |
| `hardenctl eval --runs 30 --seed 1` | the headline table in `01_results.md` |
| CI on GitHub (`.github/workflows/ci.yml`) | green on push |

Record who ran it, on what machine, and the date in
[09_feedback_tracker.md](09_feedback_tracker.md). The checklist asks whether
*another person* can do it, so it has to be someone other than you.
