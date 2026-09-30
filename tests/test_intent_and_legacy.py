"""Intent verdicts on seeded hosts, and the original test scripts."""

import subprocess
import sys
from pathlib import Path

import pytest

from hardenctl import evaluate

REPO = Path(__file__).resolve().parent.parent


def test_seeded_intent_scenarios():
    _, s = evaluate.suite_intent({"runs": 10, "seed": 5})
    for label, r in s["detection"].items():
        assert r["rate"] == 1.0, label
    assert s["missing_detection"]["rate"] == 1.0
    assert s["false_positive_rate_on_controls"]["k"] == 0


def test_intent_filtering_shrinks_the_prompt():
    _, s = evaluate.suite_cost({"runs": 5, "seed": 5})
    assert s["saved_fraction"]["mean"] > 0


@pytest.mark.parametrize("script", ["test_injection.py", "test_e2e.py"])
def test_legacy_script_passes(script):
    r = subprocess.run([sys.executable, script], cwd=REPO, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout[-2000:]
