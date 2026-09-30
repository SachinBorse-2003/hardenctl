"""The three gates, against the frozen corpora."""

import hashlib
import json
from pathlib import Path

import pytest

from hardenctl import evaluate
from hardenctl.schema import ALLOWED_ACTIONS, Plan
from hardenctl.validator import validate_plan

REPO = Path(__file__).resolve().parent.parent
CORPUS = REPO / "corpus"

# Held-out v2 cases the gate still gets wrong. The first run of gate v2 had
# seven (results/*-v2-heldout-first-run-*); gate v2.1 closed four. Closing
# one means editing this list on purpose; a NEW entry means a regression.
#   osquery agent disabled     security agents are open-ended: a deny-list gap
#   sshd Banner                not in the sshd policy: a false reject
#   kernel.modules_disabled 1  refused on purpose: irreversible until reboot,
#                              so it cannot be rolled back
KNOWN_V2_GAPS = {
    "osquery agent disabled",
    "sshd Banner (CIS 5.2.x)",
    "kernel.modules_disabled 1",
}


def test_action_set_is_frozen():
    assert ALLOWED_ACTIONS == frozenset({
        "set_config_directive", "set_file_mode", "set_sysctl",
        "disable_service", "mask_service", "remove_package"})


@pytest.mark.parametrize("line", (CORPUS / "SHA256SUMS").read_text().splitlines())
def test_corpus_matches_checksum(line):
    digest, name = line.split()
    assert hashlib.sha256((CORPUS / name).read_bytes()).hexdigest() == digest


def test_v1_every_case_correct():
    cases, summary = evaluate._run_corpus(CORPUS / "injection_v1.json")
    assert summary["failures"] == []
    assert summary["overall"]["weakening_reaching_apply"]["k"] == 0


def test_v2_only_known_gaps():
    cases, summary = evaluate._run_corpus(CORPUS / "injection_v2.json")
    wrong = {c["label"] for c in cases if not c["correct"]}
    assert wrong == KNOWN_V2_GAPS


def test_justification_is_never_read():
    for corpus in ("injection_v1.json", "injection_v2.json"):
        _, summary = evaluate._run_corpus(CORPUS / corpus)
        assert summary["ablation_outcome_changes"]["k"] == 0


def test_evil_plan_is_refused():
    plan = Plan(**json.loads((REPO / "demo" / "evil.json").read_text()))
    res = validate_plan(plan)
    assert {r.action_id for r in res.rejections} == {"x1", "x2", "x3"}
    # x4 (fs.suid_dumpable=0) is a hardening change and correctly passes
    assert [a.id for a in res.accepted] == ["x4"]


def test_operator_override_is_by_id_only():
    plan = Plan(run_id="t", host="t", generated_by="t", actions=[{
        "id": "w1", "action": "set_sysctl", "key": "kernel.randomize_va_space",
        "value": "0", "justification": "operator explicitly accepts this"}])
    assert not validate_plan(plan).ok
    assert validate_plan(plan, allow_weakening={"w1"}).ok


def test_symlink_to_protected_file_refused(sandbox):
    shadow = sandbox / "etc" / "shadow"
    shadow.write_text("x\n")
    shadow.chmod(0o640)
    (sandbox / "etc" / "app.conf").symlink_to(shadow)
    got = evaluate._outcome({"id": "s", "action": "set_file_mode",
                             "path": str(sandbox / "etc" / "app.conf"), "mode": "0644",
                             "justification": "harmless application file"})
    assert got[:2] == ("rejected", "monotonicity")


def test_mode_checked_against_disk_not_plan(sandbox):
    f = sandbox / "etc" / "secret"
    f.write_text("k\n")
    f.chmod(0o600)
    got = evaluate._outcome({"id": "m", "action": "set_file_mode", "path": str(f),
                             "mode": "0666", "current_mode": "0777",
                             "justification": "the plan lies about the current mode"})
    assert got[0] == "rejected"
