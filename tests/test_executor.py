"""Executor: apply, persistence and byte-exact rollback in the sandbox."""

from hardenctl import evaluate, executor
from hardenctl.schema import Plan


def _plan(actions):
    return Plan(run_id="t1", host="t", generated_by="test", actions=actions)


def test_created_file_is_removed_on_rollback(sandbox):
    dropin = sandbox / "etc" / "ssh" / "sshd_config.d" / "60-hardenctl.conf"
    dropin.parent.mkdir()
    before = evaluate.snapshot(sandbox)
    p = _plan([{"id": "a", "action": "set_config_directive", "path": str(dropin),
                "directive": "PermitRootLogin", "value": "no",
                "justification": "CIS: disable root login."}])
    run = executor.apply_plan(p, p.actions)
    assert run.applied == 1 and dropin.is_file()
    executor.rollback_run(run.run_id)
    assert evaluate.snapshot_diff(before, evaluate.snapshot(sandbox)) == []


def test_sysctl_persisted_and_reverted(sandbox):
    (sandbox / "etc" / "sysctl.d").mkdir()
    key = executor.sysctl_path("kernel.randomize_va_space")
    key.parent.mkdir(parents=True)
    key.write_text("0\n")
    before = evaluate.snapshot(sandbox)
    p = _plan([{"id": "a", "action": "set_sysctl", "key": "kernel.randomize_va_space",
                "value": "2", "justification": "CIS: full ASLR."}])
    run = executor.apply_plan(p, p.actions)
    assert executor.read_sysctl("kernel.randomize_va_space") == "2"
    assert "kernel.randomize_va_space = 2" in executor.sysctl_persist_file().read_text()
    executor.rollback_run(run.run_id)
    assert evaluate.snapshot_diff(before, evaluate.snapshot(sandbox)) == []


def test_symlink_refused_at_execution(sandbox):
    target = sandbox / "etc" / "real.conf"
    target.write_text("x\n")
    link = sandbox / "etc" / "link.conf"
    link.symlink_to(target)
    p = _plan([{"id": "a", "action": "set_file_mode", "path": str(link), "mode": "0600",
                "justification": "tighten a config file"}])
    run = executor.apply_plan(p, p.actions)
    assert run.steps[0].status == "failed" and run.rolled_back


def test_failure_mid_plan_reverts_exactly():
    _, s = evaluate.suite_transactional({"runs": 5, "seed": 7})
    assert s["auto_revert_exact"]["k"] == 5


def test_seeded_labs_rollback_exact_and_fully_remediated():
    _, s = evaluate.suite_rollback({"runs": 8, "seed": 3})
    assert s["rollback_fidelity"]["k"] == 8
    assert s["remediation_effectiveness"]["rate"] == 1.0
    assert s["sysctl_persistence"]["rate"] == 1.0
