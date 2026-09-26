"""
End-to-end test on a sandboxed /etc tree.

scan -> plan -> validate -> dry run -> apply -> rollback, then asserts the
restored sshd_config is byte-identical to the original. Needs no root and
touches nothing outside a temporary directory.
"""

import os
import shutil
import sys
import tempfile
from pathlib import Path

_TMP = Path(tempfile.mkdtemp())
os.environ["HARDENCTL_ROOT"] = str(_TMP)          # sandbox root for path rules
os.environ["HARDENCTL_HOME"] = str(_TMP / "state")  # run store stays in the sandbox

SB = _TMP / "etc"
(SB / "ssh").mkdir(parents=True)
SSHD = SB / "ssh" / "sshd_config"
ORIGINAL = """# managed sshd config
Port 22
PermitRootLogin yes
PasswordAuthentication yes
X11Forwarding yes
MaxAuthTries 6
"""
SSHD.write_text(ORIGINAL)
os.chmod(SSHD, 0o644)

from hardenctl import collectors, executor, hardener  # noqa: E402
from hardenctl.validator import validate_plan  # noqa: E402


def active(text: str) -> list[str]:
    return [l for l in text.splitlines() if l.strip() and not l.startswith("#")]


def main() -> int:
    print("=" * 62)
    print("1. SCAN")
    f = collectors.collect_sshd(str(SSHD))
    for x in f:
        print(f"   {x.severity.value:<8} {x.title}")

    print("\n2. PLAN (rules proposer)")
    p = hardener.RulesProposer().propose(f, "testhost")
    p.actions = [a for a in p.actions if getattr(a, "path", "").endswith("sshd_config")]
    for a in p.actions:
        print(f"   {a.id}  {a.directive} -> {a.value}")

    print("\n3. VALIDATE")
    r = validate_plan(p)
    print(f"   {r.summary()}")

    print("\n4. DRY RUN")
    for a in r.accepted:
        print(f"   would: {executor.simulate(a)}")

    print("\n5. APPLY")
    res = executor.apply_plan(p, r.accepted)
    for s in res.steps:
        print(f"   [{s.status}] {s.action_id}  {s.message}")
    print("\n   sshd_config now:")
    for line in active(SSHD.read_text()):
        print(f"     {line}")

    print("\n6. ROLLBACK")
    ok, total = executor.rollback_run(res.run_id)
    print(f"   reverted {ok}/{total}")
    print("   sshd_config restored:")
    for line in active(SSHD.read_text()):
        print(f"     {line}")

    exact = SSHD.read_text() == ORIGINAL
    print(f"\n   ROLLBACK FIDELITY: {'EXACT MATCH' if exact else 'MISMATCH'}")
    shutil.rmtree(_TMP, ignore_errors=True)
    return 0 if exact and ok == total == len(r.accepted) else 1


if __name__ == "__main__":
    sys.exit(main())
