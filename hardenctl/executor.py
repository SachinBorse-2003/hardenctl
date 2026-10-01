"""
Execution and rollback.

Every action implements three operations:

  simulate() -> str      what would change, without changing it
  apply()    -> None     make the change
  inverse()  -> dict     the action that undoes it, captured BEFORE applying

Apply is transactional at the run level. Actions execute in order; if one
fails, every already-applied action in that run is reverted in reverse order
before the error surfaces. A partially hardened host is a broken host.

No shell strings anywhere. subprocess is always called with an argument list,
so nothing a model emits can become shell syntax.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import config
from .schema import Action, Plan


def runs_root() -> Path:
    """
    Run store, resolved at call time through config.state_dir().

    Under sudo this is the INVOKING user's ~/.hardenctl/runs, the same place
    config and intent live, not /root. Run directories stay root-owned and
    mode 0700 because the backup tree can hold copies of sensitive files such
    as /etc/shadow; they are deliberately NOT chowned back to the user.
    """
    return config.state_dir() / "runs"


# --------------------------------------------------------------------------
# Run store
# --------------------------------------------------------------------------

def run_dir(run_id: str) -> Path:
    return runs_root() / run_id


def ensure_run_dir(run_id: str) -> Path:
    d = run_dir(run_id)
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    return d


def backup_dir(run_id: str) -> Path:
    return run_dir(run_id) / "backup"


def save_run(plan: Plan, record: dict) -> Path:
    d = ensure_run_dir(plan.run_id)
    (d / "plan.json").write_text(plan.model_dump_json(indent=2))
    (d / "record.json").write_text(json.dumps(record, indent=2))
    return d


def load_record(run_id: str) -> dict:
    p = run_dir(run_id) / "record.json"
    if not p.is_file():
        raise FileNotFoundError(f"no such run: {run_id}")
    return json.loads(p.read_text())


def list_runs() -> list[dict]:
    root = runs_root()
    if not root.is_dir():
        return []
    out = []
    for d in sorted(root.iterdir(), reverse=True):
        rec = d / "record.json"
        if rec.is_file():
            try:
                out.append(json.loads(rec.read_text()))
            except (OSError, json.JSONDecodeError):
                continue
    return out


# --------------------------------------------------------------------------
# Backups
# --------------------------------------------------------------------------

def backup_file(run_id: str, path: str) -> str | None:
    """
    Copy a file into the run's backup tree, preserving mode.

    Only the FIRST touch of a given file in a run is backed up. Two actions
    editing the same file must both roll back to the state before the run
    began, not to the state after the first edit — overwriting the backup on
    every action silently destroys the original.
    """
    src = Path(path)
    dest = backup_dir(run_id) / Path(path).relative_to(Path(path).anchor)
    absent = _absent_marker(dest)
    if dest.exists() or absent.exists():
        return str(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not src.is_file():
        # The run is about to CREATE this file. Record that, so rollback
        # deletes it rather than leaving a file the host never had.
        absent.touch()
        return None
    shutil.copy2(src, dest)
    return str(dest)


def _absent_marker(dest: Path) -> Path:
    return dest.with_name(dest.name + ".hardenctl-absent")


def restore_file(run_id: str, path: str) -> bool:
    src = backup_dir(run_id) / Path(path).relative_to(Path(path).anchor)
    if src.is_file():
        shutil.copy2(src, path)
        return True
    if _absent_marker(src).exists():
        Path(path).unlink(missing_ok=True)
        return True
    return False


# --------------------------------------------------------------------------
# Config file editing
# --------------------------------------------------------------------------

def read_directive(path: str, directive: str) -> str | None:
    p = Path(path)
    if not p.is_file():
        return None
    for line in p.read_text(errors="replace").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = re.match(rf"^{re.escape(directive)}\s+(.+)$", s, re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return None


def set_directive(path: str, directive: str, value: str) -> None:
    """
    Set a directive, replacing the first active occurrence or appending.
    Commented-out occurrences are left alone as documentation.
    """
    p = Path(path)
    lines = p.read_text(errors="replace").splitlines() if p.is_file() else []
    pattern = re.compile(rf"^\s*{re.escape(directive)}\s+", re.IGNORECASE)
    replaced = False
    for i, line in enumerate(lines):
        if line.strip().startswith("#"):
            continue
        if pattern.match(line):
            lines[i] = f"{directive} {value}"
            replaced = True
            break
    if not replaced:
        if lines and lines[-1].strip():
            lines.append("")
        lines.append(f"# set by hardenctl")
        lines.append(f"{directive} {value}")
    p.write_text("\n".join(lines) + "\n")


def proc_sys() -> Path:
    """
    Root of the sysctl tree. HARDENCTL_PROC_SYS points it at a sandbox so the
    eval harness can exercise sysctl apply and rollback without root.
    """
    return Path(os.environ.get("HARDENCTL_PROC_SYS", "/proc/sys"))


def sysctl_path(key: str) -> Path:
    return proc_sys() / key.replace(".", "/")


def read_sysctl(key: str) -> str | None:
    proc = sysctl_path(key)
    try:
        return proc.read_text().strip()
    except OSError:
        return None


def sysctl_persist_file() -> Path:
    """Where applied sysctls are persisted, so they survive a reboot."""
    return Path(os.environ.get("HARDENCTL_ROOT", "") + "/etc/sysctl.d/99-hardenctl.conf")


def persist_sysctl(run_id: str, key: str, value: str) -> str:
    """
    Write `key = value` into 99-hardenctl.conf, backed up on first touch like
    any other file. Skipped (not failed) when /etc/sysctl.d does not exist:
    the runtime change still stands, and we never create system directories.
    """
    f = sysctl_persist_file()
    if not f.parent.is_dir():
        return "not persisted: /etc/sysctl.d absent"
    backup_file(run_id, str(f))
    lines = f.read_text().splitlines() if f.is_file() else [
        "# managed by hardenctl — every line is reverted by `hardenctl rollback`"]
    pat = re.compile(rf"^\s*{re.escape(key)}\s*=")
    lines = [ln for ln in lines if not pat.match(ln)] + [f"{key} = {value}"]
    f.write_text("\n".join(lines) + "\n")
    return f"persisted to {f.name}"


def _is_sshd_file(path: str) -> bool:
    return path.endswith("/etc/ssh/sshd_config") or "/etc/ssh/sshd_config.d/" in path


def sshd_syntax_error() -> str | None:
    """
    `sshd -t` on the live configuration. A config sshd cannot parse is a
    lock-out at the next restart, so the step fails and the run reverts.
    Skipped in the sandbox and where sshd is not installed.
    """
    if os.environ.get("HARDENCTL_ROOT") or not shutil.which("sshd"):
        return None
    try:
        r = subprocess.run(["sshd", "-t"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        return f"sshd -t could not run: {e}"
    if r.returncode == 0:
        return None
    err = r.stderr.strip()
    # Ubuntu 24.04 starts sshd by socket activation; until the first
    # connection /run/sshd does not exist and `sshd -t` fails on that alone.
    # That says nothing about the config, so it is not a rejection.
    if "privilege separation directory" in err:
        return None
    return (err or "sshd -t failed")[:200]


# --------------------------------------------------------------------------
# Per-action handlers
# --------------------------------------------------------------------------

@dataclass
class StepResult:
    action_id: str
    action_type: str
    status: str            # "ok" | "skipped" | "failed"
    message: str = ""
    inverse: dict | None = None


def simulate(action: Action) -> str:
    k = action.action
    if k == "set_config_directive":
        cur = read_directive(action.path, action.directive)
        return f"{action.path}: {action.directive} {cur or '(unset)'} -> {action.value}"
    if k == "set_file_mode":
        p = Path(action.path)
        cur = f"{stat.S_IMODE(p.stat().st_mode):04o}" if p.exists() else "(absent)"
        return f"{action.path}: mode {cur} -> {action.mode}"
    if k == "set_sysctl":
        return f"sysctl {action.key}: {read_sysctl(action.key) or '(unset)'} -> {action.value}"
    if k in ("disable_service", "mask_service"):
        return f"systemctl {k.split('_')[0]} {action.unit}"
    if k == "remove_package":
        return f"apt-get remove {action.package}"
    return f"unknown action {k}"


def capture_inverse(action: Action) -> dict | None:
    """Build the undo action from CURRENT state, before anything changes."""
    k = action.action
    if k == "set_config_directive":
        cur = read_directive(action.path, action.directive)
        return {"action": "set_config_directive", "path": action.path,
                "directive": action.directive, "value": cur, "was_unset": cur is None}
    if k == "set_file_mode":
        p = Path(action.path)
        if not p.exists():
            return None
        return {"action": "set_file_mode", "path": action.path,
                "mode": f"{stat.S_IMODE(p.stat().st_mode):04o}"}
    if k == "set_sysctl":
        return {"action": "set_sysctl", "key": action.key, "value": read_sysctl(action.key)}
    if k in ("disable_service", "mask_service"):
        return {"action": "enable_service", "unit": action.unit}
    if k == "remove_package":
        return {"action": "install_package", "package": action.package}
    return None


def execute(action: Action, run_id: str) -> StepResult:
    k = action.action
    inv = capture_inverse(action)
    description = simulate(action)   # captured pre-change

    path = getattr(action, "path", None)
    if path is not None and Path(path).is_symlink():
        return StepResult(action.id, k, "failed", f"{path} is a symlink; refusing to follow it")

    try:
        if k == "set_config_directive":
            backup_file(run_id, action.path)
            set_directive(action.path, action.directive, action.value)
            if _is_sshd_file(action.path) and (err := sshd_syntax_error()):
                restore_file(run_id, action.path)
                return StepResult(action.id, k, "failed", f"sshd -t rejected the change: {err}")

        elif k == "set_file_mode":
            p = Path(action.path)
            if not p.exists():
                return StepResult(action.id, k, "skipped", "path absent")
            backup_file(run_id, action.path)
            os.chmod(action.path, int(action.mode, 8))

        elif k == "set_sysctl":
            proc = sysctl_path(action.key)
            if not proc.exists():
                return StepResult(action.id, k, "skipped", "sysctl key absent")
            proc.write_text(action.value + "\n")
            description += f" ({persist_sysctl(run_id, action.key, action.value)})"

        elif k in ("disable_service", "mask_service"):
            verb = "disable" if k == "disable_service" else "mask"
            r = subprocess.run(["systemctl", verb, action.unit],
                               capture_output=True, text=True, timeout=60)
            if r.returncode != 0:
                return StepResult(action.id, k, "failed", r.stderr.strip()[:200])

        elif k == "remove_package":
            env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
            r = subprocess.run(["apt-get", "remove", "-y", action.package],
                               capture_output=True, text=True, timeout=300, env=env)
            if r.returncode != 0:
                return StepResult(action.id, k, "failed", r.stderr.strip()[:200])

        else:
            return StepResult(action.id, k, "failed", f"no handler for {k}")

    except (OSError, subprocess.SubprocessError, ValueError) as e:
        return StepResult(action.id, k, "failed", f"{type(e).__name__}: {e}"[:200])

    return StepResult(action.id, k, "ok", description, inverse=inv)


def revert(inv: dict, run_id: str) -> bool:
    """Apply a captured inverse."""
    k = inv.get("action")
    try:
        if k == "set_config_directive":
            if not restore_file(run_id, inv["path"]):
                if inv.get("value") is not None:
                    set_directive(inv["path"], inv["directive"], inv["value"])
            return True
        if k == "set_file_mode":
            os.chmod(inv["path"], int(inv["mode"], 8))
            return True
        if k == "set_sysctl":
            restore_file(run_id, str(sysctl_persist_file()))
            if inv.get("value") is None:
                return True
            proc = sysctl_path(inv["key"])
            proc.write_text(inv["value"] + "\n")
            return True
        if k == "enable_service":
            subprocess.run(["systemctl", "unmask", inv["unit"]],
                           capture_output=True, timeout=60)
            subprocess.run(["systemctl", "enable", inv["unit"]],
                           capture_output=True, timeout=60)
            return True
        if k == "install_package":
            env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
            r = subprocess.run(["apt-get", "install", "-y", inv["package"]],
                               capture_output=True, timeout=300, env=env)
            return r.returncode == 0
    except (OSError, subprocess.SubprocessError, ValueError, KeyError):
        return False
    return False


# --------------------------------------------------------------------------
# Transactional run
# --------------------------------------------------------------------------

@dataclass
class RunResult:
    run_id: str
    steps: list[StepResult] = field(default_factory=list)
    rolled_back: bool = False
    error: str = ""

    @property
    def applied(self) -> int:
        return sum(1 for s in self.steps if s.status == "ok")


def apply_plan(plan: Plan, actions: list[Action]) -> RunResult:
    """Apply actions in order. On any failure, revert the whole run."""
    result = RunResult(run_id=plan.run_id)
    ensure_run_dir(plan.run_id)
    backup_dir(plan.run_id).mkdir(parents=True, exist_ok=True)
    done: list[StepResult] = []

    for action in actions:
        step = execute(action, plan.run_id)
        result.steps.append(step)
        if step.status == "failed":
            result.error = f"action {step.action_id} failed: {step.message}"
            for prev in reversed(done):
                if prev.inverse:
                    revert(prev.inverse, plan.run_id)
            result.rolled_back = True
            break
        if step.status == "ok":
            done.append(step)

    save_run(plan, {
        "run_id": plan.run_id, "host": plan.host,
        "generated_by": plan.generated_by, "timestamp": time.time(),
        "rolled_back": result.rolled_back, "error": result.error,
        "steps": [
            {"action_id": s.action_id, "action_type": s.action_type,
             "status": s.status, "message": s.message, "inverse": s.inverse}
            for s in result.steps
        ],
    })
    return result


def rollback_run(run_id: str) -> tuple[int, int]:
    """Revert a completed run. Returns (reverted, total_attempted)."""
    rec = load_record(run_id)
    steps = [s for s in rec.get("steps", []) if s["status"] == "ok" and s.get("inverse")]
    ok = sum(1 for s in reversed(steps) if revert(s["inverse"], run_id))
    rec["rolled_back"] = True
    (run_dir(run_id) / "record.json").write_text(json.dumps(rec, indent=2))
    return ok, len(steps)
