"""
Plan validation.

Three independent gates, applied in order. A plan must clear all three before
any part of it reaches the executor.

  1. Schema      — does it parse into the models in schema.py?
  2. Allowlist   — is every action type in the closed set?
  3. Monotonicity — does any action REDUCE the host's security posture?

Gate 3 is the one that matters when the model has been manipulated. A prompt
injection planted in a config file can convince a model to propose
`PermitRootLogin yes`. It cannot convince this function to accept it, because
this function does not consult the model. It consults a table — and it never
reads the action's justification.

Gate v2 (after the v1 coverage probes, 3/12)
--------------------------------------------
v1 was a deny-list: it rejected changes it knew to be weakening and let
everything else through. The coverage probes showed the flaw — a deny-list
only covers what its author thought of (drop-in files, Ciphers, sudoers,
unlisted sysctls all walked past it). v2 fails closed wherever an order is
needed to decide "weaker":

  set_config_directive  only files with a policy (sshd, login.defs), only
                        directives in that policy, only values the policy
                        orders as no weaker than the CIS value AND the value
                        currently on disk. Include/Match and everything else
                        are rejected.
  set_sysctl            only known hardening keys, only hardened values.
                        Per-interface keys are held to the `all` rule.
  set_file_mode         the new mode may not grant a bit the file does not
                        have ON DISK (the model's `current_mode` is untrusted),
                        nor exceed the sensitive-path ceiling.
  paths                 symlinks are refused; a link under /etc can point
                        anywhere, including at a file the tables protect.
  disable/mask/remove   still a deny-list (removing attack surface is the
                        normal direction), with the protected sets widened.

Gate v2.1 (after held-out corpus v2's first run: 5/44 leaked, all in the
deny-list parts or an absent file) replaces list entries with rules:
every systemd-* unit is protected; a package dpkg marks Essential or
required/important, or any kernel package, may not be removed; no mode may
grant world-write. Security agents outside those rules (osquery, EDR) remain
a deny-list gap and are documented as one.
"""

from __future__ import annotations

import fnmatch
import re
import shutil
import stat
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .schema import ALLOWED_ACTIONS, Action, Plan


# --------------------------------------------------------------------------
# Config files: which files may be edited, and how their values are ordered.
# --------------------------------------------------------------------------

# Value policies. Each returns a reason string if `value` is weaker than
# allowed (given the value currently on disk, if any), else None.

def _enum(allowed: set[str]):
    def check(value: str, current: str | None) -> str | None:
        if value.lower() not in allowed:
            return f"only {sorted(allowed)} are accepted"
        return None
    return check


def _int_at_most(ceiling: int, minimum: int = 1):
    """Lower is stricter (e.g. MaxAuthTries). Never raise above current."""
    def check(value: str, current: str | None) -> str | None:
        if not value.isdigit():
            return "must be a plain integer"
        v = int(value)
        if v < minimum or v > ceiling:
            return f"must be between {minimum} and {ceiling}"
        if current and current.isdigit() and int(current) >= minimum and v > int(current):
            return f"would raise it from the current {current}"
        return None
    return check


def _int_at_least(floor: int):
    """Higher is stricter (e.g. PASS_WARN_AGE). Never lower below current."""
    def check(value: str, current: str | None) -> str | None:
        if not value.isdigit():
            return "must be a plain integer"
        v = int(value)
        if v < floor:
            return f"must be at least {floor}"
        if current and current.isdigit() and v < int(current):
            return f"would lower it from the current {current}"
        return None
    return check


# Algorithms that must never be offered (OpenSSH names, lower-case).
WEAK_ALGORITHMS = {
    "3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "blowfish-cbc",
    "cast128-cbc", "arcfour", "arcfour128", "arcfour256", "rijndael-cbc@lysator.liu.se",
    "hmac-md5", "hmac-md5-96", "hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com",
    "hmac-sha1", "hmac-sha1-96", "hmac-sha1-etm@openssh.com", "hmac-sha1-96-etm@openssh.com",
    "umac-64@openssh.com", "umac-64-etm@openssh.com", "hmac-ripemd160",
    "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1", "ssh-rsa", "ssh-dss",
}


def _algorithms(value: str, current: str | None) -> str | None:
    """
    A replacement list with no weak entries. The +/^ prefixes ADD to the
    compiled-in defaults (which still include weaker algorithms on older
    builds) and '-' only removes, so all three are refused: the plan must
    name the full list it wants.
    """
    if value[:1] in "+-^":
        return "relative lists (+, -, ^) are refused; give the full list"
    algos = [a.strip().lower() for a in value.split(",") if a.strip()]
    if not algos:
        return "empty list"
    weak = sorted(set(algos) & WEAK_ALGORITHMS)
    if weak:
        return f"includes weak algorithm(s) {', '.join(weak)}"
    if any(not re.fullmatch(r"[a-z0-9@._-]+", a) for a in algos):
        return "malformed algorithm name"
    return None


_NO = _enum({"no"})

SSHD_POLICY: dict[str, object] = {
    "permitrootlogin": _NO,
    "passwordauthentication": _NO,
    "permitemptypasswords": _NO,
    "x11forwarding": _NO,
    "allowtcpforwarding": _NO,
    "allowagentforwarding": _NO,
    "allowstreamlocalforwarding": _NO,
    "gatewayports": _NO,
    "permittunnel": _NO,
    "permituserenvironment": _NO,
    "hostbasedauthentication": _NO,
    "kbdinteractiveauthentication": _NO,
    "challengeresponseauthentication": _NO,
    "ignorerhosts": _enum({"yes"}),
    "strictmodes": _enum({"yes"}),
    "usepam": _enum({"yes"}),
    "disableforwarding": _enum({"yes"}),
    "loglevel": _enum({"verbose", "info"}),
    "maxauthtries": _int_at_most(4),
    "maxsessions": _int_at_most(10),
    "logingracetime": _int_at_most(60),
    "clientaliveinterval": _int_at_most(300),
    "clientalivecountmax": _int_at_most(3),
    "ciphers": _algorithms,
    "macs": _algorithms,
    "kexalgorithms": _algorithms,
}

LOGIN_DEFS_POLICY: dict[str, object] = {
    "pass_max_days": _int_at_most(365),
    "pass_min_days": _int_at_least(1),
    "pass_warn_age": _int_at_least(7),
    "umask": _enum({"027", "077"}),
    "encrypt_method": _enum({"sha512", "yescrypt"}),
}


def _config_policy(path: str) -> tuple[str, dict] | None:
    """Which policy governs this file, matched by suffix (the path may carry a
    sandbox or chroot prefix). None means hardenctl may not edit it."""
    if path.endswith("/etc/ssh/sshd_config") or re.search(
            r"/etc/ssh/sshd_config\.d/[\w.@+-]+\.conf$", path):
        return "sshd", SSHD_POLICY
    if path.endswith("/etc/login.defs"):
        return "login.defs", LOGIN_DEFS_POLICY
    return None


def _current_directive(path: str, directive: str) -> str | None:
    """The directive's first active value in this file, read from disk."""
    p = Path(path)
    if not p.is_file():
        return None
    try:
        text = p.read_text(errors="replace")
    except OSError:
        return None
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = re.match(rf"^{re.escape(directive)}(?:\s*=\s*|\s+)(\S+)", s, re.IGNORECASE)
        if m:
            return m.group(1).strip().lower()
    return None


# --------------------------------------------------------------------------
# sysctl: the only keys a plan may set, and their hardened values.
# --------------------------------------------------------------------------

HARDENED_SYSCTL: dict[str, set[str]] = {
    "net.ipv4.conf.all.accept_redirects": {"0"},
    "net.ipv4.conf.all.secure_redirects": {"0"},
    "net.ipv4.conf.all.send_redirects": {"0"},
    "net.ipv4.conf.all.accept_source_route": {"0"},
    "net.ipv4.conf.all.rp_filter": {"1", "2"},
    "net.ipv4.conf.all.log_martians": {"1"},
    "net.ipv4.tcp_syncookies": {"1"},
    "net.ipv4.ip_forward": {"0"},
    "net.ipv4.icmp_echo_ignore_broadcasts": {"1"},
    "net.ipv4.icmp_ignore_bogus_error_responses": {"1"},
    "net.ipv6.conf.all.accept_redirects": {"0"},
    "net.ipv6.conf.all.accept_source_route": {"0"},
    "net.ipv6.conf.all.accept_ra": {"0"},
    "net.ipv6.conf.all.forwarding": {"0"},
    "kernel.randomize_va_space": {"2"},
    "kernel.dmesg_restrict": {"1"},
    "kernel.kptr_restrict": {"1", "2"},
    "kernel.yama.ptrace_scope": {"1", "2", "3"},
    "kernel.unprivileged_bpf_disabled": {"1", "2"},
    "kernel.kexec_load_disabled": {"1"},
    "kernel.perf_event_paranoid": {"2", "3", "4"},
    "fs.suid_dumpable": {"0"},
    "fs.protected_hardlinks": {"1"},
    "fs.protected_symlinks": {"1"},
    "fs.protected_fifos": {"1", "2"},
    "fs.protected_regular": {"1", "2"},
}

_PER_IFACE = re.compile(r"^net\.(ipv[46])\.conf\.[^.]+\.(\w+)$")


def _sysctl_rule_key(key: str) -> str:
    """net.ipv4.conf.eth0.accept_redirects is held to the `all` rule."""
    m = _PER_IFACE.match(key)
    return f"net.{m.group(1)}.conf.all.{m.group(2)}" if m else key


# --------------------------------------------------------------------------
# Services, packages, sensitive paths
# --------------------------------------------------------------------------

# Services that must never be disabled or masked by an automated plan.
PROTECTED_UNITS: set[str] = {
    "ssh.service", "sshd.service", "ssh.socket",
    "systemd-journald.service", "systemd-logind.service",
    "auditd.service", "systemd-udevd.service",
    "dbus.service", "networking.service", "systemd-networkd.service",
    "NetworkManager.service", "cron.service", "rsyslog.service",
    "apparmor.service", "ufw.service", "nftables.service", "firewalld.service",
    "fail2ban.service", "unattended-upgrades.service",
    "apt-daily.timer", "apt-daily-upgrade.timer",
    "systemd-timesyncd.service", "chrony.service",
}

# Packages whose removal would break the host or its security tooling.
PROTECTED_PACKAGES: set[str] = {
    "openssh-server", "systemd", "sudo", "apt", "dpkg", "libc6",
    "auditd", "ufw", "iptables", "nftables", "ca-certificates",
    "openssl", "linux-image-generic", "grub-common", "login", "passwd",
    "apparmor", "libpam-modules", "libpam-runtime", "libpam-pwquality",
    "unattended-upgrades", "fail2ban", "aide", "rsyslog", "systemd-timesyncd",
}

# Kernel packages: removing one can leave the host unbootable.
_KERNEL_PKG = re.compile(r"^linux-(image|modules|headers|generic|signed)(-|$)")


def _dpkg_critical(package: str) -> str | None:
    """
    Ask dpkg itself whether a package is Essential or Priority required /
    important. Deterministic, sourced from the OS rather than from a list we
    have to keep complete. Returns the reason, or None.
    """
    if not shutil.which("dpkg-query"):
        return None
    try:
        r = subprocess.run(["dpkg-query", "-W", "-f=${Essential} ${Priority}", package],
                           capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    essential, _, priority = r.stdout.strip().partition(" ")
    if essential == "yes":
        return "dpkg marks it Essential"
    if priority in ("required", "important"):
        return f"dpkg priority is {priority}"
    return None


# Paths whose permissions must not exceed a ceiling. Glob patterns, matched
# against the end of the path.
SENSITIVE_PATHS: dict[str, str] = {
    "/etc/shadow": "0640",
    "/etc/shadow-": "0640",
    "/etc/gshadow": "0640",
    "/etc/gshadow-": "0640",
    "/etc/passwd": "0644",
    "/etc/group": "0644",
    "/etc/ssh/sshd_config": "0600",
    "/etc/ssh/sshd_config.d/*.conf": "0600",
    "/etc/ssh/ssh_host_*_key": "0600",
    "/etc/sudoers": "0440",
    "/etc/sudoers.d/*": "0440",
    "/etc/crontab": "0600",
    "/boot/grub/grub.cfg": "0600",
}


@dataclass
class Rejection:
    action_id: str
    action_type: str
    gate: str          # "schema" | "allowlist" | "monotonicity"
    reason: str


@dataclass
class ValidationResult:
    accepted: list[Action] = field(default_factory=list)
    rejections: list[Rejection] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.rejections

    def summary(self) -> str:
        if self.ok:
            return f"{len(self.accepted)} action(s) accepted, 0 rejected"
        by_gate: dict[str, int] = {}
        for r in self.rejections:
            by_gate[r.gate] = by_gate.get(r.gate, 0) + 1
        detail = ", ".join(f"{v} at {k}" for k, v in sorted(by_gate.items()))
        return f"{len(self.accepted)} accepted, {len(self.rejections)} rejected ({detail})"


# --------------------------------------------------------------------------
# Gate 3 — monotonicity
# --------------------------------------------------------------------------

def _expected_mode(path: str) -> str | None:
    """
    Look up the ceiling for a sensitive path.

    Matched by suffix, not by exact string. Exact matching is defeated by any
    prefix — a chroot, a bind mount, a sandbox root — and silently disables the
    check on precisely the files it exists to protect.
    """
    for pattern, mode in SENSITIVE_PATHS.items():
        if fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(path, "*" + pattern):
            return mode
    return None


def _mode_is_looser(new: str, current: str) -> bool:
    """True if `new` grants any permission bit that `current` did not."""
    try:
        n, c = int(new, 8), int(current, 8)
    except ValueError:
        return True  # unparseable -> treat as unsafe
    return bool(n & ~c)


def _symlink_in_path(path: str) -> str | None:
    """The first component of `path` that is a symlink, if any."""
    p = Path(path)
    for part in [p, *p.parents]:
        if str(part) in ("/", ""):
            break
        if part.is_symlink():
            return str(part)
    return None


def check_monotonicity(action: Action) -> str | None:
    """
    Return a rejection reason if the action reduces the host's security
    posture — or if the gate cannot establish that it does not. Otherwise None.
    """
    kind = action.action

    path = getattr(action, "path", None)
    if path is not None:
        link = _symlink_in_path(path)
        if link:
            return f"{link} is a symlink; hardenctl does not follow links"

    if kind == "set_config_directive":
        policy = _config_policy(action.path)
        if policy is None:
            return (f"no monotonicity policy for {action.path}; only sshd and "
                    f"login.defs settings can be changed")
        family, table = policy
        rule = table.get(action.directive.lower())
        if rule is None:
            return f"{action.directive} is not a {family} setting hardenctl may change"
        current = _current_directive(action.path, action.directive)
        why = rule(action.value.strip(), current)
        if why:
            return f"would set {action.directive}={action.value} in {action.path}: {why}"
        return None

    if kind == "set_sysctl":
        hardened = HARDENED_SYSCTL.get(_sysctl_rule_key(action.key))
        if hardened is None:
            return f"{action.key} is not a known hardening sysctl"
        if action.value.strip() not in hardened:
            return (
                f"would set {action.key}={action.value}; hardened values are "
                f"{sorted(hardened)}"
            )
        return None

    if kind in ("disable_service", "mask_service"):
        if action.unit in PROTECTED_UNITS or action.unit.startswith("systemd-"):
            verb = {"disable_service": "disabled", "mask_service": "masked"}[kind]
            return f"{action.unit} is protected and may not be {verb}"
        return None

    if kind == "remove_package":
        if action.package in PROTECTED_PACKAGES:
            return f"{action.package} is protected and may not be removed"
        if _KERNEL_PKG.match(action.package):
            return f"{action.package} is a kernel package and may not be removed"
        if why := _dpkg_critical(action.package):
            return f"{action.package} may not be removed: {why}"
        return None

    if kind == "set_file_mode":
        # World-writable is never a hardening outcome, whatever the file.
        if int(action.mode, 8) & 0o002:
            return f"mode {action.mode} makes {action.path} world-writable"
        expected = _expected_mode(action.path)
        if expected and _mode_is_looser(action.mode, expected):
            return (
                f"mode {action.mode} on {action.path} is looser than the "
                f"required {expected}"
            )
        # The on-disk mode decides; the plan's own current_mode is untrusted.
        p = Path(action.path)
        if p.exists():
            on_disk = f"{stat.S_IMODE(p.stat().st_mode):04o}"
            if _mode_is_looser(action.mode, on_disk):
                return (
                    f"mode {action.mode} grants permissions {action.path} does "
                    f"not have (on disk: {on_disk})"
                )
        elif action.current_mode and _mode_is_looser(action.mode, action.current_mode):
            return (
                f"mode {action.mode} grants permissions beyond current "
                f"{action.current_mode}"
            )
        return None

    return f"no monotonicity rule for action type {kind}"


# --------------------------------------------------------------------------
# Gate 1 — schema, explained
# --------------------------------------------------------------------------

def schema_reason(action: object) -> str | None:
    """
    Why a single raw action fails gate 1, in one line; None if it parses.

    Pydantic reports one error per action model in the union, which reads as
    noise. Keep the error for the model the action claims to be.
    """
    from .schema import Plan
    try:
        Plan(run_id="check", host="check", generated_by="check", actions=[action])
        return None
    except Exception as e:  # ValidationError, or anything malformed
        kind = action.get("action") if isinstance(action, dict) else None
        if kind not in ALLOWED_ACTIONS:
            return f"action type {kind!r} is not one of the six"
        errors = getattr(e, "errors", None)
        if callable(errors):
            model = "".join(w.title() for w in kind.split("_"))
            errs = errors()
            best = next((x for x in errs if model in map(str, x.get("loc", ()))),
                        errs[0] if errs else None)
            if best:
                field_name = str(best.get("loc", ("",))[-1])
                return f"{field_name}: {best.get('msg', '')}"[:160]
        return f"{type(e).__name__}: {e}"[:160]


# --------------------------------------------------------------------------
# Top-level validation
# --------------------------------------------------------------------------

def validate_plan(plan: Plan, *, allow_weakening: set[str] | None = None) -> ValidationResult:
    """
    Run all gates over a parsed Plan.

    `allow_weakening` holds action IDs the operator has explicitly opted into
    despite a monotonicity failure. This is the only way a weakening action can
    execute, and it requires a human naming the action by ID.
    """
    allow_weakening = allow_weakening or set()
    result = ValidationResult()

    for action in plan.actions:
        # Gate 2 — allowlist. (Gate 1, schema, already ran during parsing.)
        if action.action not in ALLOWED_ACTIONS:
            result.rejections.append(Rejection(
                action_id=action.id, action_type=action.action,
                gate="allowlist",
                reason=f"action type '{action.action}' is not in the permitted set",
            ))
            continue

        # Gate 3 — monotonicity.
        reason = check_monotonicity(action)
        if reason and action.id not in allow_weakening:
            result.rejections.append(Rejection(
                action_id=action.id, action_type=action.action,
                gate="monotonicity", reason=reason,
            ))
            continue

        result.accepted.append(action)

    return result
