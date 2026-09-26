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
this function does not consult the model. It consults a table.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .schema import ALLOWED_ACTIONS, Action, Plan


# --------------------------------------------------------------------------
# Directives where one value is unambiguously weaker than another.
# Format: (path suffix, directive) -> set of values that WEAKEN the host.
# --------------------------------------------------------------------------

WEAKENING_DIRECTIVES: dict[tuple[str, str], set[str]] = {
    ("sshd_config", "PermitRootLogin"): {"yes", "without-password", "prohibit-password"},
    ("sshd_config", "PasswordAuthentication"): {"yes"},
    ("sshd_config", "PermitEmptyPasswords"): {"yes"},
    ("sshd_config", "X11Forwarding"): {"yes"},
    ("sshd_config", "AllowTcpForwarding"): {"yes"},
    ("sshd_config", "GatewayPorts"): {"yes", "clientspecified"},
    ("sshd_config", "StrictModes"): {"no"},
    ("sshd_config", "UsePAM"): {"no"},
    ("sshd_config", "Protocol"): {"1", "1,2", "2,1"},
}

# sysctl keys where a specific value is the hardened one; anything else weakens.
HARDENED_SYSCTL: dict[str, set[str]] = {
    "net.ipv4.conf.all.accept_redirects": {"0"},
    "net.ipv4.conf.all.send_redirects": {"0"},
    "net.ipv4.conf.all.accept_source_route": {"0"},
    "net.ipv4.conf.all.rp_filter": {"1", "2"},
    "net.ipv4.tcp_syncookies": {"1"},
    "net.ipv4.ip_forward": {"0"},
    "kernel.randomize_va_space": {"2"},
    "kernel.dmesg_restrict": {"1"},
    "kernel.kptr_restrict": {"1", "2"},
    "fs.suid_dumpable": {"0"},
}

# Services that must never be disabled or masked by an automated plan.
PROTECTED_UNITS: set[str] = {
    "ssh.service", "sshd.service",
    "systemd-journald.service", "systemd-logind.service",
    "auditd.service", "systemd-udevd.service",
    "dbus.service", "networking.service", "systemd-networkd.service",
    "NetworkManager.service", "cron.service", "rsyslog.service",
}

# Packages whose removal would break the host or its security tooling.
PROTECTED_PACKAGES: set[str] = {
    "openssh-server", "systemd", "sudo", "apt", "dpkg", "libc6",
    "auditd", "ufw", "iptables", "nftables", "ca-certificates",
    "openssl", "linux-image-generic", "grub-common", "login", "passwd",
}

# Paths whose permissions must not be loosened.
SENSITIVE_PATHS: dict[str, str] = {
    "/etc/shadow": "0640",
    "/etc/gshadow": "0640",
    "/etc/passwd": "0644",
    "/etc/group": "0644",
    "/etc/ssh/sshd_config": "0600",
    "/etc/sudoers": "0440",
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
    Look up the required mode for a sensitive path.

    Matched by suffix, not by exact string. Exact matching is defeated by any
    prefix — a chroot, a bind mount, a sandbox root — and silently disables the
    check on precisely the files it exists to protect.
    """
    for sensitive, mode in SENSITIVE_PATHS.items():
        if path == sensitive or path.endswith(sensitive):
            return mode
    return None


def _mode_is_looser(new: str, current: str) -> bool:
    """True if `new` grants any permission bit that `current` did not."""
    try:
        n, c = int(new, 8), int(current, 8)
    except ValueError:
        return True  # unparseable -> treat as unsafe
    return bool(n & ~c)


def check_monotonicity(action: Action) -> str | None:
    """
    Return a rejection reason if the action reduces the host's security posture,
    otherwise None.

    This is a deny-list over known-weakening changes, not a proof of safety. It
    is deliberately conservative: an action it cannot reason about is allowed
    through to the dry-run stage, which is where unknown effects get caught.
    """
    kind = action.action

    if kind == "set_config_directive":
        for (suffix, directive), bad_values in WEAKENING_DIRECTIVES.items():
            if action.path.endswith(suffix) and action.directive.lower() == directive.lower():
                if action.value.strip().lower() in bad_values:
                    return (
                        f"would set {directive}={action.value} in {action.path}, "
                        f"which weakens the host"
                    )
        return None

    if kind == "set_sysctl":
        hardened = HARDENED_SYSCTL.get(action.key)
        if hardened and action.value.strip() not in hardened:
            return (
                f"would set {action.key}={action.value}; hardened values are "
                f"{sorted(hardened)}"
            )
        return None

    if kind in ("disable_service", "mask_service"):
        if action.unit in PROTECTED_UNITS:
            verb = {"disable_service": "disabled", "mask_service": "masked"}[kind]
            return f"{action.unit} is protected and may not be {verb}"
        return None

    if kind == "remove_package":
        if action.package in PROTECTED_PACKAGES:
            return f"{action.package} is protected and may not be removed"
        return None

    if kind == "set_file_mode":
        expected = _expected_mode(action.path)
        if expected and _mode_is_looser(action.mode, expected):
            return (
                f"mode {action.mode} on {action.path} is looser than the "
                f"required {expected}"
            )
        if action.current_mode and _mode_is_looser(action.mode, action.current_mode):
            return (
                f"mode {action.mode} grants permissions beyond current "
                f"{action.current_mode}"
            )
        return None

    return None


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
