"""
Deterministic fact collection.

Everything in this module is measurement. No model is involved and no judgement
is applied beyond mechanical classification. The assessor ranks what these
functions return; it never adds to it.
"""

from __future__ import annotations

import glob
import ipaddress
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import psutil

from .schema import Exposure, Finding, Severity


# --------------------------------------------------------------------------
# Sockets
# --------------------------------------------------------------------------

_LOOPBACK = {"127.0.0.1", "::1"}
_WILDCARD = {"0.0.0.0", "::", "*"}


def classify_exposure(addr: str) -> Exposure:
    if not addr or addr in _WILDCARD:
        return Exposure.PUBLIC
    if addr in _LOOPBACK:
        return Exposure.LOOPBACK
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return Exposure.UNKNOWN
    if ip.is_loopback:
        return Exposure.LOOPBACK
    if ip.is_private or ip.is_link_local:
        return Exposure.PRIVATE
    return Exposure.PUBLIC


def collect_sockets() -> list[Finding]:
    """Listening TCP/UDP sockets, attributed to process and owning user."""
    findings: list[Finding] = []
    seen: set[tuple] = set()

    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        return findings

    for c in conns:
        if c.status not in (psutil.CONN_LISTEN, psutil.CONN_NONE):
            continue
        if not c.laddr:
            continue
        addr = c.laddr.ip
        port = c.laddr.port
        proto = "tcp" if c.type == 1 else "udp"
        if proto == "udp" and c.status != psutil.CONN_NONE:
            continue

        key = (addr, port, proto)
        if key in seen:
            continue
        seen.add(key)

        pname, runs_as = None, None
        if c.pid:
            try:
                p = psutil.Process(c.pid)
                pname = p.name()
                runs_as = p.username()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        findings.append(socket_finding(addr, port, proto, pname, runs_as, c.pid))

    return findings


def socket_finding(addr: str, port: int, proto: str, pname: str | None = None,
                   runs_as: str | None = None, pid: int | None = None) -> Finding:
    """One listening socket as a Finding. Split out so the eval harness can
    feed seeded sockets through the same classification the scanner uses."""
    exposure = classify_exposure(addr)
    sev = {
        Exposure.PUBLIC: Severity.HIGH,
        Exposure.PRIVATE: Severity.MEDIUM,
        Exposure.LOOPBACK: Severity.INFO,
        Exposure.UNKNOWN: Severity.MEDIUM,
    }[exposure]
    if exposure is Exposure.PUBLIC and runs_as == "root":
        sev = Severity.CRITICAL

    return Finding(
        # one id per socket, not per port: a port bound on loopback AND on
        # 0.0.0.0 is two exposures, and the public one must not be hidden
        id=f"sock-{proto}-{port}@{addr or '*'}",
        category="socket",
        severity=sev,
        title=f"{proto}/{port} listening on {addr or '*'}",
        detail=f"process={pname or 'unknown'} user={runs_as or 'unknown'}",
        port=port, proto=proto, bind_addr=addr or "*",
        exposure=exposure, process=pname, pid=pid, runs_as=runs_as,
    )


# --------------------------------------------------------------------------
# Package attribution
# --------------------------------------------------------------------------

def _exe_for_pid(pid: int | None) -> str | None:
    if not pid:
        return None
    try:
        return psutil.Process(pid).exe()
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
        return None


def package_for_path(path: str) -> str | None:
    """Resolve an executable path to its owning dpkg package."""
    if not path or not shutil.which("dpkg"):
        return None
    real = os.path.realpath(path)
    for candidate in (real, path):
        try:
            out = subprocess.run(
                ["dpkg", "-S", candidate],
                capture_output=True, text=True, timeout=10,
            )
        except (subprocess.TimeoutExpired, OSError):
            return None
        if out.returncode == 0 and ":" in out.stdout:
            pkg = out.stdout.split(":", 1)[0].strip()
            return pkg.split(",")[0].strip() or None
    return None


def package_version(pkg: str) -> str | None:
    if not shutil.which("dpkg-query"):
        return None
    try:
        out = subprocess.run(
            ["dpkg-query", "-W", "-f=${Version}", pkg],
            capture_output=True, text=True, timeout=10,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    return out.stdout.strip() or None if out.returncode == 0 else None


def attribute_packages(findings: list[Finding]) -> list[Finding]:
    """Fill package and version on socket findings. Mutates and returns."""
    cache: dict[str, tuple[str | None, str | None]] = {}
    for f in findings:
        if f.category != "socket" or not f.pid:
            continue
        exe = _exe_for_pid(f.pid)
        if not exe:
            continue
        if exe not in cache:
            pkg = package_for_path(exe)
            cache[exe] = (pkg, package_version(pkg) if pkg else None)
        f.package, f.version = cache[exe]
    return findings


# --------------------------------------------------------------------------
# Config inspection
# --------------------------------------------------------------------------

# directive -> (CIS value, is the current value compliant?, severity).
# Numeric settings are compared as numbers: MaxAuthTries 3 is stricter than
# the CIS value of 4, not a mismatch to "fix" upwards.
SSHD_CHECKS: dict[str, tuple[str, object, Severity]] = {
    "PermitRootLogin": ("no", lambda v: v == "no", Severity.HIGH),
    "PasswordAuthentication": ("no", lambda v: v == "no", Severity.MEDIUM),
    "PermitEmptyPasswords": ("no", lambda v: v == "no", Severity.CRITICAL),
    "X11Forwarding": ("no", lambda v: v == "no", Severity.LOW),
    "MaxAuthTries": ("4", lambda v: v.isdigit() and 0 < int(v) <= 4, Severity.LOW),
    "ClientAliveInterval": ("300", lambda v: v.isdigit() and 0 < int(v) <= 300, Severity.LOW),
    "LoginGraceTime": ("60", lambda v: v.isdigit() and 0 < int(v) <= 60, Severity.LOW),
}

_SSHD_KEYWORD = {k.lower(): k for k in SSHD_CHECKS}


def _strip_comment(value: str) -> str:
    """Drop a trailing `# ...` comment. None of the values we read can contain '#'."""
    return re.split(r"\s#", value, maxsplit=1)[0].strip()


def read_sshd_effective(path: str = "/etc/ssh/sshd_config",
                        _seen: dict | None = None, _depth: int = 0) -> dict[str, tuple[str, str, str]]:
    """
    Effective global sshd settings, the way sshd itself resolves them:

      - keywords are case-insensitive
      - `Include` is expanded in place (glob, lexical order), so the Ubuntu
        default `Include /etc/ssh/sshd_config.d/*.conf` at the top of the file
        lets a drop-in override the main file
      - the first value obtained wins
      - parsing stops at the first `Match` block, whose settings are conditional

    Returns {lowercase keyword: (keyword as written, value, file it came from)}.
    Comment text, whole-line or trailing, is discarded and never reaches a model.
    """
    seen: dict[str, tuple[str, str, str]] = {} if _seen is None else _seen
    p = Path(path)
    if _depth > 8 or not p.is_file():
        return seen
    try:
        lines = p.read_text(errors="replace").splitlines()
    except OSError:
        return seen
    root = os.environ.get("HARDENCTL_ROOT", "")
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^(\w+)(?:\s*=\s*|\s+)(.+)$", line)
        if not m:
            continue
        key, val = m.group(1), _strip_comment(m.group(2))
        low = key.lower()
        if low == "match":
            break
        if low == "include":
            for pattern in val.split():
                pat = pattern if pattern.startswith("/") else "/etc/ssh/" + pattern
                for hit in sorted(glob.glob(root + pat)):
                    read_sshd_effective(hit, seen, _depth + 1)
            continue
        if low not in seen:
            seen[low] = (key, val, str(p))
    return seen


def read_sshd_config(path: str = "/etc/ssh/sshd_config") -> dict[str, str]:
    """Effective directives as {keyword as written: value}. See read_sshd_effective."""
    return {k: v for k, v, _ in read_sshd_effective(path).values()}


def collect_sshd(path: str = "/etc/ssh/sshd_config") -> list[Finding]:
    findings: list[Finding] = []
    if not Path(path).is_file():
        return findings
    effective = read_sshd_effective(path)
    for directive, (want, compliant, sev) in SSHD_CHECKS.items():
        hit = effective.get(directive.lower())
        if hit is None:
            continue
        _, current, source = hit
        if not compliant(current.strip().lower()):
            findings.append(Finding(
                id=f"sshd-{directive.lower()}",
                category="config", severity=sev,
                title=f"sshd: {directive} is {current}",
                detail=f"CIS-recommended value is {want}"
                       + (f"; set in {source}" if source != path else ""),
                # the file the effective value came from, so a fix edits the
                # file sshd actually reads it from
                path=source, directive=directive, current_value=current,
            ))
    return findings


def collect_permissions() -> list[Finding]:
    """File modes on security-sensitive paths."""
    expected = {
        "/etc/shadow": 0o640, "/etc/gshadow": 0o640,
        "/etc/passwd": 0o644, "/etc/group": 0o644,
        "/etc/ssh/sshd_config": 0o600,
    }
    # HARDENCTL_ROOT prefixes the paths for the sandboxed test and eval runs;
    # it is unset in production.
    root = os.environ.get("HARDENCTL_ROOT", "")
    findings: list[Finding] = []
    for rel, want in expected.items():
        path = root + rel
        p = Path(path)
        if not p.exists():
            continue
        try:
            mode = stat.S_IMODE(p.stat().st_mode)
        except OSError:
            continue
        if mode & ~want:
            findings.append(Finding(
                id=f"perm-{p.name}",
                category="permission", severity=Severity.MEDIUM,
                title=f"{path} is mode {mode:04o}",
                detail=f"expected {want:04o} or stricter",
                path=path, current_value=f"{mode:04o}",
            ))
    return findings


def collect_all(sshd_path: str = "/etc/ssh/sshd_config") -> list[Finding]:
    findings = collect_sockets()
    attribute_packages(findings)
    enrich(findings)
    findings += collect_sshd(sshd_path)
    findings += collect_permissions()
    return findings


# --------------------------------------------------------------------------
# Enrichment — what the OS already knows about its own services
# --------------------------------------------------------------------------
#
# Before asking a language model what a service is, ask the machine. dpkg ships
# a one-line summary for every package and systemd carries a description for
# every unit. Both are authoritative, free, and available offline. The model is
# only worth spending on the judgement layer above this.

def package_summary(pkg: str) -> str | None:
    """dpkg's own one-line description of a package."""
    if not pkg or not shutil.which("dpkg-query"):
        return None
    try:
        out = subprocess.run(
            ["dpkg-query", "-W", "-f=${binary:Summary}", pkg],
            capture_output=True, text=True, timeout=10,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    return out.stdout.strip() or None if out.returncode == 0 else None


def unit_for_pid(pid: int | None) -> tuple[str | None, str | None]:
    """Owning systemd unit and its description, read from the cgroup."""
    if not pid:
        return None, None
    try:
        cgroup = Path(f"/proc/{pid}/cgroup").read_text(errors="replace")
    except OSError:
        return None, None

    m = re.search(r"/([\w.@\\-]+\.(?:service|socket|scope))", cgroup)
    if not m:
        return None, None
    unit = m.group(1)

    desc = None
    if shutil.which("systemctl"):
        try:
            out = subprocess.run(
                ["systemctl", "show", unit, "--property=Description", "--value"],
                capture_output=True, text=True, timeout=10,
            )
            if out.returncode == 0:
                desc = out.stdout.strip() or None
        except (subprocess.TimeoutExpired, OSError):
            pass
    return unit, desc


def cmdline_for_pid(pid: int | None) -> str | None:
    if not pid:
        return None
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return None
    parts = [p for p in raw.decode(errors="replace").split("\x00") if p]
    return " ".join(parts)[:300] or None


def enrich(findings: list[Finding]) -> list[Finding]:
    """Attach cmdline, systemd unit and package summary. Mutates and returns."""
    pkg_cache: dict[str, str | None] = {}
    for f in findings:
        if not f.pid:
            continue
        f.cmdline = cmdline_for_pid(f.pid)
        f.unit, f.unit_desc = unit_for_pid(f.pid)
        if f.package:
            if f.package not in pkg_cache:
                pkg_cache[f.package] = package_summary(f.package)
            f.pkg_summary = pkg_cache[f.package]
    return findings
