"""
Plan schema and action allowlist.

This module is the security boundary of hardenctl. The language model can emit
any text it likes; only documents that parse into these models, using only these
action types, ever reach the executor. Everything outside is rejected before it
touches the host.

Adding an action type here widens the blast radius of a compromised or
manipulated model. Treat this file as frozen after Review 1.
"""

from __future__ import annotations

import os
import re
from enum import Enum
from typing import Literal, Optional, Union

from pydantic import BaseModel, Field, field_validator


# --------------------------------------------------------------------------
# Severity and exposure vocabulary
# --------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Exposure(str, Enum):
    """How reachable a listening socket is."""
    PUBLIC = "PUBLIC"        # 0.0.0.0 / :: — every interface
    PRIVATE = "PRIVATE"      # bound to an RFC1918 address
    LOOPBACK = "LOOPBACK"    # 127.0.0.1 / ::1 only
    UNKNOWN = "UNKNOWN"


class BreakRisk(str, Enum):
    """How likely applying an action is to interrupt a running service."""
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


# --------------------------------------------------------------------------
# Findings — produced deterministically, ranked by the assessor
# --------------------------------------------------------------------------

class Finding(BaseModel):
    """A fact about the host. Collectors produce these; the model never invents one."""
    id: str
    category: Literal["socket", "package", "config", "permission", "service"]
    severity: Severity = Severity.INFO
    title: str
    detail: str = ""

    # socket findings
    port: Optional[int] = None
    proto: Optional[str] = None
    bind_addr: Optional[str] = None
    exposure: Optional[Exposure] = None
    process: Optional[str] = None
    pid: Optional[int] = None
    runs_as: Optional[str] = None

    # service identification: `unit` is measured, `purpose` is inferred
    unit: Optional[str] = None
    service: Optional[str] = None
    purpose: str = ""
    concern: Optional[str] = None

    # package findings
    package: Optional[str] = None
    version: Optional[str] = None
    cve_ids: list[str] = Field(default_factory=list)
    kev_ids: list[str] = Field(default_factory=list)
    max_cvss: Optional[float] = None

    # config findings
    path: Optional[str] = None
    directive: Optional[str] = None
    current_value: Optional[str] = None

    # --- deterministic enrichment (root required for most of it) ---
    cmdline: Optional[str] = None
    unit: Optional[str] = None            # owning systemd unit
    unit_desc: Optional[str] = None       # systemd's own description
    pkg_summary: Optional[str] = None     # dpkg's own package summary

    score: float = 0.0


class Explanation(BaseModel):
    """
    Model-generated commentary on a finding.

    Kept in a separate type from Finding on purpose. Findings are measured;
    explanations are inferred. Anything displayed from this model is labelled
    as such, and nothing here ever feeds the hardener.
    """
    finding_id: str
    purpose: str = Field(max_length=300)
    verdict: Literal["EXPECTED", "REVIEW", "CLOSE", "UNKNOWN"] = "UNKNOWN"
    reason: str = Field(max_length=400)
    confidence: Literal["HIGH", "MEDIUM", "LOW"] = "LOW"

    model_config = {"extra": "forbid"}


# --------------------------------------------------------------------------
# Actions — the closed set
# --------------------------------------------------------------------------

# Paths are checked relative to TEST_ROOT, which is "" in production. Setting
# HARDENCTL_ROOT lets the suite exercise the validator against a sandbox tree
# without loosening the rule itself — the regex below never changes.
TEST_ROOT = os.environ.get("HARDENCTL_ROOT", "")

_SAFE_PATH = re.compile(r"^/(?:etc|usr|var|opt|srv|boot)(?:/[\w.@+-]+)*/?$", re.ASCII)


def _rel(path: str) -> str:
    """Strip the configured test root before applying the path rule."""
    root = os.environ.get("HARDENCTL_ROOT", "")
    if root and path.startswith(root):
        return path[len(root):] or "/"
    return path
# ASCII only. Python's \w matches any Unicode letter, so without re.ASCII a
# directive spelled with a Cyrillic 'о' parses, slips past every table keyed
# on the Latin spelling, and leaves sshd with a line it refuses to start on.
_UNIT_NAME = re.compile(r"^[\w.@-]+\.(service|socket|timer|target)$", re.ASCII)
_DIRECTIVE = re.compile(r"^[A-Za-z][\w.-]*$", re.ASCII)
_SYSCTL_KEY = re.compile(r"^[a-z][\w.]*$", re.ASCII)
_PKG_NAME = re.compile(r"^[a-z0-9][a-z0-9.+-]+$")


class _ActionBase(BaseModel):
    """Fields every action must carry, whatever its type."""
    id: str
    justification: str = Field(min_length=10, max_length=600)
    cis_control: Optional[str] = None
    break_risk: BreakRisk = BreakRisk.MEDIUM
    finding_ids: list[str] = Field(default_factory=list)

    model_config = {"extra": "forbid"}


class SetConfigDirective(_ActionBase):
    action: Literal["set_config_directive"]
    path: str
    directive: str
    value: str
    current_value: Optional[str] = None

    @field_validator("path")
    @classmethod
    def _path_ok(cls, v: str) -> str:
        if ".." in v or not _SAFE_PATH.match(_rel(v)):
            raise ValueError(f"path outside permitted tree: {v}")
        return v

    @field_validator("directive")
    @classmethod
    def _directive_ok(cls, v: str) -> str:
        if not _DIRECTIVE.match(v):
            raise ValueError(f"malformed directive: {v}")
        return v

    @field_validator("value")
    @classmethod
    def _value_ok(cls, v: str) -> str:
        if "\n" in v or "\r" in v:
            raise ValueError("value may not contain newlines")
        return v


class DisableService(_ActionBase):
    action: Literal["disable_service"]
    unit: str

    @field_validator("unit")
    @classmethod
    def _unit_ok(cls, v: str) -> str:
        if not _UNIT_NAME.match(v):
            raise ValueError(f"malformed unit name: {v}")
        return v


class MaskService(_ActionBase):
    action: Literal["mask_service"]
    unit: str

    @field_validator("unit")
    @classmethod
    def _unit_ok(cls, v: str) -> str:
        if not _UNIT_NAME.match(v):
            raise ValueError(f"malformed unit name: {v}")
        return v


class SetFileMode(_ActionBase):
    action: Literal["set_file_mode"]
    path: str
    mode: str  # octal string, e.g. "0600"
    current_mode: Optional[str] = None

    @field_validator("path")
    @classmethod
    def _path_ok(cls, v: str) -> str:
        if ".." in v or not _SAFE_PATH.match(_rel(v)):
            raise ValueError(f"path outside permitted tree: {v}")
        return v

    @field_validator("mode")
    @classmethod
    def _mode_ok(cls, v: str) -> str:
        if not re.fullmatch(r"0[0-7]{3}", v):
            raise ValueError(f"mode must be 4-digit octal starting 0: {v}")
        return v


class SetSysctl(_ActionBase):
    action: Literal["set_sysctl"]
    key: str
    value: str
    current_value: Optional[str] = None

    @field_validator("key")
    @classmethod
    def _key_ok(cls, v: str) -> str:
        if not _SYSCTL_KEY.match(v):
            raise ValueError(f"malformed sysctl key: {v}")
        return v


class RemovePackage(_ActionBase):
    action: Literal["remove_package"]
    package: str

    @field_validator("package")
    @classmethod
    def _pkg_ok(cls, v: str) -> str:
        if not _PKG_NAME.match(v):
            raise ValueError(f"malformed package name: {v}")
        return v


Action = Union[
    SetConfigDirective,
    DisableService,
    MaskService,
    SetFileMode,
    SetSysctl,
    RemovePackage,
]

ALLOWED_ACTIONS: frozenset[str] = frozenset({
    "set_config_directive",
    "disable_service",
    "mask_service",
    "set_file_mode",
    "set_sysctl",
    "remove_package",
})


class Plan(BaseModel):
    """A complete, validated set of changes. Nothing executes outside a Plan."""
    run_id: str
    host: str
    generated_by: str  # "llm:claude-..." or "rules:v1"
    actions: list[Action] = Field(default_factory=list)
    notes: str = ""

    model_config = {"extra": "forbid"}
