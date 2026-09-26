"""
Intent — what the host is supposed to expose.

The synopsis' central claim: no existing tool holds a declaration of what a host
should expose, so every audit treats the current state as if it were the first.
This module is that declaration, and the comparison against it.

    intent.yaml   the operator's ratified statement of what should listen
    baseline      what actually listened last time (for drift)

Verdicts are deterministic. Intent turns "is this service supposed to be here?"
from a question for a model into a lookup — and reserves the model for the one
category where judgement is actually needed: services nobody declared.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import yaml

from . import config
from .schema import Exposure, Finding

IntentStatus = Literal["INTENDED", "DRIFT", "UNDECLARED", "FORBIDDEN", "NEW"]

_REACH_RANK = {"loopback": 0, "lan": 1, "public": 2}
_EXPOSURE_TO_REACH = {
    Exposure.LOOPBACK: "loopback",
    Exposure.PRIVATE: "lan",
    Exposure.PUBLIC: "public",
    Exposure.UNKNOWN: "public",
}


def intent_path() -> Path:
    return config.state_dir() / "intent.yaml"


def baseline_path() -> Path:
    return config.state_dir() / "baseline.json"


# --------------------------------------------------------------------------
# Intent file
# --------------------------------------------------------------------------

@dataclass
class Rule:
    port: int
    proto: str
    reach: str                # loopback | lan | public
    service: str = ""
    reason: str = ""


@dataclass
class Intent:
    host: str
    declared: str
    expose: list[Rule]
    forbid: list[Rule]

    def lookup(self, port: int, proto: str) -> tuple[str, Rule | None]:
        for r in self.forbid:
            if r.port == port and r.proto == proto:
                return "forbid", r
        for r in self.expose:
            if r.port == port and r.proto == proto:
                return "expose", r
        return "none", None


def load_intent() -> Intent | None:
    p = intent_path()
    if not p.is_file():
        return None
    raw = yaml.safe_load(p.read_text()) or {}

    def rules(key: str) -> list[Rule]:
        out = []
        for item in raw.get(key) or []:
            try:
                out.append(Rule(
                    port=int(item["port"]),
                    proto=str(item.get("proto", "tcp")).lower(),
                    reach=str(item.get("reach", "loopback")).lower(),
                    service=str(item.get("service", "")),
                    reason=str(item.get("reason", "")),
                ))
            except (KeyError, TypeError, ValueError):
                continue
        return out

    return Intent(
        host=str(raw.get("host", "")),
        declared=str(raw.get("declared", "")),
        expose=rules("expose"),
        forbid=rules("forbid"),
    )


def save_intent(intent: Intent) -> Path:
    d = config.state_dir()
    d.mkdir(parents=True, exist_ok=True)
    config._give_back(d)

    def dump(r: Rule) -> dict:
        row = {"port": r.port, "proto": r.proto, "reach": r.reach}
        if r.service:
            row["service"] = r.service
        if r.reason:
            row["reason"] = r.reason
        return row

    doc = {
        "host": intent.host,
        "declared": intent.declared,
        "expose": [dump(r) for r in intent.expose],
        "forbid": [dump(r) for r in intent.forbid],
    }
    header = (
        "# hardenctl intent — what this host is SUPPOSED to expose.\n"
        "# Edit freely. reach is one of: loopback | lan | public.\n"
        "# Anything listening that is not listed here is UNDECLARED.\n"
        "# Anything under `forbid` that is found listening is a VIOLATION.\n\n"
    )
    p = intent_path()
    p.write_text(header + yaml.safe_dump(doc, sort_keys=False, allow_unicode=True))
    config._give_back(p)
    return p


def propose_intent(findings: list[Finding], host: str) -> Intent:
    """
    Draft an intent file from the current state.

    This is the agent proposing policy for a human to ratify — the same shape as
    the hardener proposing a plan. Current exposure becomes declared reach, the
    OS's own package summary becomes the reason. The operator edits the draft;
    nothing is authoritative until they save it.
    """
    seen: set[tuple[int, str]] = set()
    expose: list[Rule] = []
    for f in findings:
        if f.category != "socket" or not f.port or not f.proto:
            continue
        key = (f.port, f.proto)
        if key in seen:
            continue
        seen.add(key)
        reach = _EXPOSURE_TO_REACH.get(f.exposure, "public") if f.exposure else "public"
        # Widen if another socket on the same port is more exposed.
        for g in findings:
            if g.category == "socket" and (g.port, g.proto) == key and g.exposure:
                r2 = _EXPOSURE_TO_REACH[g.exposure]
                if _REACH_RANK[r2] > _REACH_RANK[reach]:
                    reach = r2
        expose.append(Rule(
            port=f.port, proto=f.proto, reach=reach,
            service=f.process or f.package or f.unit or "",
            reason=f.pkg_summary or f.unit_desc or "",
        ))
    expose.sort(key=lambda r: (r.proto, r.port))
    return Intent(host=host, declared=time.strftime("%Y-%m-%d"), expose=expose, forbid=[])


# --------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------

@dataclass
class IntentVerdict:
    status: IntentStatus
    note: str = ""
    rule: Rule | None = None


@dataclass
class IntentReport:
    verdicts: dict[str, IntentVerdict]     # finding id -> verdict
    missing: list[Rule]                    # declared but not listening

    def count(self, status: IntentStatus) -> int:
        return sum(1 for v in self.verdicts.values() if v.status == status)


def evaluate(findings: list[Finding], intent: Intent | None,
             baseline: set[tuple[int, str]] | None = None) -> IntentReport:
    """
    Compare what is listening against what was declared.

      INTENDED    declared, and actual reach is within the declared reach
      DRIFT       declared, but actual reach is WIDER than declared
      FORBIDDEN   explicitly forbidden, yet listening
      UNDECLARED  listening, not in the intent file at all
      NEW         undeclared AND absent from the last baseline

    Missing = declared under `expose` but nothing is listening there.
    """
    verdicts: dict[str, IntentVerdict] = {}
    present: set[tuple[int, str]] = set()

    for f in findings:
        if f.category != "socket" or not f.port or not f.proto:
            continue
        key = (f.port, f.proto)
        present.add(key)
        actual = _EXPOSURE_TO_REACH.get(f.exposure, "public") if f.exposure else "public"

        if intent is None:
            status: IntentStatus = "UNDECLARED"
            if baseline is not None and key not in baseline:
                status = "NEW"
            verdicts[f.id] = IntentVerdict(status, "no intent file")
            continue

        kind, rule = intent.lookup(f.port, f.proto)
        if kind == "forbid":
            verdicts[f.id] = IntentVerdict(
                "FORBIDDEN", rule.reason or "listed under forbid", rule)
        elif kind == "expose":
            if _REACH_RANK[actual] > _REACH_RANK.get(rule.reach, 0):
                verdicts[f.id] = IntentVerdict(
                    "DRIFT", f"declared {rule.reach}, actually {actual}", rule)
            else:
                verdicts[f.id] = IntentVerdict("INTENDED", rule.reason, rule)
        else:
            status = "UNDECLARED"
            if baseline is not None and key not in baseline:
                status = "NEW"
            verdicts[f.id] = IntentVerdict(status, "not in intent file")

    missing = []
    if intent:
        missing = [r for r in intent.expose if (r.port, r.proto) not in present]

    return IntentReport(verdicts=verdicts, missing=missing)


# --------------------------------------------------------------------------
# Baseline — what listened last time
# --------------------------------------------------------------------------

def load_baseline() -> set[tuple[int, str]] | None:
    p = baseline_path()
    if not p.is_file():
        return None
    try:
        raw = json.loads(p.read_text())
        return {(int(x["port"]), str(x["proto"])) for x in raw.get("sockets", [])}
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        return None


def save_baseline(findings: list[Finding]) -> Path:
    d = config.state_dir()
    d.mkdir(parents=True, exist_ok=True)
    config._give_back(d)
    sockets = sorted({
        (f.port, f.proto) for f in findings
        if f.category == "socket" and f.port and f.proto
    })
    p = baseline_path()
    p.write_text(json.dumps({
        "taken": time.time(),
        "sockets": [{"port": po, "proto": pr} for po, pr in sockets],
    }, indent=2))
    config._give_back(p)
    return p
