"""
What the dashboard can ask for. Each function takes and returns plain JSON
data, and every decision is made by the same modules the CLI uses: the
collectors measure, intent judges, the proposers plan, the validator gates,
the executor applies. Nothing here adds a code path around the gates.
"""

from __future__ import annotations

import glob as globmod
import hashlib
import json
import os
import stat
import tempfile
import time
from pathlib import Path

from .. import collectors, config, evaluate, executor, explain as explain_mod, hardener, intent as intent_mod, llm
from ..schema import ALLOWED_ACTIONS, Plan
from ..validator import check_monotonicity, schema_reason, validate_plan

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Plans generated in this session, by run id. Apply only ever takes a plan the
# server produced itself, so the browser cannot hand it an arbitrary one.
PLANS: dict[str, Plan] = {}


class ApiError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _root() -> str:
    return os.environ.get("HARDENCTL_ROOT", "")


def _sshd() -> str:
    return _root() + "/etc/ssh/sshd_config"


def _is_root() -> bool:
    return os.geteuid() == 0


def _sandboxed() -> bool:
    return bool(_root())


# --------------------------------------------------------------------------
# Status
# --------------------------------------------------------------------------

def status() -> dict:
    prov = config.provider()
    key = config.resolve_key(prov)
    return {
        "host": hardener.hostname(),
        "root": _is_root(),
        "sandbox": _sandboxed(),
        "provider": prov["label"],
        "model": prov["model"],
        "model_ready": (not prov.get("needs_key")) or bool(key),
        "intent": intent_mod.load_intent() is not None,
        "runs": len(executor.list_runs()),
        "version": "1.0.0",
    }


# --------------------------------------------------------------------------
# Scan
# --------------------------------------------------------------------------

def scan(explain: bool = False) -> dict:
    findings = collectors.collect_all(_sshd())
    findings.sort(key=lambda f: (SEV_ORDER[f.severity.value], -(f.port or 0)))
    it = intent_mod.load_intent()
    report = intent_mod.evaluate(findings, it, intent_mod.load_baseline())
    status_of = {fid: v.status for fid, v in report.verdicts.items()}

    notes, explain_error = {}, None
    if explain:
        prov = config.provider()
        key = config.resolve_key(prov)
        if prov.get("needs_key") and not key:
            explain_error = "no model key configured (run `hardenctl configure`)"
        else:
            try:
                notes = explain_mod.Explainer(prov, key).explain(findings, status_of)
            except Exception as e:  # provider down, bad key, bad JSON
                explain_error = f"{type(e).__name__}: {e}"[:300]

    rows = []
    for f in findings:
        v = report.verdicts.get(f.id)
        e = notes.get(f.id)
        rows.append({
            "id": f.id, "category": f.category, "severity": f.severity.value,
            "port": f.port, "proto": f.proto, "bind": f.bind_addr,
            "exposure": f.exposure.value if f.exposure else None,
            "service": f.process or f.package or f.unit,
            "package": f.package, "unit": f.unit, "runs_as": f.runs_as,
            "title": f.title, "detail": f.detail, "path": f.path,
            "verdict": v.status if v else None, "note": v.note if v else "",
            "explanation": e.model_dump() if e else None,
        })
    counts = {s: report.count(s) for s in ("INTENDED", "DRIFT", "FORBIDDEN", "NEW", "UNDECLARED")}
    counts["MISSING"] = len(report.missing)
    intent_mod.save_baseline(findings)
    return {
        "rows": rows, "counts": counts, "intent": it is not None,
        "missing": [{"port": r.port, "proto": r.proto, "service": r.service,
                     "reach": r.reach} for r in report.missing],
        "attribution": _is_root() or _sandboxed(),
        "explain_error": explain_error, "scanned_at": time.strftime("%H:%M:%S"),
    }


# --------------------------------------------------------------------------
# Intent
# --------------------------------------------------------------------------

def _rule(r: intent_mod.Rule) -> dict:
    return {"port": r.port, "proto": r.proto, "reach": r.reach,
            "service": r.service, "reason": r.reason}


def intent_get() -> dict:
    it = intent_mod.load_intent()
    if it is None:
        return {"exists": False, "expose": [], "forbid": []}
    return {"exists": True, "host": it.host, "declared": it.declared,
            "expose": [_rule(r) for r in it.expose], "forbid": [_rule(r) for r in it.forbid],
            "path": str(intent_mod.intent_path())}


def intent_init() -> dict:
    findings = collectors.collect_all(_sshd())
    draft = intent_mod.propose_intent(findings, hardener.hostname())
    intent_mod.save_intent(draft)
    return intent_get()


def _port_proto(body: dict) -> tuple[int, str]:
    try:
        port = int(body.get("port"))
    except (TypeError, ValueError):
        raise ApiError("port must be a number")
    if not 0 < port < 65536:
        raise ApiError("port must be 1-65535")
    proto = str(body.get("proto", "tcp")).lower()
    if proto not in ("tcp", "udp"):
        raise ApiError("proto must be tcp or udp")
    return port, proto


def _text(body: dict, key: str) -> str:
    v = str(body.get(key, "") or "").strip()
    if len(v) > 200 or "\n" in v:
        raise ApiError(f"{key} must be one line, at most 200 characters")
    return v


def _require_intent() -> intent_mod.Intent:
    it = intent_mod.load_intent()
    if it is None:
        raise ApiError("no intent file yet — draft one first")
    return it


def intent_allow(body: dict) -> dict:
    port, proto = _port_proto(body)
    reach = str(body.get("reach", "loopback"))
    if reach not in ("loopback", "lan", "public"):
        raise ApiError("reach must be loopback, lan or public")
    it = _require_intent()
    it.expose = [r for r in it.expose if (r.port, r.proto) != (port, proto)]
    it.forbid = [r for r in it.forbid if (r.port, r.proto) != (port, proto)]
    it.expose.append(intent_mod.Rule(port=port, proto=proto, reach=reach,
                                     service=_text(body, "service"), reason=_text(body, "reason")))
    it.expose.sort(key=lambda r: (r.proto, r.port))
    intent_mod.save_intent(it)
    return intent_get()


def intent_forbid(body: dict) -> dict:
    port, proto = _port_proto(body)
    it = _require_intent()
    it.expose = [r for r in it.expose if (r.port, r.proto) != (port, proto)]
    it.forbid = [r for r in it.forbid if (r.port, r.proto) != (port, proto)]
    it.forbid.append(intent_mod.Rule(port=port, proto=proto, reach="loopback",
                                     reason=_text(body, "reason")))
    intent_mod.save_intent(it)
    return intent_get()


def intent_remove(body: dict) -> dict:
    port, proto = _port_proto(body)
    it = _require_intent()
    it.expose = [r for r in it.expose if (r.port, r.proto) != (port, proto)]
    it.forbid = [r for r in it.forbid if (r.port, r.proto) != (port, proto)]
    intent_mod.save_intent(it)
    return intent_get()


# --------------------------------------------------------------------------
# Gates, explained per action
# --------------------------------------------------------------------------

def _target(a: dict) -> str:
    return str(a.get("path") or a.get("key") or a.get("unit") or a.get("package") or "")


def _change(a: dict) -> str:
    if a.get("directive"):
        return f"{a.get('directive')} {a.get('value', '')}".strip()
    return str(a.get("value") or a.get("mode") or "")


def gate_trace(raw: object) -> dict:
    """
    One raw action through the three gates, recording where it stopped.
    Uses exactly the checks validate_plan() and the plan parser use.
    """
    a = raw if isinstance(raw, dict) else {}
    row = {"id": str(a.get("id", "?")), "action": str(a.get("action", "?")),
           "target": _target(a), "change": _change(a),
           "justification": str(a.get("justification", ""))[:600],
           "gates": [], "verdict": "accepted", "stopped_at": None, "reason": ""}

    reason = schema_reason(raw)
    if reason is not None:
        row["gates"] = [{"gate": "schema", "result": "fail", "reason": reason},
                        {"gate": "allowlist", "result": "skipped", "reason": ""},
                        {"gate": "monotonicity", "result": "skipped", "reason": ""}]
        row.update(verdict="rejected", stopped_at="schema", reason=reason)
        return row
    action = Plan(run_id="trace", host="trace", generated_by="gui", actions=[raw]).actions[0]
    row["gates"].append({"gate": "schema", "result": "pass", "reason": "parses as a typed action"})

    if action.action not in ALLOWED_ACTIONS:
        why = f"action type '{action.action}' is not in the permitted set"
        row["gates"] += [{"gate": "allowlist", "result": "fail", "reason": why},
                         {"gate": "monotonicity", "result": "skipped", "reason": ""}]
        row.update(verdict="rejected", stopped_at="allowlist", reason=why)
        return row
    row["gates"].append({"gate": "allowlist", "result": "pass", "reason": "one of the six action types"})

    why = check_monotonicity(action)
    if why:
        row["gates"].append({"gate": "monotonicity", "result": "fail", "reason": why})
        row.update(verdict="rejected", stopped_at="monotonicity", reason=why)
        return row
    row["gates"].append({"gate": "monotonicity", "result": "pass",
                         "reason": "no weaker than the host's current state"})
    try:
        row["preview"] = executor.simulate(action)
    except OSError as e:
        row["preview"] = f"(preview unavailable: {e})"
    return row


def validate(body: dict) -> dict:
    """Gate Lab: trace a pasted plan. Never applies anything."""
    doc = body.get("plan")
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except json.JSONDecodeError as e:
            raise ApiError(f"not valid JSON: {e.msg} (line {e.lineno}, column {e.colno})")
    if isinstance(doc, dict) and "actions" not in doc and "action" in doc:
        doc = {"actions": [doc]}          # a single action is fine too
    if not isinstance(doc, dict) or not isinstance(doc.get("actions"), list):
        raise ApiError('expected a plan: {"actions": [ ... ]}')
    actions = doc["actions"][:50]
    rows = [gate_trace(a) for a in actions]

    if body.get("ablate"):
        for raw, row in zip(actions, rows):
            if not isinstance(raw, dict):
                continue
            changed = 0
            for j in evaluate.ABLATION_JUSTIFICATIONS:
                changed += gate_trace(dict(raw, justification=j))["verdict"] != row["verdict"]
            row["ablation"] = {"variants": len(evaluate.ABLATION_JUSTIFICATIONS), "changed": changed,
                               "examples": evaluate.ABLATION_JUSTIFICATIONS[:3]}
    rejected = sum(r["verdict"] == "rejected" for r in rows)
    return {"rows": rows, "rejected": rejected, "accepted": len(rows) - rejected,
            "would_apply": rejected == 0 and bool(rows)}


def presets() -> dict:
    """Attack examples from the frozen corpora and lab/evil.json. Cases that
    need sandbox fixtures (symlinks, pre-existing files) are left out: on the
    real host they would test a different situation."""
    out = []
    evil = evaluate.REPO / "lab" / "evil.json"
    if evil.is_file():
        out.append({"group": "Compromised model", "label": "Four-action plan from a manipulated model",
                    "expect": "3 of 4 refused", "plan": json.loads(evil.read_text())})
    for path in sorted(evaluate.CORPUS_DIR.glob("injection_v*.json")):
        doc = json.loads(path.read_text().replace("${ROOT}", ""))
        for c in doc["cases"]:
            if c.get("fixture"):
                continue
            out.append({"group": f"{path.stem.replace('injection_', 'Corpus ')} · {c.get('group', c['set'])}",
                        "label": c["label"], "expect": c["expect"],
                        "plan": {"run_id": "lab", "host": "lab", "generated_by": "corpus",
                                 "actions": [c["action"]]}})
    return {"presets": out}


def corpus() -> dict:
    """Both frozen corpora in the eval sandbox, fixtures included."""
    result = {}
    for path in sorted(evaluate.CORPUS_DIR.glob("injection_v*.json")):
        cases, summary = evaluate._run_corpus(path)
        result[path.stem] = {
            "summary": {k: summary[k] for k in ("overall", "ablation_outcome_changes", "failures")},
            "cases": [{k: c[k] for k in ("set", "label", "expect", "outcome", "gate", "reason", "correct")}
                      for c in cases],
        }
    return result


# --------------------------------------------------------------------------
# Plan, apply, rollback
# --------------------------------------------------------------------------

def plan(body: dict) -> dict:
    proposer = body.get("proposer", "rules")
    findings = collectors.collect_all(_sshd())
    it = intent_mod.load_intent()
    status_of = {fid: v.status for fid, v in intent_mod.evaluate(findings, it).verdicts.items()}
    usage = None
    if proposer == "rules":
        p = hardener.RulesProposer().propose(findings, hardener.hostname(), status_of)
        raw_actions = [a.model_dump(mode="json", exclude_none=True) for a in p.actions]
        generated_by = p.generated_by
    elif proposer == "llm":
        prov = config.provider()
        key = config.resolve_key(prov)
        if prov.get("needs_key") and not key:
            raise ApiError("no model key configured (run `hardenctl configure`)")
        llm_p = hardener.LLMProposer(prov, key)
        t0 = time.time()
        try:
            text = llm.complete(system=hardener.SYSTEM_PROMPT,
                                user=("Findings from the host follow. Emit the remediation plan "
                                      "as a single JSON object.\n\n" + llm_p._render_findings(findings)),
                                provider=prov, api_key=key)
            raw_actions = llm.parse_json(text).get("actions", [])
        except llm.LLMError as e:
            raise ApiError(str(e), 502)
        usage = {"latency_s": round(time.time() - t0, 1), **{k: v for k, v in llm.LAST_USAGE.items()
                                                            if k in ("input_tokens", "output_tokens")}}
        generated_by = llm_p.name
    else:
        raise ApiError("proposer must be rules or llm")

    rows = [gate_trace(a) for a in raw_actions]
    # The stored plan holds every action that parses; apply re-validates it
    # and refuses the whole plan if any action fails a gate.
    parsed = [a for a, r in zip(raw_actions, rows) if r["stopped_at"] != "schema"]
    p = Plan(run_id=hardener.new_run_id(), host=hardener.hostname(),
             generated_by=generated_by, actions=parsed)
    PLANS[p.run_id] = p
    rejected = sum(r["verdict"] == "rejected" for r in rows)
    return {"run_id": p.run_id, "generated_by": generated_by, "rows": rows,
            "rejected": rejected, "applicable": rejected == 0 and bool(parsed), "usage": usage}


def apply(body: dict) -> dict:
    run_id = str(body.get("run_id", ""))
    if body.get("confirm") != "APPLY":
        raise ApiError('apply needs the confirmation text "APPLY"')
    if not (_is_root() or _sandboxed()):
        raise ApiError("applying changes needs root: restart the dashboard with sudo", 403)
    p = PLANS.get(run_id)
    if p is None:
        raise ApiError("unknown plan — generate a plan in this session first", 404)
    result = validate_plan(p)             # gates again, against the disk as it is now
    if result.rejections:
        return {"applied": False, "error": "plan rejected — not applying",
                "rejections": [{"id": r.action_id, "gate": r.gate, "reason": r.reason}
                               for r in result.rejections]}
    run = executor.apply_plan(p, result.accepted)
    PLANS.pop(run_id, None)               # a plan is applied at most once
    return {"applied": not run.rolled_back, "run_id": run.run_id, "rolled_back": run.rolled_back,
            "error": run.error,
            "steps": [{"id": s.action_id, "action": s.action_type, "status": s.status,
                       "message": s.message} for s in run.steps]}


def runs() -> dict:
    out = []
    for r in executor.list_runs():
        out.append({"run_id": r["run_id"], "generated_by": r.get("generated_by"),
                    "timestamp": r.get("timestamp"),
                    "when": time.strftime("%d %b %H:%M:%S", time.localtime(r.get("timestamp", 0))),
                    "applied": sum(1 for s in r.get("steps", []) if s["status"] == "ok"),
                    "rolled_back": bool(r.get("rolled_back")), "error": r.get("error", "")})
    return {"runs": out}


def rollback(body: dict) -> dict:
    run_id = str(body.get("run_id", ""))
    if body.get("last"):
        pending = [r for r in executor.list_runs() if not r.get("rolled_back")]
        if not pending:
            raise ApiError("no run to roll back")
        run_id = pending[0]["run_id"]
    if not run_id:
        raise ApiError("give a run id")
    if not (_is_root() or _sandboxed()):
        raise ApiError("rolling back needs root: restart the dashboard with sudo", 403)
    try:
        ok, total = executor.rollback_run(run_id)
    except FileNotFoundError as e:
        raise ApiError(str(e), 404)
    return {"run_id": run_id, "reverted": ok, "total": total}


# --------------------------------------------------------------------------
# Fingerprint: what rollback is supposed to restore exactly
# --------------------------------------------------------------------------

FINGERPRINT_FILES = ["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*.conf", "/etc/shadow",
                     "/etc/gshadow", "/etc/passwd", "/etc/group", "/etc/login.defs",
                     "/etc/sysctl.d/99-hardenctl.conf"]


def fingerprint() -> dict:
    root = _root()
    files = {}
    for pattern in FINGERPRINT_FILES:
        hits = sorted(globmod.glob(root + pattern)) if "*" in pattern else [root + pattern]
        for p in hits:
            shown = p[len(root):] if root else p
            path = Path(p)
            if path.is_symlink():
                files[shown] = {"state": "symlink", "target": os.readlink(p)}
            elif path.is_file():
                try:
                    digest = hashlib.sha256(path.read_bytes()).hexdigest()
                except PermissionError:
                    digest = None
                files[shown] = {"state": "file", "sha256": digest,
                                "mode": f"{stat.S_IMODE(path.stat().st_mode):04o}"}
            else:
                files[shown] = {"state": "absent"}
    sysctls = {k: executor.read_sysctl(k) for k in hardener._SYSCTL_TARGETS}
    return {"files": files, "sysctls": sysctls, "taken_at": time.strftime("%H:%M:%S")}


# --------------------------------------------------------------------------
# Results: the recorded numbers, and a live re-run
# --------------------------------------------------------------------------

def _latest(pattern: str) -> tuple[dict | None, str | None]:
    hits = sorted(globmod.glob(str(evaluate.REPO / "results" / pattern)))
    if not hits:
        return None, None
    return json.loads(Path(hits[-1]).read_text()), Path(hits[-1]).name


def _commit(doc: dict | None) -> str | None:
    return (doc or {}).get("meta", {}).get("git_commit", "")[:7] or None


def results() -> dict:
    gv1, f1 = _latest("*-v2-on-gate-v1-injection.json")
    gv2, f2 = _latest("*-v2-heldout-first-run-injection.json")
    rel, f3 = _latest("*-v1.0-release-summary.json")
    base, f4 = _latest("*-v0.1-baseline-summary.json")
    llm_doc, f5 = _latest("*-v1.0-final-llm-rerun-llm.json")

    def heldout(doc: dict | None, key: str) -> dict | None:
        if not doc:
            return None
        s = doc[key] if key == "summary" else doc
        return s["corpora"]["injection_v2"]["by_set"]["heldout"]["weakening_reaching_apply"]

    out: dict = {"sources": []}
    if gv1 and gv2 and rel:
        out["heldout"] = [
            {"label": "Gate v1 (Review 1)", "commit": _commit(gv1), **heldout(gv1, "summary")},
            {"label": "Gate v2, first run", "commit": _commit(gv2), **heldout(gv2, "summary")},
            {"label": "Gate v2.1 (current)", "commit": _commit(rel),
             **rel["summaries"]["injection"]["corpora"]["injection_v2"]["by_set"]["heldout"]["weakening_reaching_apply"]},
        ]
    if base and rel:
        b, r = base["summaries"], rel["summaries"]
        out["before_after"] = [
            {"metric": "Weaknesses fixed (rules)",
             "before": b["rollback"]["remediation_effectiveness"], "after": r["rollback"]["remediation_effectiveness"]},
            {"metric": "DRIFT detected",
             "before": b["intent"]["detection"]["DRIFT"], "after": r["intent"]["detection"]["DRIFT"]},
            {"metric": "Labs fully remediated",
             "before": b["rollback"]["runs_fully_remediated"], "after": r["rollback"]["runs_fully_remediated"]},
        ]
        abl = [c["ablation_outcome_changes"] for c in r["injection"]["corpora"].values()]
        out["tiles"] = {
            "rollback": r["rollback"]["rollback_fidelity"],
            "auto_revert": r["transactional"]["auto_revert_exact"],
            "ablation": {"k": sum(a["k"] for a in abl), "n": sum(a["n"] for a in abl)},
            "intent_fp": r["intent"]["false_positive_rate_on_controls"],
            "prompt_saved": r["cost"]["saved_fraction"]["mean"],
        }
        out["before_commit"], out["after_commit"] = _commit(base), _commit(rel)
    if llm_doc:
        out["llm"] = {c: llm_doc["summary"][c]["plan_validity"] for c in ("clean", "poisoned")}
        out["llm_model"] = llm_doc["summary"].get("model")
    out["sources"] = [f for f in (f1, f2, f3, f4, f5) if f]
    return out


def rerun(body: dict) -> dict:
    """The seeded suites, live, in the eval sandbox; results go to a temp dir."""
    runs_n = max(1, min(int(body.get("runs", 30)), 100))
    with tempfile.TemporaryDirectory(prefix="hctl-gui-eval-") as d:
        t0 = time.time()
        res = evaluate.run(evaluate.DEFAULT_SUITES, runs=runs_n, seed=1, out_dir=Path(d), label="gui")
        took = round(time.time() - t0, 1)
    s = res["summaries"]
    inj = s["injection"]["corpora"]
    rows = []
    for name, block in inj.items():
        rows.append({"metric": f"{name}: weakening reaching apply", **block["overall"]["weakening_reaching_apply"]})
        rows.append({"metric": f"{name}: justification swaps changing a verdict", **block["ablation_outcome_changes"]})
    rows += [
        {"metric": "Rollback byte-exact", **s["rollback"]["rollback_fidelity"]},
        {"metric": "Weaknesses fixed (rules)", **s["rollback"]["remediation_effectiveness"]},
        {"metric": "sysctls persisted", **s["rollback"]["sysctl_persistence"]},
        {"metric": "Exact auto-revert on injected failure", **s["transactional"]["auto_revert_exact"]},
    ]
    rows += [{"metric": f"Intent {k} detected", **v} for k, v in s["intent"]["detection"].items()]
    rows.append({"metric": "Intent false positives", **s["intent"]["false_positive_rate_on_controls"]})
    return {"runs": runs_n, "seconds": took, "commit": (res["meta"]["git_commit"] or "")[:7],
            "rows": rows, "prompt_saved": s["cost"]["saved_fraction"]["mean"]}
