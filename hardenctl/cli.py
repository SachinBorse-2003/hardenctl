"""hardenctl command line interface."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from . import collectors, config, executor, explain as explain_mod, hardener, intent as intent_mod, llm

cfg = config
from .schema import Exposure, Plan, Severity
from .validator import validate_plan

app = typer.Typer(add_completion=False, help="Agentic Linux hardening with rollback.")
console = Console()

SEV_COLOR = {
    Severity.CRITICAL: "bold red", Severity.HIGH: "red",
    Severity.MEDIUM: "yellow", Severity.LOW: "cyan", Severity.INFO: "dim",
}
SEV_ORDER = {s: i for i, s in enumerate(
    [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO])}


def _consent(assume_yes: bool) -> None:
    if assume_yes:
        return
    console.print(
        "[yellow]This will inspect and modify this host. Only proceed on a "
        "machine you own or are authorised to change.[/yellow]")
    if not typer.confirm("Confirm authorisation"):
        raise typer.Abort()


def ensure_key(provider: dict) -> str | None:
    """
    Resolve an API key, prompting once and offering to save it.

    Called only when a command actually needs the model, so the deterministic
    commands never ask for a credential they will not use.
    """
    if not provider.get("needs_key"):
        return None

    key = config.resolve_key(provider)
    if key:
        return key

    console.print(f"[yellow]No API key found for {provider['label']}.[/yellow]")
    console.print("[dim]Set one now, or press Ctrl-C and run "
                  "`hardenctl configure` to pick a different provider "
                  "(including a local model that needs no key).[/dim]")
    key = typer.prompt(f"  {provider['label']} API key", hide_input=True).strip()
    if not key:
        raise typer.Abort()

    if typer.confirm(f"  Save it to {config.config_path()}? (mode 0600)", default=True):
        path = config.save_key(key, provider["name"])
        console.print(f"[green]saved to {path}[/green]\n")
    return key


def _load_plan(plan_file: str) -> Plan:
    """Parse a plan file (gate 1). A failure is reported like any other
    rejection, per action, and nothing is applied."""
    from pydantic import ValidationError
    from .validator import schema_reason
    try:
        raw = json.loads(Path(plan_file).read_text())
    except (OSError, json.JSONDecodeError) as e:
        console.print(f"[red]cannot read plan: {e}[/red]")
        raise typer.Exit(1)
    try:
        return Plan(**raw)
    except (ValidationError, TypeError):
        console.print("[bold red]plan rejected — not applying[/bold red]")
        actions = raw.get("actions", []) if isinstance(raw, dict) else []
        shown = 0
        for a in actions if isinstance(actions, list) else []:
            reason = schema_reason(a)
            if reason:
                aid = a.get("id", "?") if isinstance(a, dict) else "?"
                console.print(f"  [red]✗[/red] {aid} \\[schema] {reason}")
                shown += 1
        if not shown:
            console.print("  [red]✗[/red] \\[schema] the plan document itself is malformed")
        raise typer.Exit(1)


@app.command()
def configure(
    show: bool = typer.Option(False, "--show", help="Print current settings and exit."),
    clear: bool = typer.Option(False, "--clear", help="Remove the stored key."),
):
    """Choose a model provider and store its API key."""
    if clear:
        msg = "stored key removed" if config.clear_key() else "no stored key"
        console.print(msg)
        return

    p = config.provider()
    if show:
        console.print(f"provider : {p['name']} ({p['label']})")
        console.print(f"model    : {p['model']}")
        console.print(f"endpoint : {p['base_url']}")
        console.print(f"key      : {config.masked(config.resolve_key(p))}")
        console.print(f"config   : {config.config_path()}")
        return

    console.print("[bold]Available providers[/bold]")
    names = list(config.PROVIDERS)
    for i, name in enumerate(names, 1):
        pr = config.PROVIDERS[name]
        mark = " [green](current)[/green]" if name == p["name"] else ""
        console.print(f"  {i}. {pr['label']}{mark}")
        console.print(f"     [dim]{pr['model']}[/dim]")

    idx = typer.prompt("\nProvider", default=str(names.index(p["name"]) + 1))
    try:
        chosen = names[int(idx) - 1]
    except (ValueError, IndexError):
        console.print("[red]invalid choice[/red]")
        raise typer.Exit(1)

    pr = dict(config.PROVIDERS[chosen])
    pr["name"] = chosen
    cfg = config.load_config()
    cfg["provider"] = chosen

    model = typer.prompt("Model", default=pr["model"])
    cfg["model"] = model

    if pr["needs_key"]:
        key = typer.prompt(f"{pr['label']} API key ({pr['key_hint']})",
                           hide_input=True).strip()
        if key:
            cfg["api_key"] = key
        if chosen == "anthropic":
            ws = typer.prompt(
                "Workspace id (blank unless your key is identity-linked)",
                default=cfg.get("workspace_id", ""), show_default=False).strip()
            if ws:
                cfg["workspace_id"] = ws
            else:
                cfg.pop("workspace_id", None)
        if chosen == "anthropic":
            console.print("[dim]Identity-linked keys (from Claude Code or an "
                          "org login) also need a workspace ID. Leave blank "
                          "for a standard console key.[/dim]")
            ws = typer.prompt("Workspace ID", default="").strip()
            if ws:
                cfg["workspace_id"] = ws
            else:
                cfg.pop("workspace_id", None)
    else:
        cfg.pop("api_key", None)
        console.print("[dim]No key needed for a local provider.[/dim]")

    path = config.save_config(cfg)
    console.print(f"[green]saved to {path}[/green]")


@app.command()
def scan(
    sshd: str = typer.Option("/etc/ssh/sshd_config", help="Path to sshd_config."),
    output: str = typer.Option("", "--json", help="Write findings JSON here."),
    explain: bool = typer.Option(False, "--explain",
                                 help="Ask the model about undeclared services."),
):
    """Enumerate attack surface, compare against intent, rank findings."""
    findings = collectors.collect_all(sshd)
    findings.sort(key=lambda f: (SEV_ORDER[f.severity], -(f.port or 0)))

    if os.geteuid() != 0 and any(f.category == "socket" for f in findings):
        console.print("[yellow]running without root — process and package "
                      "attribution unavailable. Re-run with sudo.[/yellow]\n")

    intent = intent_mod.load_intent()
    baseline = intent_mod.load_baseline()
    report = intent_mod.evaluate(findings, intent, baseline)
    status_of = {fid: v.status for fid, v in report.verdicts.items()}

    notes = {}
    if explain:
        try:
            prov = config.provider()
            key = ensure_key(prov)
            n_ask = sum(1 for f in findings if f.category == "socket"
                        and status_of.get(f.id) != "INTENDED")
            with console.status(f"asking {prov['label']} about {n_ask} undeclared service(s)..."):
                notes = explain_mod.Explainer(prov, key).explain(findings, status_of)
        except llm.LLMError as e:
            console.print(f"[red]{e}[/red]\n")
        except typer.Abort:
            raise
        except Exception as e:
            console.print(f"[red]explain failed: {type(e).__name__}: {e}[/red]\n")

    INTENT_COLOR = {"INTENDED": "green", "DRIFT": "bold yellow", "FORBIDDEN": "bold red",
                    "NEW": "bold red", "UNDECLARED": "yellow"}
    VERDICT_COLOR = {"EXPECTED": "green", "REVIEW": "yellow",
                     "CLOSE": "bold red", "UNKNOWN": "dim"}

    table = Table(title=f"hardenctl scan — {hardener.hostname()}", header_style="bold")
    cols = ["SEVERITY", "PORT", "SERVICE", "EXPOSURE", "INTENT"]
    cols += ["VERDICT", "WHY"] if explain else ["FINDING"]
    for col in cols:
        table.add_column(col, overflow="fold")

    for f in findings:
        sev = f"[{SEV_COLOR[f.severity]}]{f.severity.value}[/]"
        expo = f.exposure.value if f.exposure else "—"
        svc = f.process or f.package or f.unit or "—"
        v = report.verdicts.get(f.id)
        if v:
            intent_cell = f"[{INTENT_COLOR[v.status]}]{v.status}[/]"
            if v.status == "DRIFT":
                intent_cell += f"\n[dim]{v.note}[/dim]"
        else:
            intent_cell = "[dim]—[/dim]"

        if explain:
            e = notes.get(f.id)
            if v and v.status == "INTENDED":
                verdict = "[green]EXPECTED[/green]"
                why = f"[dim]declared: {v.note or v.rule.service}[/dim]" if v.rule else "[dim]declared[/dim]"
            elif e:
                verdict = f"[{VERDICT_COLOR[e.verdict]}]{e.verdict}[/]"
                why = f"{e.purpose} [dim]({e.confidence.lower()})[/dim]"
            else:
                verdict = "[dim]—[/dim]"
                why = f.pkg_summary or f.unit_desc or "[dim]—[/dim]"
            table.add_row(sev, str(f.port or "—"), svc, expo, intent_cell, verdict, why)
        else:
            table.add_row(sev, str(f.port or "—"), svc, expo, intent_cell, f.title)

    console.print(table)

    # summary line
    parts = []
    for st in ("INTENDED", "DRIFT", "FORBIDDEN", "NEW", "UNDECLARED"):
        n = report.count(st)
        if n:
            parts.append(f"[{INTENT_COLOR[st]}]{n} {st.lower()}[/]")
    if report.missing:
        parts.append(f"[bold red]{len(report.missing)} missing[/]")
    if intent is None:
        console.print("[dim]no intent file — run `hardenctl intent init` to declare "
                      "what this host should expose[/dim]")
    else:
        console.print("  ".join(parts) if parts else "[dim]nothing listening[/dim]")
        for r in report.missing:
            console.print(f"  [red]MISSING[/red] {r.proto}/{r.port} {r.service} — declared but not listening")
    if explain and notes:
        console.print("[dim]VERDICT and WHY on undeclared rows are model-inferred. "
                      "INTENT is measured against your declaration.[/dim]")

    intent_mod.save_baseline(findings)

    if output:
        Path(output).write_text(json.dumps(
            [f.model_dump(mode="json") for f in findings], indent=2))
        console.print(f"[green]findings written to {output}[/green]")


@app.command()
def plan(
    proposer: str = typer.Option("rules", help="rules | llm"),
    sshd: str = typer.Option("/etc/ssh/sshd_config"),
    findings_file: str = typer.Option("", "--findings", help="Reuse a scan JSON."),
    output: str = typer.Option("", "--out", help="Write plan JSON here."),
):
    """Generate a validated hardening plan. Does not modify anything."""
    if findings_file:
        from .schema import Finding
        raw = json.loads(Path(findings_file).read_text())
        found = [Finding(**r) for r in raw]
    else:
        found = collectors.collect_all(sshd)

    it = intent_mod.load_intent()
    status_of = {fid: v.status for fid, v in intent_mod.evaluate(found, it).verdicts.items()}
    try:
        prop = hardener.get_proposer(proposer)
        if proposer == "rules":
            p = prop.propose(found, hardener.hostname(), status_of)
        else:
            p = prop.propose(found, hardener.hostname())
    except Exception as e:
        console.print(f"[red]plan synthesis failed: {e}[/red]")
        raise typer.Exit(1)

    result = validate_plan(p)

    table = Table(title=f"plan {p.run_id} — {p.generated_by}", header_style="bold")
    for col in ("ID", "ACTION", "TARGET", "CHANGE", "RISK"):
        table.add_column(col, overflow="fold")
    for a in result.accepted:
        target = getattr(a, "path", None) or getattr(a, "key", None) \
            or getattr(a, "unit", None) or getattr(a, "package", "")
        change = getattr(a, "value", None) or getattr(a, "mode", None) or "—"
        detail = f"{getattr(a, 'directive', '')} {change}".strip()
        table.add_row(a.id, a.action, str(target), detail, a.break_risk.value)
    console.print(table)

    if result.rejections:
        console.print("\n[bold red]REJECTED[/bold red]")
        for r in result.rejections:
            console.print(f"  [red]✗[/red] {r.action_id} \\[{r.gate}] {r.reason}")

    console.print(f"\n[dim]{result.summary()}[/dim]")

    if output:
        Path(output).write_text(p.model_dump_json(indent=2))
        console.print(f"[green]plan written to {output}[/green]")


@app.command()
def apply(
    plan_file: str = typer.Argument(..., help="Plan JSON from `plan --out`."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the consent prompt."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show changes only."),
):
    """Validate and apply a plan, with automatic rollback on failure."""
    p = _load_plan(plan_file)
    result = validate_plan(p)

    if result.rejections:
        console.print("[bold red]plan rejected — not applying[/bold red]")
        for r in result.rejections:
            console.print(f"  [red]✗[/red] {r.action_id} \\[{r.gate}] {r.reason}")
        raise typer.Exit(1)

    if dry_run:
        for a in result.accepted:
            console.print(f"  [cyan]would:[/cyan] {executor.simulate(a)}")
        console.print(f"\n[dim]{len(result.accepted)} action(s), nothing applied[/dim]")
        return

    _consent(yes)
    run = executor.apply_plan(p, result.accepted)

    for s in run.steps:
        icon = {"ok": "[green]✓[/green]", "skipped": "[yellow]–[/yellow]",
                "failed": "[red]✗[/red]"}[s.status]
        console.print(f"  {icon} {s.action_id}  {s.message}")

    if run.rolled_back:
        console.print(f"\n[bold red]{run.error}[/bold red]")
        console.print("[yellow]all changes in this run were reverted[/yellow]")
        raise typer.Exit(1)

    console.print(f"\n[green]{run.applied} action(s) applied[/green]")
    console.print(f"[dim]rollback with: hardenctl rollback {run.run_id}[/dim]")


@app.command()
def rollback(
    run_id: str = typer.Argument("", help="Run ID to revert."),
    last: bool = typer.Option(False, "--last", help="Revert the most recent run."),
):
    """Revert a completed run."""
    if last:
        rs = [r for r in executor.list_runs() if not r.get("rolled_back")]
        if not rs:
            console.print("[dim]no un-reverted runs[/dim]")
            raise typer.Exit(1)
        run_id = rs[0]["run_id"]
    if not run_id:
        console.print("[red]give a run id or --last[/red]")
        raise typer.Exit(1)
    try:
        ok, total = executor.rollback_run(run_id)
    except FileNotFoundError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)
    console.print(f"[green]reverted {ok}/{total} action(s) from run {run_id}[/green]")


intent_app = typer.Typer(help="Declare and inspect what this host should expose.")
app.add_typer(intent_app, name="intent")


@intent_app.command("init")
def intent_init(
    sshd: str = typer.Option("/etc/ssh/sshd_config"),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing intent file."),
):
    """Draft intent.yaml from the current state, for you to edit and ratify."""
    p = intent_mod.intent_path()
    if p.is_file() and not force:
        console.print(f"[yellow]{p} already exists — use --force to overwrite[/yellow]")
        raise typer.Exit(1)
    findings = collectors.collect_all(sshd)
    draft = intent_mod.propose_intent(findings, hardener.hostname())
    path = intent_mod.save_intent(draft)
    console.print(f"[green]drafted {len(draft.expose)} rule(s) → {path}[/green]")
    console.print("[dim]This is a proposal from the current state. Open it, tighten "
                  "reach where you can, move anything unwanted under `forbid`, "
                  "then re-scan.[/dim]")


@intent_app.command("show")
def intent_show():
    """Print the current intent file."""
    p = intent_mod.intent_path()
    if not p.is_file():
        console.print("[dim]no intent file[/dim]")
        raise typer.Exit(1)
    console.print(p.read_text())


@intent_app.command("allow")
def intent_allow(
    port: int = typer.Argument(...),
    proto: str = typer.Option("tcp"),
    reach: str = typer.Option("loopback", help="loopback | lan | public"),
    service: str = typer.Option("", help="Name of the service."),
    reason: str = typer.Option("", help="Why this is supposed to listen."),
):
    """Declare a port as intended, at a given reach."""
    if reach not in ("loopback", "lan", "public"):
        console.print("[red]reach must be loopback, lan or public[/red]")
        raise typer.Exit(1)
    it = intent_mod.load_intent()
    if it is None:
        console.print("[red]no intent file — run `hardenctl intent init` first[/red]")
        raise typer.Exit(1)
    it.expose = [r for r in it.expose if not (r.port == port and r.proto == proto)]
    it.forbid = [r for r in it.forbid if not (r.port == port and r.proto == proto)]
    it.expose.append(intent_mod.Rule(port=port, proto=proto, reach=reach,
                                     service=service, reason=reason))
    it.expose.sort(key=lambda r: (r.proto, r.port))
    intent_mod.save_intent(it)
    console.print(f"[green]{proto}/{port} declared: reach={reach}[/green]")


@intent_app.command("forbid")
def intent_forbid(
    port: int = typer.Argument(...),
    proto: str = typer.Option("tcp"),
    reason: str = typer.Option("", help="Why this must never listen."),
):
    """Move a port to the forbid list."""
    it = intent_mod.load_intent()
    if it is None:
        console.print("[red]no intent file — run `hardenctl intent init` first[/red]")
        raise typer.Exit(1)
    it.expose = [r for r in it.expose if not (r.port == port and r.proto == proto)]
    it.forbid = [r for r in it.forbid if not (r.port == port and r.proto == proto)]
    it.forbid.append(intent_mod.Rule(port=port, proto=proto, reach="loopback", reason=reason))
    intent_mod.save_intent(it)
    console.print(f"[green]{proto}/{port} is now forbidden[/green]")


@app.command()
def runs():
    """List past runs."""
    rs = executor.list_runs()
    if not rs:
        console.print("[dim]no runs recorded[/dim]")
        return
    table = Table(header_style="bold")
    for col in ("RUN ID", "HOST", "PROPOSER", "ACTIONS", "STATUS"):
        table.add_column(col)
    for r in rs:
        applied = sum(1 for s in r.get("steps", []) if s["status"] == "ok")
        status = "[yellow]rolled back[/yellow]" if r.get("rolled_back") else "[green]applied[/green]"
        table.add_row(r["run_id"], r.get("host", "—"),
                      r.get("generated_by", "—"), str(applied), status)
    console.print(table)


@app.command("eval")
def eval_cmd(
    suite: list[str] = typer.Option(
        [], "--suite", "-s",
        help="injection | rollback | transactional | intent | cost | llm (repeatable). "
             "Default: all but llm."),
    runs: int = typer.Option(30, help="Seeded runs per suite."),
    seed: int = typer.Option(1, help="Base seed; fixed seeds make runs repeatable."),
    llm_runs: int = typer.Option(0, "--llm-runs",
                                 help="Runs per condition for the llm suite (sends "
                                      "sandbox findings to the configured model)."),
    out: str = typer.Option("", help="Results directory (default: <repo>/results)."),
    label: str = typer.Option("", help="Tag added to result file names."),
):
    """Run the evaluation harness in a sandbox and write raw JSON results."""
    from . import evaluate

    suites = list(suite) or list(evaluate.DEFAULT_SUITES)
    if llm_runs and "llm" not in suites:
        suites.append("llm")
    unknown = [s for s in suites if s not in evaluate.SUITES]
    if unknown:
        console.print(f"[red]unknown suite(s): {', '.join(unknown)}[/red]")
        raise typer.Exit(1)
    if "llm" in suites and not llm_runs:
        llm_runs = 5

    with console.status(f"running {', '.join(suites)} ..."):
        res = evaluate.run(suites, runs=runs, seed=seed, llm_runs=llm_runs,
                           out_dir=Path(out) if out else None, label=label)

    def fmt(r: dict) -> str:
        if not isinstance(r, dict) or "k" not in r:
            return "—"
        lo, hi = r["ci95"]
        return f"{r['k']}/{r['n']}  ({r['rate']:.1%}, 95% CI {lo:.1%}–{hi:.1%})" if r["n"] else "0/0"

    s = res["summaries"]
    table = Table(title="hardenctl eval", header_style="bold")
    table.add_column("METRIC")
    table.add_column("RESULT")
    for name, block in (s.get("injection") or {}).get("corpora", {}).items():
        table.add_row(f"{name}: correct", fmt(block["overall"]["correct"]))
        table.add_row(f"{name}: weakening reaching apply",
                      fmt(block["overall"]["weakening_reaching_apply"]))
        table.add_row(f"{name}: justification ablation changes",
                      fmt(block["ablation_outcome_changes"]))
    if "rollback" in s:
        table.add_row("rollback fidelity", fmt(s["rollback"]["rollback_fidelity"]))
        table.add_row("remediation effectiveness (rules)",
                      fmt(s["rollback"]["remediation_effectiveness"]))
        if "sysctl_persistence" in s["rollback"]:
            table.add_row("sysctl persistence", fmt(s["rollback"]["sysctl_persistence"]))
    if "transactional" in s:
        table.add_row("auto-revert exact on failure", fmt(s["transactional"]["auto_revert_exact"]))
    if "intent" in s:
        for lbl, r in s["intent"]["detection"].items():
            table.add_row(f"intent {lbl} detected", fmt(r))
        table.add_row("intent MISSING detected", fmt(s["intent"]["missing_detection"]))
        table.add_row("intent false positives (controls)",
                      fmt(s["intent"]["false_positive_rate_on_controls"]))
    if "cost" in s:
        table.add_row("explainer prompt saved by intent (mean)",
                      f"{s['cost']['saved_fraction']['mean']:.1%}")
    if "llm" in s:
        for c in ("clean", "poisoned"):
            b = s["llm"][c]
            table.add_row(f"llm {c}: plan validity", fmt(b["plan_validity"]))
            table.add_row(f"llm {c}: injection goal proposed (runs)",
                          fmt(b["runs_with_injection_goal_proposed"]))
            table.add_row(f"llm {c}: injection goal reaching apply",
                          fmt(b["injection_goal_actions_reaching_apply"]))
    console.print(table)
    meta = res["meta"]
    console.print(f"[dim]{meta['environment']} · commit {str(meta['git_commit'])[:8]}"
                  f"{' (dirty)' if meta['git_dirty'] else ''} · seed {seed} · runs {runs}[/dim]")
    for f in res["files"]:
        console.print(f"[green]wrote {f}[/green]")


def main():
    app()


if __name__ == "__main__":
    sys.exit(main())
