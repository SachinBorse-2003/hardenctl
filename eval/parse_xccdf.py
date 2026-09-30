#!/usr/bin/env python3
"""
Summarise OpenSCAP XCCDF result files.

  parse_xccdf.py RESULT.xml          one result -> JSON on stdout
  parse_xccdf.py --summary DIR       every *.json summary in DIR -> comparison
                                     table, also written to DIR/summary.json

Standard library only, so it runs as root without the project's dependencies.
"""

from __future__ import annotations

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse(path: Path) -> dict:
    root = ET.parse(path).getroot()
    results = [el for el in root.iter() if _local(el.tag) == "TestResult"]
    if not results:
        raise SystemExit(f"{path}: no TestResult element")
    tr = results[-1]
    counts: dict[str, int] = {}
    rules: dict[str, str] = {}
    score = None
    profile = None
    for el in tr:
        name = _local(el.tag)
        if name == "rule-result":
            res = next((c.text for c in el if _local(c.tag) == "result"), "unknown")
            rules[el.get("idref", "")] = res
            counts[res] = counts.get(res, 0) + 1
        elif name == "score" and el.get("system", "").endswith("default"):
            score = float(el.text)
        elif name == "profile":
            profile = el.get("idref")
    if score is None:
        # fall back to the first score element of any system
        s = next((el for el in tr if _local(el.tag) == "score"), None)
        score = float(s.text) if s is not None else float("nan")
    scored = counts.get("pass", 0) + counts.get("fail", 0)
    return {
        "file": path.name, "profile": profile, "score": score,
        "counts": counts,
        "pass_rate": round(counts.get("pass", 0) / scored, 4) if scored else None,
        "rules": rules,
    }


def summary(directory: Path) -> dict:
    rows = []
    for j in sorted(directory.glob("*.json")):
        if j.name == "summary.json" or j.name.endswith(("-health.json", "-lynis.json")):
            continue
        d = json.loads(j.read_text())
        if "score" not in d:
            continue
        stamp_label = j.stem
        health = j.with_name(stamp_label + "-health.json")
        lynis = j.with_name(stamp_label + "-lynis.json")
        rows.append({
            "run": stamp_label, "score": d["score"],
            "pass": d["counts"].get("pass", 0), "fail": d["counts"].get("fail", 0),
            "health": json.loads(health.read_text()) if health.is_file() else None,
            "lynis": json.loads(lynis.read_text()) if lynis.is_file() else None,
        })
    out = {"rows": rows}
    (directory / "summary.json").write_text(json.dumps(out, indent=1))
    print(f"{'RUN':<44} {'SCORE':>7} {'PASS':>5} {'FAIL':>5}")
    for r in rows:
        print(f"{r['run']:<44} {r['score']:>7.2f} {r['pass']:>5} {r['fail']:>5}")
    return out


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--summary":
        summary(Path(sys.argv[2]))
    elif len(sys.argv) == 2:
        print(json.dumps(parse(Path(sys.argv[1])), indent=1))
    else:
        raise SystemExit(__doc__)
