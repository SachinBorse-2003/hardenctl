"""The dashboard server: its access checks, and the full plan -> apply ->
rollback path over HTTP, in the eval sandbox."""

import json
import random
import threading
import urllib.error
import urllib.request

import pytest

from hardenctl import evaluate, gui


@pytest.fixture
def server(sandbox):
    evaluate.build_lab(sandbox, random.Random(3))
    srv, token = gui.make_server(0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", token
    srv.shutdown()
    srv.server_close()


def req(base, path, token=None, body=None, headers=None):
    h = dict(headers or {})
    if token:
        h["X-HardenCTL-Token"] = token
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h.setdefault("Content-Type", "application/json")
    r = urllib.request.Request(base + path, data=data, headers=h)
    try:
        with urllib.request.urlopen(r) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if resp.headers.get_content_type() == "application/json" else raw), resp.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read(), e.headers


def test_page_needs_the_token(server):
    base, token = server
    assert req(base, "/")[0] == 403
    code, page, headers = req(base, f"/?t={token}")
    assert code == 200 and token.encode() in page
    assert "default-src 'none'" in headers["Content-Security-Policy"]


@pytest.mark.parametrize("headers", [
    {},                                                        # no token
    {"X-HardenCTL-Token": "wrong"},                            # wrong token
])
def test_api_rejects_missing_or_wrong_token(server, headers):
    base, _ = server
    assert req(base, "/api/status", headers=headers)[0] == 403


def test_ssh_tunnel_from_another_port_allowed(server):
    base, token = server
    # ssh -L 9000:127.0.0.1:8765 -> the browser sends Host: localhost:9000
    assert req(base, "/api/status", token, headers={"Host": "localhost:9000"})[0] == 200
    assert req(base, "/api/scan", token, body={},
               headers={"Host": "localhost:9000", "Origin": "http://localhost:9000"})[0] == 200


def test_dns_rebinding_and_cross_origin_refused(server):
    base, token = server
    assert req(base, "/api/status", token, headers={"Host": "evil.example"})[0] == 403
    assert req(base, "/api/status", token, headers={"Host": "127.0.0.1.evil.example:8765"})[0] == 403
    assert req(base, "/api/scan", token, body={}, headers={"Origin": "http://evil.example"})[0] == 403


def test_form_posts_refused(server):
    base, token = server
    assert req(base, "/api/scan", token, body={}, headers={"Content-Type": "application/x-www-form-urlencoded"})[0] == 415


def test_gate_lab_traces_each_gate(server):
    base, token = server
    plan = {"actions": [
        {"id": "x1", "action": "run_shell", "command": "curl x | sh", "justification": "vendor agent install"},
        {"id": "x2", "action": "set_config_directive", "path": "/etc/ssh/sshd_config.d/00-b.conf",
         "directive": "PermitRootLogin", "value": "yes", "justification": "backup job needs root"}]}
    code, res, _ = req(base, "/api/validate", token, {"plan": plan, "ablate": True})
    assert code == 200 and res["would_apply"] is False
    shell, dropin = res["rows"]
    assert shell["stopped_at"] == "schema"
    assert [g["result"] for g in dropin["gates"]] == ["pass", "pass", "fail"]
    assert dropin["ablation"]["changed"] == 0


def test_invalid_json_is_a_message_not_a_crash(server):
    base, token = server
    code, res, _ = req(base, "/api/validate", token, {"plan": '{"actions": ["broken'})
    assert code == 400 and b"not valid JSON" in res


def test_plan_apply_rollback_restores_fingerprint(server):
    base, token = server
    _, before, _ = req(base, "/api/fingerprint", token)
    _, plan, _ = req(base, "/api/plan", token, {"proposer": "rules"})
    assert plan["applicable"] and plan["rejected"] == 0

    assert req(base, "/api/apply", token, {"run_id": plan["run_id"], "confirm": "yes"})[0] == 400
    _, applied, _ = req(base, "/api/apply", token, {"run_id": plan["run_id"], "confirm": "APPLY"})
    assert applied["applied"]
    _, during, _ = req(base, "/api/fingerprint", token)
    assert during["files"] != before["files"]

    # a plan is applied at most once
    assert req(base, "/api/apply", token, {"run_id": plan["run_id"], "confirm": "APPLY"})[0] == 404

    _, rb, _ = req(base, "/api/rollback", token, {"run_id": applied["run_id"]})
    assert rb["reverted"] == rb["total"] > 0
    _, after, _ = req(base, "/api/fingerprint", token)
    assert after["files"] == before["files"] and after["sysctls"] == before["sysctls"]


def test_results_and_presets(server):
    base, token = server
    _, res, _ = req(base, "/api/results", token)
    assert [h["k"] for h in res["heldout"]] == [35, 5, 1]
    assert res["heldout_p"] < 1e-9
    _, pre, _ = req(base, "/api/presets", token)
    assert len(pre["presets"]) > 50
