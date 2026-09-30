"""
Provider-agnostic chat client.

One function, `complete()`, that takes a system prompt and a user message and
returns text. Two wire formats cover every provider hardenctl supports:
Anthropic's messages API and the OpenAI chat-completions shape that OpenAI,
OpenRouter, Ollama, vLLM, LM Studio and most local runtimes all speak.

Callers never see the difference. Swapping providers changes a config value,
not a line of hardener.py or explain.py.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request


class LLMError(RuntimeError):
    pass


# Token usage reported by the provider for the most recent call. The eval
# harness reads it to measure the cost of the agent; nothing else depends on it.
LAST_USAGE: dict = {}


def _anthropic_body(system: str, user: str, model: str, max_tokens: int) -> dict:
    return {
        "model": model,
        "max_tokens": max_tokens,
        "system": system,
        "messages": [{"role": "user", "content": user}],
    }


def _openai_body(system: str, user: str, model: str, max_tokens: int) -> dict:
    return {
        "model": model,
        "max_tokens": max_tokens,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }


def _anthropic_text(data: dict) -> str:
    return "".join(
        b.get("text", "") for b in data.get("content", [])
        if b.get("type") == "text"
    )


def _openai_text(data: dict) -> str:
    choices = data.get("choices") or []
    if not choices:
        return ""
    return choices[0].get("message", {}).get("content") or ""


def complete(
    system: str,
    user: str,
    provider: dict,
    api_key: str | None = None,
    max_tokens: int = 4000,
    timeout: int = 180,
) -> str:
    """Send one turn and return the model's text."""
    wire = provider.get("wire", "anthropic")
    model = provider["model"]
    url = provider["base_url"]

    if wire == "anthropic":
        body = _anthropic_body(system, user, model, max_tokens)
        headers = {"content-type": "application/json",
                   "anthropic-version": "2023-06-01"}
        if api_key:
            headers["x-api-key"] = api_key
        # Identity-linked keys (SSO / org-issued) must name the workspace the
        # request acts in. Plain keys reject the header, so only send it when set.
        if ws := provider.get("workspace_id"):
            headers["anthropic-workspace-id"] = ws
        # Identity-linked keys must name the workspace they act in.
        if ws := provider.get("workspace_id"):
            headers["anthropic-workspace-id"] = ws
    else:
        body = _openai_body(system, user, model, max_tokens)
        headers = {"content-type": "application/json"}
        if api_key:
            headers["authorization"] = f"Bearer {api_key}"

    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:300]
        if e.code == 400 and "workspace-id" in detail:
            raise LLMError(
                "This API key is identity-linked and needs a workspace ID. "
                "Run: hardenctl configure  (or create a standard key at "
                "console.anthropic.com)"
            ) from e
        if "workspace-id" in detail:
            raise LLMError(
                "this API key is identity-linked and needs a workspace id. "
                "Run: hardenctl configure  (paste the id from console.anthropic.com "
                "-> Settings -> Workspaces, it looks like wrkspc_...)"
            ) from e
        if e.code in (401, 403):
            raise LLMError(
                f"{provider.get('label', 'provider')} rejected the API key "
                f"(HTTP {e.code}). Run: hardenctl configure"
            ) from e
        raise LLMError(f"{provider.get('label')} returned HTTP {e.code}: {detail}") from e
    except urllib.error.URLError as e:
        raise LLMError(
            f"could not reach {url} — {e.reason}. "
            f"For a local model, check it is running."
        ) from e

    LAST_USAGE.clear()
    LAST_USAGE.update(data.get("usage") or {})
    text = (_anthropic_text(data) if wire == "anthropic" else _openai_text(data)).strip()
    if not text:
        raise LLMError("provider returned an empty response")
    return text


def parse_json(text: str) -> dict:
    """Strip markdown fences and parse. Models add them despite instructions."""
    t = text.strip()
    if t.startswith("```"):
        t = t.split("\n", 1)[1] if "\n" in t else t[3:]
        if t.rstrip().endswith("```"):
            t = t.rstrip()[:-3]
    t = t.strip()

    try:
        return json.loads(t)
    except json.JSONDecodeError:
        pass

    # Model wrapped the object in prose.
    a, b = t.find("{"), t.rfind("}")
    if a != -1 and b > a:
        try:
            return json.loads(t[a:b + 1])
        except json.JSONDecodeError:
            pass

    # Truncated at max_tokens: recover the objects that did complete. A partial
    # answer beats none — the caller validates every item anyway, so a
    # half-finished array costs coverage and nothing else.
    salvaged = _salvage_objects(t)
    if salvaged:
        return salvaged

    raise LLMError(
        "provider returned truncated or invalid JSON and nothing could be "
        "recovered from it"
    )


def _salvage_objects(text: str) -> dict | None:
    """
    Pull every complete {...} out of a truncated JSON document.

    Uses a stack of opening positions rather than a depth counter, because the
    objects worth recovering sit inside an array inside the top-level object —
    they close at depth 2, never at depth 0.
    """
    objs = []
    stack: list[int] = []
    in_str = False
    esc = False
    quote = chr(34)
    backslash = chr(92)

    for i, ch in enumerate(text):
        if in_str:
            if esc:
                esc = False
            elif ch == backslash:
                esc = True
            elif ch == quote:
                in_str = False
            continue
        if ch == quote:
            in_str = True
        elif ch == "{":
            stack.append(i)
        elif ch == "}" and stack:
            opened = stack.pop()
            try:
                objs.append(json.loads(text[opened:i + 1]))
            except json.JSONDecodeError:
                pass

    inner = [o for o in objs if "finding_id" in o or "action" in o]
    if not inner:
        return None
    key = "explanations" if "finding_id" in inner[0] else "actions"
    return {key: inner}
