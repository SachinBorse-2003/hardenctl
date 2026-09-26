"""
Configuration, provider selection and credential storage.

Two problems solved here.

**Sudo home.** hardenctl needs root to attribute sockets to processes, but under
sudo `Path.home()` is /root. A key saved there is invisible when the operator
next runs as themselves, and vice versa. Every path resolves through
`real_home()`, which honours SUDO_USER.

**Provider lock-in.** A provider is a base URL, a model, an auth header and a
wire format — nothing more. Local models via Ollama need no key and make no
outbound connection, which matters for the air-gapped hosts that most need
hardening and least want an API call leaving the box.
"""

from __future__ import annotations

import json
import os
import pwd
import stat
from pathlib import Path

PROVIDERS: dict[str, dict] = {
    "anthropic": {
        "label": "Anthropic",
        "base_url": "https://api.anthropic.com/v1/messages",
        "model": "claude-sonnet-5",
        "wire": "anthropic",
        "needs_key": True,
        "key_hint": "sk-ant-...",
    },
    "openai": {
        "label": "OpenAI",
        "base_url": "https://api.openai.com/v1/chat/completions",
        "model": "gpt-4o-mini",
        "wire": "openai",
        "needs_key": True,
        "key_hint": "sk-...",
    },
    "openrouter": {
        "label": "OpenRouter",
        "base_url": "https://openrouter.ai/api/v1/chat/completions",
        "model": "anthropic/claude-sonnet-5",
        "wire": "openai",
        "needs_key": True,
        "key_hint": "sk-or-...",
    },
    "ollama": {
        "label": "Ollama — local, no key, nothing leaves the host",
        "base_url": "http://localhost:11434/v1/chat/completions",
        "model": "llama3.1",
        "wire": "openai",
        "needs_key": False,
        "key_hint": "",
    },
}

DEFAULT_PROVIDER = "anthropic"
ENV_KEYS = ["HARDENCTL_API_KEY", "ANTHROPIC_API_KEY",
            "OPENAI_API_KEY", "OPENROUTER_API_KEY"]


# --------------------------------------------------------------------------
# Sudo-aware paths
# --------------------------------------------------------------------------

def real_home() -> Path:
    """The invoking user's home, not root's, when running under sudo."""
    if sudo_user := os.environ.get("SUDO_USER"):
        try:
            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except KeyError:
            pass
    return Path.home()


def state_dir() -> Path:
    if override := os.environ.get("HARDENCTL_HOME"):
        return Path(override)
    return real_home() / ".hardenctl"


def config_path() -> Path:
    return state_dir() / "config.json"


def _give_back(path: Path) -> None:
    """Hand a file created under sudo back to the invoking user."""
    if not (sudo_user := os.environ.get("SUDO_USER")):
        return
    try:
        pw = pwd.getpwnam(sudo_user)
        os.chown(path, pw.pw_uid, pw.pw_gid)
    except (KeyError, PermissionError, OSError):
        pass


# --------------------------------------------------------------------------
# Load / save
# --------------------------------------------------------------------------

def load_config() -> dict:
    p = config_path()
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def save_config(cfg: dict) -> Path:
    d = state_dir()
    d.mkdir(parents=True, exist_ok=True)
    _give_back(d)
    p = config_path()
    p.write_text(json.dumps(cfg, indent=2))
    os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)   # 0600 — holds a credential
    _give_back(p)
    return p


def provider(name: str | None = None) -> dict:
    """Resolved provider settings: defaults, overlaid with saved overrides."""
    cfg = load_config()
    name = name or cfg.get("provider") or DEFAULT_PROVIDER
    p = dict(PROVIDERS.get(name, PROVIDERS[DEFAULT_PROVIDER]))
    p["name"] = name
    for field in ("base_url", "model", "workspace_id"):
        if cfg.get(field):
            p[field] = cfg[field]
    return p


def env_key() -> str | None:
    for var in ENV_KEYS:
        if v := os.environ.get(var):
            return v
    return None


def resolve_key(p: dict) -> str | None:
    """Environment first, then the saved config. Never prompts."""
    if not p.get("needs_key"):
        return None
    return env_key() or load_config().get("api_key") or None


def save_key(key: str, provider_name: str | None = None) -> Path:
    cfg = load_config()
    cfg["api_key"] = key
    if provider_name:
        cfg["provider"] = provider_name
    return save_config(cfg)


def clear_key() -> bool:
    cfg = load_config()
    if "api_key" not in cfg:
        return False
    cfg.pop("api_key")
    save_config(cfg)
    return True


def masked(key: str | None) -> str:
    if not key:
        return "(none)"
    return f"{key[:7]}…{key[-4:]}" if len(key) > 14 else "…" + key[-4:]
