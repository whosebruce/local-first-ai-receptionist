"""Configuration loading and validation.

Every environment-specific value is configurable here; nothing in the source
tree hardcodes a filesystem root, address, model endpoint, or platform ID.
Defaults are the safest possible: bind loopback only, outbound sending
disabled, no model endpoints, Discord disabled.

Precedence: explicit path argument > RECEPTIONIST_CONFIG env var > config.json
next to the state root (RECEPTIONIST_HOME env var, default ~/.local/state/ai-receptionist).
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
from pathlib import Path
from typing import Any

CONFIG_VERSION = 1

CATEGORIES = ("family", "client", "vendor")

_SNOWFLAKE_RE = re.compile(r"^\d{15,21}$")


class ConfigError(ValueError):
    pass


def state_root() -> Path:
    return Path(os.environ.get("RECEPTIONIST_HOME", "~/.local/state/ai-receptionist")).expanduser()


def default_config() -> dict[str, Any]:
    root = state_root()
    return {
        "config_version": CONFIG_VERSION,
        "business_name": "Your Business",
        "assistant_name": "Assistant",
        "listen_host": "127.0.0.1",
        "listen_port": 8080,
        "allow_private_lan_bind": False,    # opt-in to bind a private-LAN interface
        "relay_url": "",                    # owner alert sink (HMAC-signed); empty = log only
        "allow_private_lan_relay": False,   # opt-in to send alerts to a LAN sink
        "transport": {
            "kind": "bluebubbles",          # or "stub" for tests/dry runs
            "server_url": "",               # e.g. http://127.0.0.1:1234 (local server)
            "webhook_public_url": "",       # URL the transport calls back on
        },
        "outbound": {
            # HARD OWNER GATE: nothing is ever sent to a real contact until the
            # owner sets this to true by hand after reading the operator guide.
            # Installers, tests, and agents must never set it.
            "enabled": False,
            "max_auto_replies_per_contact_per_day": 4,
            "ack_cooldown_seconds": 21600,
        },
        "default_country_code": "1",
        "discord": {
            "enabled": False,
            "guild_id": "",
            "owner_user_id": "",
            "bot_user_id": "",
            "intake_channel_id": "",
            "category_channels": {},
            "pending_alert_ttl_seconds": 3600,
        },
        "owner_seen_check": {
            # Optional second-channel nudge for a genuinely new lead. The same
            # HMAC-signed relay receives route.kind=owner_seen_check; the local
            # adapter decides whether that means SMS/iMessage/etc.
            "enabled": False,
            "delay_seconds": 180,
        },
        "tier2": {
            "test_cohort_max": 10,
            "test_ttl_seconds": 86400,
            "sweep_interval_seconds": 60,
            "context_max_turns": 12,
            "max_reply_chars": 1200,
            "fast_ack_cooldown_seconds": 3600,
            "max_daily_replies": 60,
            "image": {
                "max_bytes": 8 * 1024 * 1024,
                "max_per_message": 3,
                "max_per_day": 10,
                "retention_seconds": 86400,
                "quarantine_dir": str(root / "quarantine"),
            },
            "model": {"base_url": "", "model": "", "num_ctx": 8192,
                      "timeout_seconds": 45, "allow_private_lan": False},
            "vision": {"base_url": "", "model": "", "timeout_seconds": 90,
                       "allow_private_lan": False},
        },
        "state_dir": str(root),
    }


def _merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            out[key] = _merge(base[key], value)
        else:
            out[key] = value
    return out


def _validate_host(host: str, allow_private_lan: bool) -> None:
    """Listen/bind hosts must be loopback, or a private-range address the
    operator explicitly opted into. Public interfaces are always refused."""
    if host in ("localhost",):
        return
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        raise ConfigError(f"listen_host must be an IP address or 'localhost', got {host!r}")
    if addr.is_unspecified:
        # 0.0.0.0 / :: mean "all interfaces" = public exposure. Never allowed,
        # even with the LAN opt-in (which classifies these as private).
        raise ConfigError("refusing to bind the unspecified address (all interfaces)")
    if addr.is_loopback:
        return
    if addr.is_private and allow_private_lan:
        return
    if addr.is_private:
        raise ConfigError(
            "listen_host is a LAN address; set allow_private_lan_bind: true to "
            "confirm the interface is on a trusted network"
        )
    raise ConfigError(f"refusing to bind a non-private address: {host}")


def _validate_local_endpoint(name: str, cfg: dict[str, Any]) -> None:
    """Model endpoints must be loopback, or private-LAN when explicitly allowed.
    Public endpoints and external AI providers are always refused."""
    base_url = str(cfg.get("base_url") or "")
    if not base_url:
        return
    match = re.match(r"^http://([^/:]+)(:\d+)?(/.*)?$", base_url)
    if not match:
        raise ConfigError(f"{name}.base_url must be plain http:// to a host, got {base_url!r}")
    host = match.group(1)
    if host == "localhost":
        return
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        raise ConfigError(f"{name}.base_url host must be an IP or 'localhost' (no DNS): {host!r}")
    if addr.is_loopback:
        return
    # Globally routable, link-local (169.254/16, incl. the well-known cloud
    # metadata address), and unspecified endpoints are refused unconditionally
    # — no config can send contact data to a public/external/metadata endpoint.
    if addr.is_global:
        raise ConfigError(f"{name}.base_url host {host} is globally routable; refused")
    if addr.is_link_local or addr.is_unspecified:
        raise ConfigError(f"{name}.base_url host {host} is link-local/unspecified; refused")
    if addr.is_private and bool(cfg.get("allow_private_lan")):
        return
    raise ConfigError(
        f"{name}.base_url host {host} is not loopback; LAN endpoints require "
        f"{name}.allow_private_lan: true, and public endpoints are never allowed"
    )


def _validate_snowflake(name: str, value: str) -> None:
    if value and not _SNOWFLAKE_RE.match(str(value)):
        raise ConfigError(f"{name} must be a numeric platform ID, got {value!r}")


def validate(config: dict[str, Any]) -> dict[str, Any]:
    if int(config.get("config_version", 0)) != CONFIG_VERSION:
        raise ConfigError(f"config_version must be {CONFIG_VERSION}")
    _validate_host(str(config.get("listen_host", "")), bool(config.get("allow_private_lan_bind")))
    port = int(config.get("listen_port", 0))
    if not 1 <= port <= 65535:
        raise ConfigError("listen_port out of range")
    tier2 = config.get("tier2") or {}
    _validate_local_endpoint("tier2.model", tier2.get("model") or {})
    _validate_local_endpoint("tier2.vision", tier2.get("vision") or {})
    discord = config.get("discord") or {}
    if discord.get("enabled"):
        for field in ("guild_id", "owner_user_id", "bot_user_id", "intake_channel_id"):
            if not discord.get(field):
                raise ConfigError(f"discord.enabled requires discord.{field}")
            _validate_snowflake(f"discord.{field}", str(discord[field]))
        for category, channel in (discord.get("category_channels") or {}).items():
            if category not in CATEGORIES:
                raise ConfigError(f"unknown discord category {category!r}")
            _validate_snowflake(f"discord.category_channels.{category}", str(channel))
    seen_check = config.get("owner_seen_check") or {}
    delay = int(seen_check.get("delay_seconds", 180))
    if delay < 1 or delay > 86400:
        raise ConfigError("owner_seen_check.delay_seconds must be between 1 and 86400")
    # An empty quarantine_dir (as shipped in the example config) resolves to a
    # default under the state dir so a fresh install starts without edits.
    image_cfg = (config.get("tier2") or {}).get("image") or {}
    if not image_cfg.get("quarantine_dir"):
        state_dir = Path(config.get("state_dir") or state_root()).expanduser()
        image_cfg["quarantine_dir"] = str(state_dir / "quarantine")
    relay = str(config.get("relay_url") or "")
    if relay and not re.match(r"^https?://(127\.\d{1,3}\.\d{1,3}\.\d{1,3}|localhost|\[::1\]|(\d{1,3}\.){3}\d{1,3})(:\d+)?(/.*)?$", relay):
        raise ConfigError("relay_url must target a local/LAN HTTP endpoint")
    if relay:
        host_match = re.match(r"^https?://([^/:\[\]]+|\[::1\])", relay)
        host = host_match.group(1) if host_match else ""
        if host not in ("localhost", "[::1]"):
            try:
                addr = ipaddress.ip_address(host.strip("[]"))
            except ValueError:
                raise ConfigError("relay_url host must be an IP or localhost")
            if addr.is_global or addr.is_unspecified or not (addr.is_loopback or addr.is_private):
                raise ConfigError("relay_url must not target a public/unspecified address")
            # A non-loopback (LAN) relay sink receives the owner alert, which
            # quotes the contact's message. Require an explicit opt-in so
            # leaving the loopback boundary is a deliberate operator choice.
            if not addr.is_loopback and not bool(config.get("allow_private_lan_relay")):
                raise ConfigError(
                    "relay_url is a LAN address; set allow_private_lan_relay: true "
                    "to confirm the alert sink is on a trusted network")
    return config


def load(path: str | os.PathLike | None = None) -> dict[str, Any]:
    candidate = path or os.environ.get("RECEPTIONIST_CONFIG") or (state_root() / "config.json")
    candidate = Path(candidate).expanduser()
    merged = default_config()
    if candidate.exists():
        merged = _merge(merged, json.loads(candidate.read_text()))
    return validate(merged)
