"""Loads and validates config.yaml."""

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

DATA_DIR = Path(os.environ.get("SERVERSTATS_DATA", "/data"))
MOUNTED_CONFIG = Path("/config/config.yaml")  # ./config/config.yaml in docker-compose.yml


def config_path() -> Path:
    """SERVERSTATS_CONFIG if set, else ./config/config.yaml (the bind mount; it's
    generated there on first start). Only if that folder isn't writable does the
    config live in the data volume instead."""
    if os.environ.get("SERVERSTATS_CONFIG"):
        return Path(os.environ["SERVERSTATS_CONFIG"])
    fallback = DATA_DIR / "config.yaml"
    if MOUNTED_CONFIG.exists():
        return MOUNTED_CONFIG
    if fallback.exists() or not os.access(MOUNTED_CONFIG.parent, os.W_OK):
        return fallback
    return MOUNTED_CONFIG


def _env_bool(name: str) -> bool | None:
    v = os.environ.get(name, "").strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off"):
        return False
    return None


DEFAULT_CONFIG = """\
# ServerStats configuration, generated on first start. Edit it and restart
# ServerStats (docker compose restart) to apply. All settings are optional.

settings:
  # Reject UI/API requests without the header Authentik sets (agent endpoints
  # excepted). Keep this on once Authentik is in front; for a LAN test without
  # it, set SERVERSTATS_REQUIRE_AUTH_HEADER=false in .env (overrides this).
  require_auth_header: {require_auth_header}
  # Header your reverse proxy sets with the signed-in user.
  auth_header: X-authentik-username
  # Let agents join with the join key shown under "Add host" in the UI, so
  # they don't need to be listed below.
  enrollment: true
  # Mark a host offline after this many seconds without a report (or 3x its
  # reporting interval, if longer).
  stale_after: 60
  # Default poll interval for SSH hosts, in seconds.
  ssh_interval: 15
  # Report at most this many processes per host (busiest first).
  max_procs: 500

# Chat notifications. Create an incoming webhook in Rocket.Chat (Administration
# > Integrations > New > Incoming) and paste its URL here, or put it in .env as
# SERVERSTATS_ROCKETCHAT_WEBHOOK so it stays out of this file (.env wins).
# notifications:
#   rocketchat:
#     webhook_url: https://chat.example.com/hooks/ID/TOKEN
#     on_oom: true      # a host's kernel killed a process for lack of memory
#     cooldown: 300     # at most one message per host this often (seconds)
#     channel: ""       # optional: post to this channel instead of the webhook's own
#     on_offline: true  # a host stopped reporting AND stopped answering ping
#     on_recovery: true # ...and it's back

# When a host stops reporting, ping it (by the Tailscale name it reported, or its
# ping_host / ssh address from the host list) to tell a stopped agent from a stopped
# machine. Only a host that stays silent for `failures` rounds is called offline.
# ping:
#   enabled: true
#   interval: 30      # seconds between rounds
#   failures: 3
#   port: 22          # also tried over TCP (a refusal means the machine is up)
#   timeout: 3

# Hosts that join with the join key don't need to be listed here. List SSH
# hosts (the server connects to them), or agents with a fixed token:
hosts: []
#  - name: pi
#    mode: ssh
#    address: 192.168.1.20
#    user: serverstats
#  - name: nas
#    mode: agent
#    token: <openssl rand -hex 32>
"""


def _write_default(path: Path) -> None:
    require = _env_bool("SERVERSTATS_REQUIRE_AUTH_HEADER")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(DEFAULT_CONFIG.format(require_auth_header=str(require is not False).lower()))
        log.info("wrote a default config to %s", path)
    except OSError as e:
        log.warning("no config at %s and couldn't write one (%s); using defaults", path, e)

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


log = logging.getLogger("serverstats")


class ConfigError(Exception):
    pass


@dataclass
class Host:
    name: str
    mode: str  # "agent" or "ssh"
    token: str | None = None
    address: str | None = None
    port: int = 22
    user: str = "serverstats"
    interval: float = 15.0
    host_key: str | None = None  # optional pinned SHA256 fingerprint
    description: str = ""
    enrolled: bool = False  # joined with the join key rather than listed in config.yaml
    token_hash: str | None = None  # enrolled hosts: sha256 of their token
    ping_host: str | None = None  # what to ping when it stops reporting (default: its Tailscale name)


@dataclass
class Settings:
    stale_after: float = 60.0
    ssh_interval: float = 15.0
    ssh_key: Path = field(default_factory=lambda: DATA_DIR / "ssh" / "id_ed25519")
    max_procs: int = 500
    auth_header: str = "X-authentik-username"
    require_auth_header: bool = True
    enrollment: bool = True  # let agents join with the join key


@dataclass
class RocketChat:
    webhook_url: str = ""
    on_oom: bool = True  # tell the channel when an agent reports an out-of-memory kill
    cooldown: float = 300.0  # seconds between out-of-memory messages about the same host
    channel: str = ""  # post here instead of the webhook's own channel
    on_offline: bool = True  # tell the channel when a host is confirmed offline (see Ping)
    on_recovery: bool = True  # ...and when it comes back


@dataclass
class Notifications:
    rocketchat: RocketChat = field(default_factory=RocketChat)


@dataclass
class Ping:
    """Pinging hosts that stop reporting, to tell a stopped agent from a stopped machine."""
    enabled: bool = True
    interval: float = 30.0  # seconds between rounds
    failures: int = 3  # unanswered rounds in a row before the machine counts as offline
    port: int = 22  # also tried over TCP; a refusal counts as an answer
    timeout: float = 3.0  # seconds to wait for each answer


@dataclass
class Config:
    settings: Settings
    hosts: list[Host]
    notifications: Notifications = field(default_factory=Notifications)
    ping: Ping = field(default_factory=Ping)

    def host(self, name: str) -> Host | None:
        return next((h for h in self.hosts if h.name == name), None)


def _notifications(raw) -> Notifications:
    rc = ((raw or {}).get("rocketchat") if isinstance(raw, dict) else None) or {}
    if not isinstance(rc, dict):
        raise ConfigError("notifications.rocketchat must be a mapping")
    # The URL holds a secret, so it may come from .env instead of this file.
    url = os.environ.get("SERVERSTATS_ROCKETCHAT_WEBHOOK", "").strip() or str(rc.get("webhook_url") or "").strip()
    if url and not re.match(r"^https?://[^\s/]+\S*$", url):
        raise ConfigError("notifications.rocketchat.webhook_url must be an http(s) URL")
    try:
        cooldown = max(float(rc.get("cooldown", 300)), 0.0)
    except (TypeError, ValueError):
        raise ConfigError("notifications.rocketchat.cooldown must be a number of seconds")
    return Notifications(rocketchat=RocketChat(
        webhook_url=url,
        on_oom=bool(rc.get("on_oom", True)),
        on_offline=bool(rc.get("on_offline", True)),
        on_recovery=bool(rc.get("on_recovery", True)),
        cooldown=cooldown,
        channel=str(rc.get("channel") or "").strip(),
    ))


def _ping(raw) -> Ping:
    raw = raw or {}
    if not isinstance(raw, dict):
        raise ConfigError("ping must be a mapping")
    try:
        p = Ping(
            enabled=bool(raw.get("enabled", True)),
            interval=float(raw.get("interval", 30)),
            failures=int(raw.get("failures", 3)),
            port=int(raw.get("port", 22)),
            timeout=float(raw.get("timeout", 3)),
        )
    except (TypeError, ValueError):
        raise ConfigError("ping: interval, failures, port and timeout must be numbers")
    if not (5 <= p.interval <= 3600 and 1 <= p.failures <= 20 and 1 <= p.port <= 65535 and 0.5 <= p.timeout <= 10):
        raise ConfigError("ping: interval must be 5-3600, failures 1-20, port 1-65535 and timeout 0.5-10")
    return p


def load(path: Path | None = None) -> Config:
    path = path or config_path()
    if not path.exists():
        _write_default(path)
    raw = (yaml.safe_load(path.read_text()) if path.exists() else None) or {}

    s = raw.get("settings") or {}
    settings = Settings(
        stale_after=float(s.get("stale_after", 60)),
        ssh_interval=float(s.get("ssh_interval", 15)),
        ssh_key=Path(s["ssh_key"]) if s.get("ssh_key") else DATA_DIR / "ssh" / "id_ed25519",
        max_procs=int(s.get("max_procs", 500)),
        auth_header=str(s.get("auth_header", "X-authentik-username")),
        require_auth_header=bool(s.get("require_auth_header", True)),
        enrollment=bool(s.get("enrollment", True)),
    )
    # .env can switch the SSO check off for a LAN test without editing this file.
    env_require = _env_bool("SERVERSTATS_REQUIRE_AUTH_HEADER")
    if env_require is not None:
        settings.require_auth_header = env_require

    for old in ("history_hours", "retention_days"):
        if old in s:
            log.warning("settings.%s is no longer used: history is kept forever. "
                        "Delete old history with Prune in the dashboard.", old)

    hosts: list[Host] = []
    seen_names: set[str] = set()
    seen_tokens: set[str] = set()
    for i, h in enumerate(raw.get("hosts") or []):
        name = str(h.get("name", "")).strip()
        if not NAME_RE.match(name):
            raise ConfigError(f"hosts[{i}]: invalid or missing name {name!r}")
        if name in seen_names:
            raise ConfigError(f"hosts[{i}]: duplicate host name {name!r}")
        seen_names.add(name)

        mode = str(h.get("mode", "agent")).lower()
        host = Host(name=name, mode=mode, description=str(h.get("description", "")))
        if h.get("ping_host"):
            host.ping_host = str(h["ping_host"]).strip()
            if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,252}$", host.ping_host):
                raise ConfigError(f"host {name!r}: ping_host must be a host name or IP address")
        if mode == "agent":
            token = str(h.get("token") or "")
            if len(token) < 24:
                raise ConfigError(f"host {name!r}: agent token must be at least 24 characters (openssl rand -hex 32)")
            if token in seen_tokens:
                raise ConfigError(f"host {name!r}: token is reused by another host")
            seen_tokens.add(token)
            host.token = token
        elif mode == "ssh":
            if not h.get("address"):
                raise ConfigError(f"host {name!r}: ssh mode needs an address")
            host.address = str(h["address"])
            host.port = int(h.get("port", 22))
            host.user = str(h.get("user", "serverstats"))
            host.interval = float(h.get("interval", settings.ssh_interval))
            host.host_key = h.get("host_key")
        else:
            raise ConfigError(f"host {name!r}: mode must be 'agent' or 'ssh', got {mode!r}")
        hosts.append(host)

    return Config(settings=settings, hosts=hosts, notifications=_notifications(raw.get("notifications")),
                  ping=_ping(raw.get("ping")))
