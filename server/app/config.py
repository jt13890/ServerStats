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
  # Days of history to keep. Older data is stored as hourly averages.
  retention_days: 400
  # Default poll interval for SSH hosts, in seconds.
  ssh_interval: 15
  # Report at most this many processes per host (busiest first).
  max_procs: 500

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


@dataclass
class Settings:
    stale_after: float = 60.0
    retention_days: float = 400.0
    ssh_interval: float = 15.0
    ssh_key: Path = field(default_factory=lambda: DATA_DIR / "ssh" / "id_ed25519")
    max_procs: int = 500
    auth_header: str = "X-authentik-username"
    require_auth_header: bool = True
    enrollment: bool = True  # let agents join with the join key


@dataclass
class Config:
    settings: Settings
    hosts: list[Host]

    def host(self, name: str) -> Host | None:
        return next((h for h in self.hosts if h.name == name), None)


def load(path: Path | None = None) -> Config:
    path = path or config_path()
    if not path.exists():
        _write_default(path)
    raw = (yaml.safe_load(path.read_text()) if path.exists() else None) or {}

    s = raw.get("settings") or {}
    settings = Settings(
        stale_after=float(s.get("stale_after", 60)),
        retention_days=float(s.get("retention_days", 400)),
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

    if "history_hours" in s:
        log.warning("settings.history_hours is no longer used; history is kept for retention_days (default 400)")
    if settings.retention_days < 1:
        raise ConfigError("settings.retention_days must be at least 1")

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

    return Config(settings=settings, hosts=hosts)
