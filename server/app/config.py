"""Loads and validates config.yaml."""

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

CONFIG_PATH = Path(os.environ.get("SERVERSTATS_CONFIG", "/config/config.yaml"))
DATA_DIR = Path(os.environ.get("SERVERSTATS_DATA", "/data"))

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


@dataclass
class Settings:
    stale_after: float = 60.0
    retention_days: float = 400.0
    ssh_interval: float = 15.0
    ssh_key: Path = field(default_factory=lambda: DATA_DIR / "ssh" / "id_ed25519")
    max_procs: int = 500
    auth_header: str = "X-authentik-username"
    require_auth_header: bool = True


@dataclass
class Config:
    settings: Settings
    hosts: list[Host]

    def host(self, name: str) -> Host | None:
        return next((h for h in self.hosts if h.name == name), None)


def load(path: Path = CONFIG_PATH) -> Config:
    if not path.exists():
        raise ConfigError(f"config file not found: {path} (copy config.example.yaml there)")
    raw = yaml.safe_load(path.read_text()) or {}

    s = raw.get("settings") or {}
    settings = Settings(
        stale_after=float(s.get("stale_after", 60)),
        retention_days=float(s.get("retention_days", 400)),
        ssh_interval=float(s.get("ssh_interval", 15)),
        ssh_key=Path(s["ssh_key"]) if s.get("ssh_key") else DATA_DIR / "ssh" / "id_ed25519",
        max_procs=int(s.get("max_procs", 500)),
        auth_header=str(s.get("auth_header", "X-authentik-username")),
        require_auth_header=bool(s.get("require_auth_header", True)),
    )

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
