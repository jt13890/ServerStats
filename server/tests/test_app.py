import json

import pytest
from fastapi.testclient import TestClient

TOKEN_A = "a" * 40
TOKEN_B = "b" * 40
USER = {"X-authentik-username": "alice"}

CONFIG = f"""
settings:
  require_auth_header: true
hosts:
  - name: alpha
    mode: agent
    token: {TOKEN_A}
  - name: beta
    mode: agent
    token: {TOKEN_B}
"""


@pytest.fixture()
def client(tmp_path, monkeypatch):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(CONFIG)
    from app import config

    monkeypatch.setattr(config, "CONFIG_PATH", cfg_file)
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config.load, "__defaults__", (cfg_file,))
    from app.main import app

    with TestClient(app) as c:
        yield c


def sample(**over):
    from agent_collector import collect

    data = collect(0.05, 20)[0]
    data.update(over)
    return data


def ingest(client, token, payload):
    return client.post("/api/ingest", content=json.dumps(payload),
                       headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})


def test_ui_requires_sso_header(client):
    assert client.get("/api/hosts").status_code == 401
    assert client.get("/").status_code == 401
    assert client.get("/api/hosts", headers=USER).status_code == 200


def test_agent_endpoints_bypass_sso(client):
    assert client.get("/healthz").status_code == 200
    r = client.get("/api/agent/serverstats_agent.py")
    assert r.status_code == 200 and r.text.startswith("#!/usr/bin/env python3")
    assert client.get("/api/agent/install.sh").status_code == 200


def test_ingest_rejects_bad_token(client):
    assert ingest(client, "nope", {}).status_code == 401
    assert client.post("/api/ingest", json={}).status_code == 401


def test_ingest_attributes_to_token_owner(client):
    # A host can't report as another host: identity comes from the token.
    r = ingest(client, TOKEN_B, sample(hostname="alpha"))
    assert r.status_code == 200 and r.json()["host"] == "beta"
    hosts = {h["name"]: h for h in client.get("/api/hosts", headers=USER).json()}
    assert hosts["beta"]["status"] == "online"
    assert hosts["alpha"]["status"] == "pending"
    detail = client.get("/api/hosts/beta", headers=USER).json()
    assert detail["processes"] and "cmd" in detail["processes"][0]
    assert detail["disk_io"]["devices"] is not None
    assert detail["disks"]


def test_malformed_payload_is_normalized(client):
    evil = {
        "cpu": {"percent": "<img src=x onerror=alert(1)>", "count": "lots"},
        "load": "high",
        "memory": [],
        "disks": [{"mount": "/", "total": "1", "used": None}, "junk"],
        "processes": [{"pid": "1", "name": {"x": 1}, "cpu": float("inf")}] * 5000,
        "status": "online", "server_time": 0,
    }
    assert ingest(client, TOKEN_A, evil).status_code == 200
    h = client.get("/api/hosts/alpha", headers=USER).json()
    assert h["cpu"] == {"count": 1, "percent": 0.0}
    assert h["load"] == [0.0, 0.0, 0.0]
    assert h["memory"]["total"] == 0.0
    assert h["disks"] == [{"mount": "/", "device": "", "fs": "", "total": 0.0, "used": 0.0, "free": 0.0, "percent": 0.0}]
    assert len(h["processes"]) == 500
    assert h["processes"][0]["cpu"] == 0.0 and isinstance(h["processes"][0]["name"], str)
    assert h["server_time"] > 0


def test_ingest_size_limit(client):
    big = {"processes": [{"cmd": "x" * 1000}] * 5000}
    assert ingest(client, TOKEN_A, big).status_code == 413


def test_history(client):
    for _ in range(3):
        ingest(client, TOKEN_A, sample())
    hist = client.get("/api/hosts/alpha/history?hours=1", headers=USER).json()
    assert hist["metrics"] and {"cpu", "mem", "disk_util", "disk_read", "rx"} <= hist["metrics"][0].keys()
    assert hist["storage"]  # first sample always records storage
    assert client.get("/api/hosts/nope/history", headers=USER).status_code == 404


def test_config_validation(tmp_path):
    from app.config import ConfigError, load

    bad = [
        "hosts: [{name: x, mode: agent, token: short}]",
        f"hosts: [{{name: x, mode: agent, token: {TOKEN_A}}}, {{name: y, mode: agent, token: {TOKEN_A}}}]",
        "hosts: [{name: x, mode: ssh}]",
        "hosts: [{name: 'bad name', mode: ssh, address: h}]",
        "hosts: [{name: x, mode: telnet}]",
    ]
    for text in bad:
        p = tmp_path / "c.yaml"
        p.write_text(text)
        with pytest.raises(ConfigError):
            load(p)


def test_public_paths_are_exact(client):
    assert client.get("/api/agent/../hosts").status_code in (401, 404)
    assert client.get("/api/agent/other").status_code == 401
    assert client.get("/healthzz").status_code == 401


def test_slow_agent_is_not_flagged_offline(client, monkeypatch):
    import time as _time

    # An agent reporting every 120s must stay "online" between reports even
    # though the default stale_after is 60s.
    assert ingest(client, TOKEN_A, sample(interval=120)).status_code == 200
    real = _time.time
    monkeypatch.setattr("app.main.time.time", lambda: real() + 150)
    hosts = {h["name"]: h for h in client.get("/api/hosts", headers=USER).json()}
    assert hosts["alpha"]["status"] == "online"
    monkeypatch.setattr("app.main.time.time", lambda: real() + 400)
    hosts = {h["name"]: h for h in client.get("/api/hosts", headers=USER).json()}
    assert hosts["alpha"]["status"] == "offline"


def test_interval_is_clamped(client):
    ingest(client, TOKEN_A, sample(interval=10**9))
    assert client.get("/api/hosts/alpha", headers=USER).json()["interval"] == 3600.0


# -- long-term history ----------------------------------------------------------

def test_year_of_history_is_rolled_up_and_pruned(tmp_path):
    import time as _time

    from app.store import Store

    store = Store(tmp_path / "db.sqlite", retention_days=400)
    now = _time.time()
    # One sample every 2h for 420 days; CPU ramps smoothly with age so values can be checked.
    for k in range(420 * 12, -1, -1):
        t = now - k * 7200
        store.record("h", {"cpu": {"percent": (now - t) / 86400 / 4.2}, "disks": []}, now=t)
    store.rollup(now)
    store.prune({"h"}, now)

    def count(table):
        return store._db.execute(f"SELECT COUNT(*), MIN(ts) FROM {table}").fetchone()

    raw, m5, h1 = count("history"), count("history_5m"), count("history_1h")
    assert raw[1] >= now - 3 * 86400 - 3600        # raw kept ~3 days
    assert m5[1] >= now - 90 * 86400 - 3600        # 5-minute tier kept 90 days
    assert h1[1] >= now - 400 * 86400 - 7200       # hourly tier kept retention_days
    assert h1[0] > 400 * 11                        # ...and it has most of a year+

    year = store.history("h", 24 * 365)
    pts = year["metrics"]
    assert year["bucket"] >= 3600 and 200 <= len(pts) <= 245
    assert pts[0]["t"] <= now - 360 * 86400        # reaches back a full year
    assert pts[-1]["t"] >= now - 2 * year["bucket"]  # and up to now, not just the last rollup
    # Values survive the averaging: ~200 days ago CPU was ~200/4.2.
    mid = min(pts, key=lambda p: abs(p["t"] - (now - 200 * 86400)))
    assert abs(mid["cpu"] - 200 / 4.2) < 1

    hour = store.history("h", 1)
    assert hour["bucket"] < 300  # short ranges still come from raw samples


def test_rollup_is_idempotent(tmp_path):
    import time as _time

    from app.store import Store

    store = Store(tmp_path / "db.sqlite", retention_days=400)
    now = _time.time()
    for k in range(100):
        store.record("h", {"cpu": {"percent": 50.0}, "disks": []}, now=now - 10000 + k * 60)
    store.rollup(now)
    first = store._db.execute("SELECT COUNT(*), SUM(cpu) FROM history_5m").fetchone()
    store.rollup(now)
    store.rollup(now + 1)
    assert store._db.execute("SELECT COUNT(*), SUM(cpu) FROM history_5m").fetchone() == first


def test_trends_endpoint(client):
    ingest(client, TOKEN_A, sample())
    tr = client.get("/api/trends", headers=USER).json()
    assert set(tr["hosts"]) == {"alpha"}
    assert {"t", "cpu", "mem", "disk_util", "storage"} <= tr["hosts"]["alpha"].keys()


def test_retention_setting(tmp_path):
    from app.config import ConfigError, load

    p = tmp_path / "c.yaml"
    p.write_text("settings: {history_hours: 24}\nhosts: []\n")
    assert load(p).settings.retention_days == 400  # old setting ignored (logged)
    p.write_text("settings: {retention_days: 30}\nhosts: []\n")
    assert load(p).settings.retention_days == 30
    p.write_text("settings: {retention_days: 0}\nhosts: []\n")
    with pytest.raises(ConfigError):
        load(p)


# -- SSH: no code is ever sent --------------------------------------------------

class _FakeStream:
    def __init__(self, data):
        self._data = data

    async def read(self, n):
        chunk, self._data = self._data[:n], self._data[n:]
        return chunk


class _FakeConn:
    """Stands in for an SSH connection; `forced` = host has the forced command."""

    def __init__(self, forced, output=b""):
        self.forced, self.output, self.commands = forced, output, []

    def create_process(self, command, **kw):
        self.commands.append(command)
        conn = self

        class Proc:
            exit_status = 0

            async def __aenter__(self):
                out = conn.output if conn.forced else b"serverstats-key-not-restricted\n"
                self.stdout, self.stderr = _FakeStream(out), _FakeStream(b"")
                return self

            async def __aexit__(self, *a):
                return False

            async def wait(self):
                return None

        return Proc()


def _poller():
    from app.ssh_poller import SSHPoller

    return SSHPoller([], None, None, 500)


def test_ssh_only_ever_requests_the_harmless_probe():
    import asyncio

    from app.config import Host
    from app.ssh_poller import PROBE_COMMAND

    host = Host(name="h", mode="ssh", address="x")
    conn = _FakeConn(forced=True, output=json.dumps(sample()).encode())
    data = asyncio.run(_poller()._collect(conn, host))
    assert data["cpu"]["count"] >= 1
    assert conn.commands == [PROBE_COMMAND] and PROBE_COMMAND.startswith("echo ")


def test_ssh_refuses_unrestricted_keys():
    import asyncio

    from app.config import Host
    from app.ssh_poller import UnrestrictedKeyError

    with pytest.raises(UnrestrictedKeyError):
        asyncio.run(_poller()._collect(_FakeConn(forced=False), Host(name="h", mode="ssh", address="x")))


def test_ssh_output_is_size_limited():
    import asyncio

    from app.config import Host

    conn = _FakeConn(forced=True, output=b"{" + b" " * (9 * 1024 * 1024))
    with pytest.raises(RuntimeError, match="too large"):
        asyncio.run(_poller()._collect(conn, Host(name="h", mode="ssh", address="x")))


def test_server_code_has_no_exec_paths():
    """Nothing on the server may execute or deserialize code."""
    import pathlib
    import re

    src = "\n".join(p.read_text() for p in pathlib.Path("app").glob("*.py"))
    for pattern in (r"\beval\(", r"\bexec\(", r"\bpickle\b", r"\bsubprocess\b", r"os\.system", r"yaml\.load\(",
                    r"yaml\.unsafe", r"shell=True", r"create_subprocess"):
        assert not re.search(pattern, src), pattern


# -- Docker ---------------------------------------------------------------------

def test_cgroup_v2_counters(tmp_path, monkeypatch):
    import agent_collector as a

    cg = tmp_path / "system.slice" / "docker-abc.scope"
    cg.mkdir(parents=True)
    (cg / "cpu.stat").write_text("usage_usec 2500000\nuser_usec 2000000\n")
    (cg / "memory.current").write_text("104857600\n")
    (cg / "memory.stat").write_text("anon 50\ninactive_file 4857600\n")
    (cg / "io.stat").write_text("8:0 rbytes=1000 wbytes=2000 rios=1\n8:16 rbytes=24 wbytes=48\n")
    real_read = a._read
    monkeypatch.setattr(a, "CGROUP_ROOT", str(tmp_path))
    monkeypatch.setattr(a, "_read", lambda p: "0::/system.slice/docker-abc.scope\n" if p == "/proc/42/cgroup" else real_read(p))
    assert a._cgroup_counters(42) == (2_500_000_000, 100_000_000, 1024, 2048)


def test_docker_payload_is_normalized(client):
    docker = {
        "containers": [
            {"id": "a" * 64, "name": "media-app-1", "project": "media", "service": "app", "image": "x",
             "status": "Up 2 hours", "cpu": 50.0, "mem": 1e8, "mem_percent": 1.5, "rx_rate": "lots", "disk": 4096},
            "junk",
        ],
        "volumes": [{"name": "media_data", "project": "media", "size": 1e9}, {"name": {"x": 1}}],
        "disk_at": 1.0,
    }
    ingest(client, TOKEN_A, sample(docker=docker))
    d = client.get("/api/hosts/alpha", headers=USER).json()["docker"]
    assert len(d["containers"]) == 1
    c = d["containers"][0]
    assert c["id"] == "a" * 12 and c["project"] == "media" and c["cpu"] == 50.0 and c["rx_rate"] is None
    assert d["volumes"][0]["size"] == 1e9 and d["volumes"][1]["name"] == "{'x': 1}"
    # The fleet overview doesn't carry per-container data.
    assert "docker" not in client.get("/api/hosts", headers=USER).json()[0]

    ingest(client, TOKEN_A, sample(docker={"error": "no permission"}))
    assert client.get("/api/hosts/alpha", headers=USER).json()["docker"] == {"error": "no permission"}


def test_ui_is_revalidated(client):
    assert client.get("/", headers=USER).headers["cache-control"] == "no-cache"
    assert client.get("/static/app.js", headers=USER).headers["cache-control"] == "no-cache"
    assert "cache-control" not in client.get("/api/hosts", headers=USER).headers


def test_cgroup_v2_without_memory_controller(tmp_path, monkeypatch):
    """Raspberry Pi OS disables the memory cgroup by default: still report CPU."""
    import agent_collector as a

    cg = tmp_path / "system.slice" / "docker-abc.scope"
    cg.mkdir(parents=True)
    (cg / "cpu.stat").write_text("usage_usec 1000\n")
    real_read = a._read
    monkeypatch.setattr(a, "CGROUP_ROOT", str(tmp_path))
    monkeypatch.setattr(a, "_read", lambda p: "0::/system.slice/docker-abc.scope\n" if p == "/proc/42/cgroup" else real_read(p))
    assert a._cgroup_counters(42) == (1_000_000, None, 0, 0)
    delta = a._docker_delta(
        {"containers": {"c": {"counters": (0, None, 0, 0), "net": None}}},
        {"containers": {"c": {"name": "x", "project": "p", "service": "s", "image": "i", "status": "Up",
                              "counters": (1_000_000_000, None, 0, 0), "net": None, "volumes": []}}},
        1.0, 1000,
    )
    c = delta["containers"][0]
    assert c["cpu"] == 100.0 and c["mem"] is None and c["mem_percent"] is None
