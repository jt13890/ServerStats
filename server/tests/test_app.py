import json
import zlib
import math

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

def test_history_is_rolled_up_and_kept_forever(tmp_path):
    import time as _time

    from app.store import Store

    store = Store(tmp_path / "db.sqlite")
    now = _time.time()
    # One sample every 2h for 420 days; CPU ramps smoothly with age so values can be checked.
    for k in range(420 * 12, -1, -1):
        t = now - k * 7200
        store.record("h", {"cpu": {"percent": (now - t) / 86400 / 4.2}, "disks": []}, now=t)
    store.rollup(now)
    store.compact({"h"}, now)

    def count(table):
        return store._db.execute(f"SELECT COUNT(*), MIN(ts) FROM {table}").fetchone()

    raw, m5, h1 = count("history"), count("history_5m"), count("history_1h")
    assert raw[1] >= now - 3 * 86400 - 3600        # raw kept ~3 days
    assert m5[1] >= now - 90 * 86400 - 3600        # 5-minute tier kept 90 days
    assert h1[1] <= now - 420 * 86400 + 7200       # hourly tier keeps everything
    assert h1[0] > 419 * 12

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

    store = Store(tmp_path / "db.sqlite")
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


def test_old_retention_settings_are_ignored(tmp_path, caplog):
    from app.config import load

    p = tmp_path / "c.yaml"
    for old in ("history_hours: 24", "retention_days: 30", "retention_days: 0"):
        p.write_text(f"settings: {{{old}}}\nhosts: []\n")
        caplog.clear()
        settings = load(p).settings
        assert not hasattr(settings, "retention_days")
        assert "kept forever" in caplog.text


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


# -- remote agent updates -------------------------------------------------------

def _post_update(client, name, header=True):
    headers = dict(USER, **({"X-ServerStats-Action": "1"} if header else {}))
    return client.post(f"/api/hosts/{name}/update", headers=headers)


def test_update_flow(client):
    from app.main import AGENT_SHA256, AGENT_VERSION

    ingest(client, TOKEN_A, sample(agent_version="1.0.0", updates=True))
    assert client.get("/api/hosts", headers=USER).json()[0]["update_available"] is True

    assert _post_update(client, "alpha", header=False).status_code == 403  # CSRF guard
    assert client.post("/api/hosts/alpha/update", headers={"X-ServerStats-Action": "1"}).status_code == 401  # SSO
    assert _post_update(client, "alpha").status_code == 200

    # Offered on the next reports, at most 3 times, then given up on.
    for _ in range(3):
        reply = ingest(client, TOKEN_A, sample(agent_version="1.0.0", updates=True)).json()
        assert reply["update"] == {"version": AGENT_VERSION, "sha256": AGENT_SHA256}
    assert "update" not in ingest(client, TOKEN_A, sample(agent_version="1.0.0", updates=True)).json()

    # Once the agent runs the new version the request is done.
    assert _post_update(client, "alpha").status_code == 200
    assert "update" not in ingest(client, TOKEN_A, sample(agent_version=AGENT_VERSION, updates=True)).json()
    assert client.get("/api/hosts/alpha", headers=USER).json()["update_pending"] is False
    assert _post_update(client, "alpha").status_code == 409  # already up to date


def test_update_refused_when_agent_opted_out(client):
    ingest(client, TOKEN_A, sample(agent_version="1.0.0", updates=False))
    r = _post_update(client, "alpha")
    assert r.status_code == 409 and "doesn't accept remote updates" in r.json()["detail"]
    ingest(client, TOKEN_B, sample(agent_version="1.0.0", updates=True))
    r = client.post("/api/update-agents", headers=dict(USER, **{"X-ServerStats-Action": "1"})).json()
    assert r["queued"] == ["beta"] and "alpha" in r["skipped"]


def test_served_agent_matches_announced_hash(client):
    import hashlib

    from app.main import AGENT_SHA256

    body = client.get("/api/agent/serverstats_agent.py").content
    assert hashlib.sha256(body).hexdigest() == AGENT_SHA256


def test_failed_update_is_not_offered_again(client):
    from app.main import AGENT_VERSION

    ingest(client, TOKEN_A, sample(agent_version="1.0.0", updates=True))
    assert _post_update(client, "alpha").status_code == 200
    reply = ingest(client, TOKEN_A, sample(agent_version="1.0.0", updates=True, update_failed=AGENT_VERSION)).json()
    assert "update" not in reply
    r = _post_update(client, "alpha")
    assert r.status_code == 409 and "failed to start" in r.json()["detail"]


# -- joining with the join key --------------------------------------------------

ACTION = dict(USER, **{"X-ServerStats-Action": "1"})


def _join(client, key, name):
    return client.post("/api/enroll", json={"key": key, "name": name, "hostname": name})


def test_enrollment(client):
    key = client.get("/api/meta", headers=USER).json()["join_key"]
    assert key and len(key) >= 32
    assert _join(client, "wrong", "newbox").status_code == 401

    r = _join(client, key, "newbox")  # no SSO header needed: agents call this
    assert r.status_code == 200
    token = r.json()["token"]
    assert ingest(client, token, sample()).json()["host"] == "newbox"
    host = client.get("/api/hosts/newbox", headers=USER).json()
    assert host["enrolled"] and host["status"] == "online"

    # Names are unique, including against config.yaml hosts.
    assert _join(client, key, "newbox").status_code == 409
    assert _join(client, key, "alpha").status_code == 409
    assert _join(client, key, "bad name!").status_code == 400

    # Only a hash of the token is stored.
    from app.main import app as _app
    stored = _app.state.store._db.execute("SELECT token_hash FROM enrolled").fetchall()
    assert token not in str(stored)

    # A new join key stops new joins but not existing hosts.
    assert client.post("/api/join-key/rotate", headers=USER).status_code == 403  # action header
    new_key = client.post("/api/join-key/rotate", headers=ACTION).json()["join_key"]
    assert new_key != key
    assert _join(client, key, "other").status_code == 401
    assert ingest(client, token, sample()).status_code == 200

    # Enrolled hosts can be removed; config.yaml hosts can't be removed from the UI.
    assert client.post("/api/hosts/alpha/remove", headers=ACTION).status_code == 409
    assert client.post("/api/hosts/newbox/remove", headers=USER).status_code == 403
    assert client.post("/api/hosts/newbox/remove", headers=ACTION).status_code == 200
    assert client.get("/api/hosts/newbox", headers=USER).status_code == 404
    assert ingest(client, token, sample()).status_code == 401


def test_enrollment_can_be_turned_off(tmp_path, monkeypatch):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("settings:\n  require_auth_header: false\n  enrollment: false\nhosts: []\n")
    from app import config

    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config.load, "__defaults__", (cfg_file,))
    from app.main import app

    with TestClient(app) as c:
        assert c.get("/api/meta").json()["join_key"] is None
        assert _join(c, "anything", "x").status_code == 401
        assert not (tmp_path / "join_key").exists()


def test_generates_config_when_missing(tmp_path, monkeypatch):
    from app import config

    monkeypatch.delenv("SERVERSTATS_CONFIG", raising=False)
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    mounted = tmp_path / "mounted" / "config.yaml"
    monkeypatch.setattr(config, "MOUNTED_CONFIG", mounted)
    # No ./config folder (not mounted): fall back to the data volume.
    assert config.config_path() == tmp_path / "config.yaml"

    # With the bind mount, the config is generated there.
    mounted.parent.mkdir()
    assert config.config_path() == mounted
    conf = config.load()
    assert mounted.exists()
    assert conf.hosts == [] and conf.settings.require_auth_header and conf.settings.enrollment
    assert config.load().settings.stale_after == 60  # the generated file parses as the defaults
    assert "retention_days" not in mounted.read_text()
    mounted.write_text("settings: {stale_after: 30}\n")
    assert config.load().settings.stale_after == 30


def test_env_overrides_require_auth_header(tmp_path, monkeypatch):
    from app import config

    monkeypatch.setenv("SERVERSTATS_REQUIRE_AUTH_HEADER", "false")
    conf = config.load(tmp_path / "new.yaml")
    assert conf.settings.require_auth_header is False
    assert "require_auth_header: false" in (tmp_path / "new.yaml").read_text()
    (tmp_path / "set.yaml").write_text("settings: {require_auth_header: true}\n")
    assert config.load(tmp_path / "set.yaml").settings.require_auth_header is False


def test_unwritable_config_location_falls_back_to_defaults(tmp_path):
    from app.config import load

    blocker = tmp_path / "file"
    blocker.write_text("")
    conf = load(blocker / "config.yaml")  # parent is a file: can't create
    assert conf.hosts == [] and conf.settings.enrollment


# -- CPU accounting on devices that take cores offline ---------------------------

def test_cpu_percent_survives_cores_going_offline():
    from agent_collector import _cpu_percent

    before = {"cpu0": (500, 500, 0), "cpu1": (500, 500, 0), "cpu2": (900, 100, 0), "cpu3": (400, 600, 0)}
    # cpu2 and cpu3 went offline: the old summary-line math saw totals go
    # backwards and reported billions of percent.
    after = {"cpu0": (550, 550, 0), "cpu1": (560, 540, 0)}
    assert _cpu_percent(before, after) == 55.0
    # A core that went offline and came back has restarted counters: skipped.
    assert _cpu_percent(before, {"cpu0": (550, 550, 0), "cpu3": (5, 5, 0)}) == 50.0
    # iowait running backwards doesn't count as busy time.
    assert _cpu_percent({"cpu0": (100, 100, 50)}, {"cpu0": (110, 190, 40)}) == 10.0
    assert _cpu_percent(before, {}) == 0.0


def test_absurd_percentages_are_clamped(client):
    ingest(client, TOKEN_A, sample(cpu={"count": 4, "percent": 84416868700.0},
                                   memory={"percent": -5, "total": 1}))
    h = client.get("/api/hosts/alpha", headers=USER).json()
    assert h["cpu"]["percent"] == 100.0 and h["memory"]["percent"] == 0.0
    hist = client.get("/api/hosts/alpha/history?hours=1", headers=USER).json()["metrics"]
    assert all(0 <= p["cpu"] <= 100 for p in hist)


def test_docker_status_and_off_switch(monkeypatch, tmp_path):
    import agent_collector as a

    sock = tmp_path / "docker.sock"
    sock.write_text("")
    monkeypatch.setattr(a, "DOCKER_SOCK", str(sock))
    monkeypatch.setattr(a, "DOCKER_HELPER_SOCK", str(tmp_path / "no-helper.sock"))
    monkeypatch.setenv("SERVERSTATS_DOCKER", "0")
    d = a._Docker()
    assert d.snapshot() is None  # off: Docker isn't touched at all
    assert d.status() == {"present": True, "available": True, "enabled": False}
    d.override = True  # turned on from the dashboard
    assert d.status()["enabled"] is True
    sock.unlink()
    assert a._Docker().status()["present"] is False


def test_docker_helper_serves_fixed_listing(monkeypatch, tmp_path):
    """The agent gets containers from the helper's socket, not the Docker API."""
    import threading

    import agent_collector as a

    listing = {"containers": [{"id": "b" * 64, "name": "web-app-1", "project": "web", "service": "app",
                               "image": "img", "status": "Up", "pid": 0, "host_net": False, "volumes": ["v"]}],
               "disk": None}
    monkeypatch.setattr(a._DockerReader, "listing", lambda self: listing)
    path = str(tmp_path / "helper.sock")
    threading.Thread(target=a.serve_docker_helper, args=(path,), daemon=True).start()
    import os
    import time
    for _ in range(50):
        if os.path.exists(path):
            break
        time.sleep(0.05)
    assert oct(os.stat(path).st_mode & 0o777) == "0o660"
    monkeypatch.setattr(a, "DOCKER_HELPER_SOCK", path)
    monkeypatch.setenv("SERVERSTATS_DOCKER", "1")
    snap = a._Docker().snapshot()
    assert list(snap["containers"]) == ["b" * 64] and snap["containers"]["b" * 64]["project"] == "web"


def test_docker_toggle_from_dashboard(client):
    ingest(client, TOKEN_A, sample(docker_ctl={"present": True, "available": True, "enabled": False}))
    h = client.get("/api/hosts/alpha", headers=USER).json()
    assert h["docker_ctl"] == {"present": True, "available": True, "enabled": False} and h["docker_pref"] is None
    assert "settings" not in ingest(client, TOKEN_A, sample()).json()

    assert client.post("/api/hosts/alpha/docker", json={"enabled": True}, headers=USER).status_code == 403
    assert client.post("/api/hosts/alpha/docker", json={"enabled": "yes"}, headers=ACTION).status_code == 400
    assert client.post("/api/hosts/alpha/docker", json={"enabled": True}, headers=ACTION).status_code == 200
    assert ingest(client, TOKEN_A, sample()).json()["settings"] == {"docker": True}
    assert client.get("/api/hosts/alpha", headers=USER).json()["docker_pref"] is True


def test_load_score_weights_busy_resources(tmp_path):
    import time as _time

    from app.store import Store

    store = Store(tmp_path / "db.sqlite")
    now = _time.time()

    def put(host, ts, cpu, mem, disk, storage):
        store._db.execute("INSERT INTO history (host, ts, cpu, mem, disk_util, storage) VALUES (?, ?, ?, ?, ?, ?)",
                          (host, ts, cpu, mem, disk, storage))

    for k in range(12 * 24):  # one day, every 5 minutes
        t = now - k * 300
        put("pegged", t, 90, 10, 10, 10)      # one resource maxed out
        put("even", t, 50, 50, 50, 50)
        put("idle", t, 0, 0, 0, 0)
        put("full-disk", t, 20, 20, 0, 100)   # storage doesn't count toward load
    put("old", now - 5 * 86400, 99, 99, 99, 99)  # outside the 3-day window

    from app.store import load_of

    hosts = store.load_scores()["hosts"]
    assert "load" not in hosts["old"]  # nothing in the 3-day window...
    assert hosts["old"]["high1"]["load"] == pytest.approx(100, abs=0.1)  # ...but it counts toward the week's 1% high
    p = hosts["pegged"]
    assert p["load"] == pytest.approx(91.9, abs=0.1)  # 1 - .1*.9*.9, not the plain mean of 37%
    assert set(p["parts"]) == {"cpu", "mem", "disk_util"}
    assert p["parts"]["cpu"] > 10 * p["parts"]["mem"] > 0
    assert sum(p["parts"].values()) == pytest.approx(p["load"], abs=0.2)
    assert p["avg"]["cpu"] == 90 and 23 <= p["hours"] <= 25
    assert hosts["even"]["load"] == pytest.approx(load_of({"cpu": 50, "mem": 50, "disk_util": 50})[0], abs=0.1)
    assert hosts["idle"]["load"] == 0
    assert hosts["full-disk"]["load"] == pytest.approx(36, abs=0.5)  # 1 - .8*.8*1: storage ignored


def test_load_formula():
    import math

    from app.store import load_of

    def load(cpu, mem, disk):
        return load_of({"cpu": cpu, "mem": mem, "disk_util": disk})[0]

    # Sandpiper's volume V = 1/((1-cpu)(1-mem)(1-disk)), as 100 * (1 - 1/V).
    for u in ((15, 65, 5), (36, 33, 6), (90, 10, 10), (50, 50, 50)):
        volume = 1 / math.prod(1 - x / 100 for x in u)
        assert load(*u) == pytest.approx(100 * (1 - 1 / volume))
    # Anything maxed out means the server is full, however idle the rest is.
    assert load(0, 0, 100) == 100
    assert load(3, 10, 100) == pytest.approx(100)
    assert load(100, 100, 100) == pytest.approx(100)  # never more
    # Never less than the busiest resource; higher when several are busy.
    assert load(90, 10, 10) == pytest.approx(91.9, abs=0.05)
    assert load(70, 60, 10) > load(70, 10, 10) > 70
    assert load(0, 0, 0) == 0
    # Storage isn't part of load.
    assert load_of({"cpu": 10, "mem": 10, "disk_util": 10, "storage": 100}) == load_of({"cpu": 10, "mem": 10, "disk_util": 10})
    # Out-of-range and missing values.
    assert load(-5, 150, None) == 100
    assert load_of({}) == (0.0, {})

    # Shares (each resource's factor in V, -ln(1-u)) add up to the load, grow
    # with how full each resource is, and a quieter one stays visible.
    total, parts = load_of({"cpu": 15, "mem": 65, "disk_util": 5})
    assert sum(parts.values()) == pytest.approx(total)
    assert parts["mem"] > parts["cpu"] > parts["disk_util"] > 0
    assert parts["cpu"] / total == pytest.approx(math.log(1 / 0.85) / math.log(1 / (0.85 * 0.35 * 0.95)))
    assert 0.1 < parts["cpu"] / total < 0.16
    total, parts = load_of({"cpu": 0, "mem": 0, "disk_util": 100})
    assert parts == {"cpu": 0.0, "mem": 0.0, "disk_util": 100.0}
    assert all(str(v) != "-0.0" for v in parts.values())
    total, parts = load_of({"cpu": 70, "mem": 70, "disk_util": 70})
    assert parts["cpu"] == pytest.approx(total / 3)


def test_trends_include_load_scores(client):
    ingest(client, TOKEN_A, sample())
    tr = client.get("/api/trends", headers=USER).json()
    assert tr["load"]["window_hours"] == 72
    alpha = tr["load"]["hosts"]["alpha"]
    assert set(alpha["parts"]) == {"cpu", "mem", "disk_util"}
    assert 0 <= alpha["load"] <= 100


def test_one_percent_high_and_peaks(tmp_path):
    import time as _time

    from app.store import Store

    store = Store(tmp_path / "db.sqlite")
    now = _time.time()
    n = 12 * 24 * 7  # a week of 5-minute slots
    rows = []
    for k in range(n):
        t = now - 60 - k * 300
        cpu = 10.0
        if k in (100, 101, 102):
            cpu = 100.0          # a short spike, three slots long
        elif k == 1000:
            cpu = 80.0           # a second, separate busy spell
        rows.append(("h", t, cpu, 10.0, 10.0, 10.0))
    store._db.executemany("INSERT INTO history (host, ts, cpu, mem, disk_util, storage) VALUES (?,?,?,?,?,?)", rows)
    store.rollup(now)  # older slots now come from the 5-minute tier, recent ones from raw samples

    week = store.load_week("h")
    assert n - 1 <= len(week["t"]) <= n + 1 and set(week["parts"]) == {"cpu", "mem", "disk_util"}
    assert sorted(week["t"]) == week["t"]
    hi = week["high1"]
    assert hi["slots"] == math.ceil(len(week["t"]) * 0.01)  # ~21 slots
    from app.store import load_of

    spike = load_of({"cpu": 100, "mem": 10, "disk_util": 10, "storage": 10})[0]
    busy = load_of({"cpu": 80, "mem": 10, "disk_util": 10, "storage": 10})[0]
    base = load_of({"cpu": 10, "mem": 10, "disk_util": 10, "storage": 10})[0]
    expected = (3 * spike + busy + (hi["slots"] - 4) * base) / hi["slots"]
    assert hi["load"] == pytest.approx(expected, abs=0.2)
    assert sum(hi["parts"].values()) == pytest.approx(hi["load"], abs=0.3)
    # Peaks: highest first, and separate busy spells rather than neighbouring slots.
    peaks = week["peaks"]
    assert peaks[0]["load"] == pytest.approx(spike, abs=0.1)
    assert peaks[1]["load"] == pytest.approx(busy, abs=0.1)
    assert all(abs(a["t"] - b["t"]) >= 3 * 3600 for a in peaks for b in peaks if a is not b)
    assert store.load_scores()["hosts"]["h"]["high1"]["load"] == hi["load"]


def test_peak_snapshots_keep_the_busiest_moment(tmp_path):
    from app.store import SLOT, Store

    store = Store(tmp_path / "db.sqlite")
    t0 = (1_800_000_000 // SLOT) * SLOT

    def data(cpu, top):
        return {
            "cpu": {"count": 4, "percent": cpu}, "memory": {"percent": 20.0, "total": 8e9},
            "disk_io": {"util": 5.0, "devices": [{"label": "sda", "util": 5.0, "read_rate": 1, "write_rate": 2}]},
            "disks": [{"mount": "/", "percent": 30.0, "used": 3, "total": 10}],
            "processes": [{"pid": 1, "name": top, "user": "root", "cpu": cpu * 4, "mem": 1.0, "rss": 1, "cmd": top + " --x"},
                          {"pid": 2, "name": "hog", "user": "u", "cpu": 0.5, "mem": 30.0, "rss": 9, "cmd": "x" * 999}],
            "docker": {"containers": [{"project": "web", "name": "a", "cpu": 50.0, "mem": 1e9, "mem_percent": 12.5},
                                      {"project": "web", "name": "b", "cpu": 25.0, "mem": 1e9, "mem_percent": 12.5}]},
        }

    store.record("h", data(30, "calm"), now=t0 + 10)
    store.record("h", data(95, "busy"), now=t0 + 100)
    store.record("h", data(50, "later"), now=t0 + 200)  # lower than the busy moment: not kept
    snap = store.load_moment("h", t0 + 1)
    assert snap["ts"] == t0 + 100 and snap["processes"][0]["name"] == "busy"
    assert {p["name"] for p in snap["processes"]} == {"busy", "hog"}  # top by CPU and by memory
    assert len(snap["processes"][1]["cmd"]) <= 160
    assert snap["stacks"] == [{"name": "web", "stack": True, "containers": 2, "cpu": 75.0, "mem": 2e9,
                               "mem_percent": 25.0, "read_rate": 0.0, "write_rate": 0.0}]
    assert snap["parts"]["cpu"] > snap["parts"]["mem"] and snap["values"]["cpu"] == 95
    # Moments saved under an older formula are re-scored from their values.
    blob = zlib.compress(json.dumps({"load": 143.0, "parts": {"storage": 99}, "values": {"cpu": 50, "mem": 50, "storage": 99},
                                     "processes": []}).encode())
    store._db.execute("INSERT INTO load_snapshots (host, slot, ts, load, data) VALUES ('h', ?, ?, 143, ?)",
                      (int(t0 // SLOT) + 50, t0 + 50 * SLOT, blob))
    store._db.commit()
    old = store.load_moment("h", t0 + 50 * SLOT)
    assert old["load"] == 75 and set(old["parts"]) == {"cpu", "mem"}

    # A fresh Store (restart) still only replaces the snapshot with a busier moment.
    store2 = Store(tmp_path / "db.sqlite")
    store2.record("h", data(60, "after-restart"), now=t0 + 250)
    assert store2.load_moment("h", t0)["processes"][0]["name"] == "busy"
    store2.record("h", data(99, "peak"), now=t0 + 280)
    assert store2.load_moment("h", t0)["processes"][0]["name"] == "peak"
    store2.record("h", data(10, "next"), now=t0 + SLOT + 5)
    assert store2.load_moment("h", t0 + SLOT)["processes"][0]["name"] == "next"
    assert store2.load_moment("h", t0 - SLOT) is None

    # After 8 days only the busiest snapshot of each hour is kept (t0 is on the hour).
    store2.record("h", data(40, "next-hour"), now=t0 + 3600 + 5)
    store2.compact({"h"}, now=t0 + 9 * 86400)
    assert store2.load_moment("h", t0)["processes"][0]["name"] == "peak"
    assert store2.load_moment("h", t0 + SLOT) is None
    assert store2.load_moment("h", t0 + 3600)["processes"][0]["name"] == "next-hour"
    store2.compact({"h"}, now=t0 + 30 * 86400)  # idempotent
    assert store2.load_moment("h", t0)["processes"][0]["name"] == "peak"


def test_load_endpoints(client):
    ingest(client, TOKEN_A, sample())
    week = client.get("/api/hosts/alpha/load", headers=USER).json()
    assert week["days"] == 7 and len(week["t"]) == 1 and week["high1"]["slots"] == 1
    assert week["peaks"] == [] or week["peaks"][0]["t"] == week["t"][0]
    snap = client.get(f"/api/hosts/alpha/load/moment?t={week['t'][0]}", headers=USER).json()
    assert snap["processes"] and "load" in snap
    assert client.get("/api/hosts/alpha/load/moment?t=1000", headers=USER).json() is None
    assert client.get("/api/hosts/nope/load", headers=USER).status_code == 404
    assert client.get("/api/hosts/alpha/load").status_code in (401, 403)
    tr = client.get("/api/trends", headers=USER).json()
    assert tr["load"]["peak_days"] == 7 and "high1" in tr["load"]["hosts"]["alpha"]


def test_prune(client):
    import time as _time

    store = client.app.state.store
    now = _time.time()
    for host in ("alpha", "beta"):
        for days in (10, 200, 400, 800, 1200):
            t = now - days * 86400
            # (Only tables the app's background rollup doesn't write to.)
            store._db.execute("INSERT INTO history_1h (host, ts, cpu) VALUES (?, ?, 5)", (host, t))
            store._db.execute("INSERT INTO storage_1h (host, ts, mount, used, total) VALUES (?, ?, '/', 1, 2)", (host, t))
            store._db.execute("INSERT INTO load_snapshots (host, slot, ts, load, data) VALUES (?, ?, ?, 1, x'00')",
                              (host, int(t // 300), t))
    store._db.commit()

    def remaining(host):
        return sorted(round((now - t) / 86400) for (t,) in
                      store._db.execute("SELECT ts FROM history_1h WHERE host = ?", (host,)))

    meta = client.get("/api/meta", headers=USER).json()
    assert [o["days"] for o in meta["prune_options"]] == [30, 90, 180, 365, 730, 1095]  # nothing past 3 years

    # Preview: 1 year for alpha only -> its 400/800/1200-day rows, in 3 tables.
    p = client.get("/api/prune?days=365&host=alpha", headers=USER).json()
    assert p["rows"] == 3 * 3 and p["hosts"] == ["alpha"] and p["oldest"] == pytest.approx(now - 1200 * 86400)
    assert client.get("/api/prune?days=365", headers=USER).json()["hosts"] == ["alpha", "beta"]
    assert client.get("/api/prune?days=1500", headers=USER).status_code == 400

    def post(body, headers=None):
        return client.post("/api/prune", json=body, headers={**USER, **({"X-ServerStats-Action": "1"} if headers is None else headers)})

    assert post({"days": 365}, headers={}).status_code == 403  # CSRF guard
    assert client.post("/api/prune", json={"days": 365}, headers={"X-ServerStats-Action": "1"}).status_code in (401, 403)
    for bad in (1500, 7, 0, -365, "365", 365.5, True, None):
        assert post({"days": bad}).status_code == 400, bad
    assert post({"days": 365, "host": "nope"}).status_code == 404
    assert post([365]).status_code == 400

    assert post({"days": 365, "host": "alpha"}).json()["rows"] == 3 * 3
    assert remaining("alpha") == [10, 200] and remaining("beta") == [10, 200, 400, 800, 1200]
    assert post({"days": 1095}).json()["rows"] == 3 and remaining("beta") == [10, 200, 400, 800]
    assert post({"days": 1095}).json()["rows"] == 0
    assert post({"days": 180}).json()["rows"] == 4 * 3  # alpha's 200, beta's 200/400/800
    assert remaining("alpha") == [10] and remaining("beta") == [10]
