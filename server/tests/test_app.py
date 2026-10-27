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
    assert {"t", "cpu", "mem", "disk_util", "storage", "temp"} <= tr["hosts"]["alpha"].keys()


def test_trends_carry_temperature(client):
    temps = [{"name": "Package id 0", "chip": "coretemp", "kind": "cpu", "temp": 61.5},
             {"name": "Samsung SSD", "chip": "nvme", "kind": "disk", "temp": 70.0}]
    ingest(client, TOKEN_A, sample(temps=temps))
    ingest(client, TOKEN_B, sample(temps=[]))
    tr = client.get("/api/trends", headers=USER).json()["hosts"]
    assert tr["alpha"]["temp"] == [61.5]  # the hottest CPU sensor, not the hotter drive
    assert tr["beta"]["temp"] == [None]  # a host with no sensors has nothing to draw


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


def test_ui_is_never_stale(client):
    import hashlib
    import re

    from app.main import STATIC

    page = client.get("/", headers=USER)
    assert page.headers["cache-control"] == "no-store"
    # Script and stylesheet URLs carry a hash of their contents, so a new
    # release is a new URL that no cache along the way can have.
    for name in ("app.js", "style.css"):
        digest = hashlib.sha256((STATIC / name).read_bytes()).hexdigest()[:12]
        assert f'"/static/{name}?v={digest}"' in page.text
        assert f'"/static/{name}"' not in page.text
    url = re.search(r'src="(/static/app\.js\?v=[0-9a-f]+)"', page.text).group(1)
    js = client.get(url, headers=USER)
    assert js.status_code == 200 and js.headers["cache-control"] == "no-cache"
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

    # Enrolled hosts can be renamed (history and token follow); config.yaml hosts can't.
    assert client.post("/api/hosts/newbox/rename", json={"name": "renamed"}, headers=USER).status_code == 403
    assert client.post("/api/hosts/alpha/rename", json={"name": "x"}, headers=ACTION).status_code == 409
    assert client.post("/api/hosts/newbox/rename", json={"name": "alpha"}, headers=ACTION).status_code == 409
    assert client.post("/api/hosts/newbox/rename", json={"name": "bad name!"}, headers=ACTION).status_code == 400
    assert client.post("/api/hosts/newbox/rename", json={"name": "renamed"}, headers=ACTION).status_code == 200
    assert client.get("/api/hosts/newbox", headers=USER).status_code == 404
    assert client.get("/api/hosts/renamed", headers=USER).json()["status"] == "online"
    assert ingest(client, token, sample()).json()["host"] == "renamed"
    assert client.post("/api/hosts/renamed/rename", json={"name": "newbox"}, headers=ACTION).status_code == 200

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

    # For 30 days every 5 minutes is kept; after that only the busiest
    # snapshot of each hour (t0 is on the hour).
    store2.record("h", data(40, "next-hour"), now=t0 + 3600 + 5)
    store2.compact({"h"}, now=t0 + 29 * 86400)
    assert store2.load_moment("h", t0 + SLOT)["processes"][0]["name"] == "next"
    store2.compact({"h"}, now=t0 + 31 * 86400)
    assert store2.load_moment("h", t0)["processes"][0]["name"] == "peak"
    assert store2.load_moment("h", t0 + SLOT) is None
    assert store2.load_moment("h", t0 + 3600)["processes"][0]["name"] == "next-hour"
    store2.compact({"h"}, now=t0 + 60 * 86400)  # idempotent
    assert store2.load_moment("h", t0)["processes"][0]["name"] == "peak"


def test_load_endpoints(client):
    ingest(client, TOKEN_A, sample())
    week = client.get("/api/hosts/alpha/load", headers=USER).json()
    assert week["days"] == 7 and len(week["t"]) == 1 and week["high1"]["slots"] == 1
    assert week["peaks"] == [] or week["peaks"][0]["t"] == week["t"][0]
    m = client.get(f"/api/hosts/alpha/moment?t={week['t'][0]}&span=300", headers=USER).json()
    assert m["snapshot"]["processes"] and "load" in m["snapshot"] and m["stats"]["cpu"] is not None
    m = client.get("/api/hosts/alpha/moment?t=1000&span=300", headers=USER).json()
    assert m["snapshot"] is None and m["stats"] is None
    assert client.get("/api/hosts/nope/moment?t=1000", headers=USER).status_code == 404
    assert client.get("/api/hosts/alpha/moment?t=1000").status_code in (401, 403)
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


def test_moment_for_any_chart_point(tmp_path):
    from app.store import Store

    store = Store(tmp_path / "db.sqlite")
    t0 = (1_800_000_000 // 3600) * 3600  # on the hour

    def data(cpu, mem, disk, top):
        return {
            "cpu": {"count": 2, "percent": cpu}, "memory": {"percent": mem, "total": 8e9},
            "load": [1.5, 1.0, 0.5], "net": {"rx_rate": 1000.0, "tx_rate": 500.0},
            "disk_io": {"util": disk, "read_rate": 10.0, "write_rate": 20.0, "devices": []},
            "disks": [{"mount": "/", "percent": 50.0, "used": 5e9, "total": 1e10}],
            "tasks": {"total": 100, "threads": 400},
            "processes": [{"pid": 1, "name": top, "user": "u", "cpu": cpu * 2, "mem": mem, "rss": 1, "cmd": top}],
        }

    # One sample a minute for an hour; a busy spell 20-25 minutes in.
    for k in range(60):
        busy = 20 <= k < 25
        store.record("h", data(90 if busy else 10, 40, 5, "build" if busy else "idle"), now=t0 + k * 60 + 1)

    # A 1-minute point: stats for that minute, what ran in its 5-minute slot.
    m = store.moment("h", t0 + 21 * 60, 60)
    assert m["stats"]["cpu"] == 90 and m["stats"]["mem"] == 40 and m["stats"]["load1"] == 1.5
    assert m["stats"]["rx"] == 1000 and m["stats"]["procs"] == 100
    assert m["load"]["load"] == pytest.approx(100 * (1 - 0.1 * 0.6 * 0.95), abs=0.1)
    assert sum(m["load"]["parts"].values()) == pytest.approx(m["load"]["load"], abs=0.2)
    assert m["snapshot"]["processes"][0]["name"] == "build"
    assert m["storage"] == [{"mount": "/", "used": 5e9, "total": 1e10}]

    # An hour-long point (e.g. the 30-day chart): averages over the hour, and
    # the busiest moment anywhere in it.
    m = store.moment("h", t0, 3600)
    assert m["stats"]["cpu"] == pytest.approx((5 * 90 + 55 * 10) / 60, abs=0.01)
    assert m["snapshot"]["processes"][0]["name"] == "build"
    # A quiet stretch: its own busiest moment.
    m = store.moment("h", t0 + 40 * 60, 10 * 60)
    assert m["stats"]["cpu"] == 10 and m["snapshot"]["processes"][0]["name"] == "idle"
    # Still works once rolled up into the 5-minute and hourly tiers.
    store.rollup(t0 + 10 * 86400)
    store.compact({"h"}, t0 + 10 * 86400)
    m = store.moment("h", t0, 3600)
    assert m["stats"]["cpu"] == pytest.approx((5 * 90 + 55 * 10) / 60, abs=0.01)
    assert m["snapshot"]["processes"][0]["name"] == "build"  # the hour's busiest was kept
    # Nothing recorded.
    m = store.moment("h", t0 - 7200, 3600)
    assert m["stats"] is None and m["load"] is None and m["snapshot"] is None


def test_history_for_a_zoomed_window(client):
    import time as _time

    store = client.app.state.store
    now = _time.time()
    # A sample a minute for two hours, CPU = minutes ago.
    for k in range(120):
        store.record("alpha", {"cpu": {"percent": float(k)}, "disks": []}, now=now - k * 60)
    start, end = now - 90 * 60, now - 60 * 60  # 30 minutes, an hour ago
    h = client.get(f"/api/hosts/alpha/history?start={start}&end={end}", headers=USER).json()
    assert h["bucket"] == pytest.approx(30 * 60 / 240)
    ts = [p["t"] for p in h["metrics"]]
    assert ts and min(ts) >= start - h["bucket"] and max(ts) < end
    assert all(60 <= p["cpu"] <= 90 for p in h["metrics"])
    assert len(ts) in (30, 31)
    # The "last N hours" form still works.
    assert len(client.get("/api/hosts/alpha/history?hours=1", headers=USER).json()["metrics"]) >= 59
    for bad in (f"start={start}", f"end={end}", f"start={end}&end={start}", f"start={start}&end={start + 10}",
                f"start=nan&end={end}", f"start={start}&end=inf"):
        assert client.get(f"/api/hosts/alpha/history?{bad}", headers=USER).status_code in (400, 422), bad


def test_zooming_into_old_history_uses_what_is_left(tmp_path):
    import time as _time

    from app.store import Store

    store = Store(tmp_path / "db.sqlite")
    now = _time.time()
    # A sample a minute for 10 days, CPU = days ago * 10.
    for k in range(10 * 24 * 60 - 1, -1, -1):
        t = now - k * 60
        store.record("h", {"cpu": {"percent": (now - t) / 86400 * 10}, "disks": []}, now=t)
    store.rollup(now)
    store.compact({"h"}, now)
    assert store._db.execute("SELECT MIN(ts) FROM history").fetchone()[0] > now - 4 * 86400  # raw is ~3 days

    # Zoom into 4 hours a week ago: too fine for 5-minute averages by the
    # usual rule, and the raw samples are gone; the 5-minute tier fills in.
    start = now - 7 * 86400
    h = store.history("h", 0, start=start, end=start + 4 * 3600)
    assert h["bucket"] == 60 and 40 <= len(h["metrics"]) <= 49
    assert all(68 <= p["cpu"] <= 70.1 for p in h["metrics"])  # 7 days ago, minus up to 4h
    # A window spanning the raw boundary: 5-minute points before it, raw after.
    edge = store._db.execute("SELECT MIN(ts) FROM history").fetchone()[0]
    h = store.history("h", 0, start=edge - 3600, end=edge + 3600)
    ts = [p["t"] for p in h["metrics"]]
    before = [t for t in ts if t < edge - 300]
    after = [t for t in ts if t >= edge]
    assert 10 <= len(before) <= 13 and len(after) >= 55  # 5-minute vs per-minute
    assert len(ts) == len(set(ts))
    # The moment view works there too.
    for offset in range(0, 300, 60):  # any minute, whether or not a 5-minute row starts in it
        m = store.moment("h", start + 3600 + offset, 60)
        assert m["stats"]["cpu"] == pytest.approx(69.6, abs=0.3), offset


# -- Windows hosts -----------------------------------------------------------------

def test_windows_installer_is_served_without_sso(client):
    r = client.get("/api/agent/install.ps1")
    assert r.status_code == 200
    assert "Register-ScheduledTask" in r.text and "serverstats_agent.py" in r.text


def test_windows_sample_is_accepted(client):
    win = sample(
        platform="windows", os="Windows 11 Pro 24H2", kernel="10.0.26100", arch="AMD64", load=[],
        disks=[{"mount": "C:\\", "device": "C:", "fs": "ntfs", "total": 1000, "used": 400, "free": 600, "percent": 40.0}],
        disk_io={"read_rate": 1, "write_rate": 2, "util": 3, "devices": [
            {"name": "PhysicalDrive0", "label": "Disk 0", "virtual": False, "read_rate": 1, "write_rate": 2, "util": 3}]},
        processes=[{"pid": 4, "ppid": 0, "name": "System", "state": "S", "user": "SYSTEM", "cpu": 0.0, "mem": 0.1,
                    "rss": 1000, "threads": 200, "started": 1700000000, "cmd": "System"}],
    )
    assert ingest(client, TOKEN_A, win).status_code == 200
    h = client.get("/api/hosts/alpha", headers=USER).json()
    assert h["platform"] == "windows" and h["os"] == "Windows 11 Pro 24H2"
    assert h["load"] == [0.0, 0.0, 0.0]
    assert h["disks"][0]["mount"] == "C:\\"
    assert h["processes"][0]["user"] == "SYSTEM"
    # Anything but "windows" is treated as Linux, so the field can't be abused.
    ingest(client, TOKEN_B, sample(platform="<b>"))
    assert client.get("/api/hosts/beta", headers=USER).json()["platform"] == "linux"
    assert sample()["platform"] == "linux"


def test_windows_helpers():
    import struct
    from agent_collector import _filetime_to_unix, _win_os_name, _win_parse_pagefiles

    assert _filetime_to_unix(116444736000000000 + 10000000 * 1700000000) == 1700000000
    assert _filetime_to_unix(0) == 0
    # Windows 11 still calls itself Windows 10 in the registry.
    assert _win_os_name("Windows 10 Pro", "26100", "24H2") == "Windows 11 Pro 24H2"
    assert _win_os_name("Windows 10 Pro", "19045", "22H2") == "Windows 10 Pro 22H2"
    assert _win_os_name("Windows Server 2022 Standard", "20348") == "Windows Server 2022 Standard"
    assert _win_os_name("", "junk") == "Windows"
    # Two page files: NextEntryOffset, TotalSize, TotalInUse, PeakUsage, then the name.
    raw = struct.pack("<IIII", 28, 1000, 250, 300) + b"\0" * 12 + struct.pack("<IIII", 0, 500, 5, 5)
    assert _win_parse_pagefiles(raw, 4096) == (1500 * 4096, 255 * 4096)
    assert _win_parse_pagefiles(b"", 4096) == (0, 0)


def test_agent_log_file_is_rotated(tmp_path):
    from agent_collector import _LogFile

    log = _LogFile(str(tmp_path / "agent.log"), limit=100)
    for i in range(30):
        log.write("line %d\n" % i)
    assert (tmp_path / "agent.log.1").exists()
    assert 0 < (tmp_path / "agent.log").stat().st_size <= 100 + 20
    assert "line 29" in (tmp_path / "agent.log").read_text()


def test_collect_with_windows_backends(monkeypatch):
    """The Windows code paths in collect(), with the Win32 calls stubbed out."""
    import agent_collector as a

    calls = {"n": 0}

    def tick():
        calls["n"] += 1
        return calls["n"]

    monkeypatch.setattr(a, "IS_WINDOWS", True)
    monkeypatch.setattr(a, "_win_cpu_times", lambda: ({"cpu0": (100 * tick(), 100 * tick(), 0)}, 1700000000), raising=False)
    monkeypatch.setattr(a, "_win_diskstats", lambda: {"PhysicalDrive0": (1000 * tick(), 500 * tick(), 10 * tick())}, raising=False)
    monkeypatch.setattr(a, "_win_net_bytes", lambda: (1000 * tick(), 2000 * tick()), raising=False)
    monkeypatch.setattr(a, "_win_uptime", lambda: 12345.0, raising=False)
    monkeypatch.setattr(a, "_win_os_info", lambda: "Windows 11 Pro 24H2", raising=False)
    monkeypatch.setattr(a, "_win_meminfo", lambda: {"total": 8, "available": 4, "used": 4, "percent": 50.0,
                                                    "swap_total": 0, "swap_used": 0}, raising=False)
    monkeypatch.setattr(a, "_win_disks", lambda: [{"mount": "C:\\", "device": "C:", "fs": "ntfs", "total": 10, "used": 4,
                                                   "free": 6, "percent": 40.0}], raising=False)

    def procs():
        n = tick()
        proc = {"state": "S", "ppid": 0, "threads": 4, "starttime": 5, "started": 1700000000}
        return {
            4: dict(proc, name="System", ticks=100, rss=1000, uid="SYSTEM", cmd=""),
            100: dict(proc, name="app.exe", ticks=100 + n * 5000000, rss=2000, uid="alice", cmd="C:\\x\\app.exe"),
        }

    monkeypatch.setattr(a, "_win_proc_snapshot", procs, raising=False)

    class FakeGpu:  # the real one needs the Windows performance counters
        def snapshot(self):
            return None

        def report(self):
            return {"adapters": [{"name": "RTX", "util": 12.5, "engine": "3D", "mem_used": 1, "mem_total": 2, "shared_used": 3}]}

        def status(self):
            return {"present": True, "available": True, "enabled": True}

    monkeypatch.setattr(a, "_GPU", FakeGpu())
    monkeypatch.setattr(a, "_win_temps", lambda: [
        {"name": "ACPI thermal zone TZ00", "chip": "acpi", "kind": "board", "temp": 48.0, "high": None, "crit": None},
        {"name": "RTX", "chip": "nvidia", "kind": "gpu", "temp": 61.0, "high": None, "crit": None}], raising=False)
    s = a.collect(0.01, 50)[0]
    assert s["platform"] == "windows" and s["os"] == "Windows 11 Pro 24H2" and s["load"] == [] and s["uptime"] == 12345.0
    by_pid = {p["pid"]: p for p in s["processes"]}
    assert by_pid[100]["user"] == "alice" and by_pid[100]["cmd"] == "C:\\x\\app.exe"
    assert by_pid[100]["state"] == "R" and by_pid[4]["state"] == "S"
    assert by_pid[4]["cmd"] == "System"  # no path (access denied): falls back to the name
    assert by_pid[100]["started"] == 1700000000
    assert s["tasks"]["running"] == 1 and s["docker"] is None and s["docker_ctl"] is None  # no Docker on Windows
    assert s["gpu"]["adapters"][0]["util"] == 12.5 and s["gpu_ctl"]["enabled"] is True
    assert [t["name"] for t in s["temps"]] == ["ACPI thermal zone TZ00", "RTX"]
    assert s["gpu"]["adapters"][0]["temp"] == 61.0  # the NVIDIA reading is shown on the GPU too
    assert s["disk_io"]["devices"][0]["label"] == "Disk 0"
    assert s["disks"][0]["mount"] == "C:\\"
    # What the server gets from a Windows agent is accepted as it is.
    from app.schema import normalize
    assert normalize(s, 100)["platform"] == "windows"
    assert a.updates_enabled() is False


# -- Windows: no-admin process list, GPU ----------------------------------------------

def _process_entry(pid, ppid, threads, create, user, kernel, ws, name, base, name_at, nxt, ptr=8):
    """One SYSTEM_PROCESS_INFORMATION entry as NtQuerySystemInformation lays it out."""
    import struct
    o = (64, 80, 88, 144, "<Q", 152) if ptr == 8 else (60, 68, 72, 104, "<I", 112)
    buf = bytearray(o[5])
    struct.pack_into("<II", buf, 0, nxt, threads)
    struct.pack_into("<qqq", buf, 32, create, user, kernel)
    raw = name.encode("utf-16-le")
    struct.pack_into("<HH", buf, 56, len(raw), len(raw))
    struct.pack_into(o[4], buf, o[0], base + name_at if raw else 0)
    struct.pack_into(o[4], buf, o[1], pid)
    struct.pack_into(o[4], buf, o[2], ppid)
    struct.pack_into(o[4], buf, o[3], ws)
    return bytes(buf), raw


def test_win_parse_processes():
    from agent_collector import _win_parse_processes

    for ptr in (8, 4):
        size = 152 if ptr == 8 else 112
        base = 0x7FF000000000 if ptr == 8 else 0x10000000
        names = ["", "System", "chrome.exe"]
        # Entries first, then the names they point at, like the real buffer.
        names_at = size * 3
        offsets, pos = [], names_at
        for n in names:
            offsets.append(pos)
            pos += len(n.encode("utf-16-le"))
        entries = [
            _process_entry(0, 0, 8, 0, 0, 999999, 8192, names[0], base, offsets[0], size, ptr),
            _process_entry(4, 0, 200, 133000000000000000, 5, 10, 4096, names[1], base, offsets[1], size, ptr),
            _process_entry(1234, 4, 31, 133000000000000000 + 10000000, 100, 50, 123456, names[2], base, offsets[2], 0, ptr),
        ]
        raw = b"".join(e[0] for e in entries) + b"".join(e[1] for e in entries)
        procs = _win_parse_processes(raw, base, ptr)
        assert sorted(procs) == [4, 1234]  # the idle process is left out
        assert procs[4]["name"] == "System" and procs[4]["threads"] == 200 and procs[4]["ticks"] == 15
        chrome = procs[1234]
        assert chrome["name"] == "chrome.exe" and chrome["ppid"] == 4 and chrome["rss"] == 123456
        assert chrome["ticks"] == 150 and chrome["starttime"] == 133000000000000000 + 10000000
        assert chrome["started"] == int((133000000000000000 + 10000000 - 116444736000000000) / 10000000)


def test_gpu_aggregate():
    from agent_collector import _gpu_aggregate

    luid_a, luid_b = "0x00000000_0x0000f3a5", "0x00000000_0x00010a2b"
    adapters = [{"luid": luid_a, "name": "NVIDIA GeForce RTX 4070", "mem_total": 12 * 1024 ** 3},
                {"luid": luid_b, "name": "Intel(R) UHD Graphics", "mem_total": 0}]
    engines = [
        # Two processes on the same 3D engine add up; another engine type is separate.
        ("pid_10_luid_0x00000000_0x0000F3A5_phys_0_eng_0_engtype_3D", 30.0),
        ("pid_11_luid_0x00000000_0x0000F3A5_phys_0_eng_0_engtype_3D", 25.0),
        ("pid_11_luid_0x00000000_0x0000F3A5_phys_0_eng_3_engtype_VideoEncode", 40.0),
        ("pid_12_luid_0x00000000_0x00010A2B_phys_0_eng_0_engtype_3D", 0.2),
        ("junk", 99.0),
    ]
    dedicated = [("luid_0x00000000_0x0000F3A5_phys_0", 2.0 * 1024 ** 3)]
    shared = [("luid_0x00000000_0x0000F3A5_phys_0", 100.0), ("luid_0x00000000_0x00010A2B_phys_0", 500.0)]
    out = _gpu_aggregate(engines, dedicated, shared, adapters)
    assert out[0] == {"name": "NVIDIA GeForce RTX 4070", "util": 55.0, "engine": "3D", "mem_used": 2.0 * 1024 ** 3,
                      "mem_total": 12 * 1024 ** 3, "shared_used": 100.0}
    assert out[1]["util"] == 0.2 and out[1]["engine"] == "" and out[1]["mem_total"] is None and out[1]["shared_used"] == 500.0
    # Utilisation is capped, and without DXGI the GPUs are named from the counters.
    capped = _gpu_aggregate([("pid_1_luid_0x0_0x1_phys_0_eng_0_engtype_3D", 80.0),
                             ("pid_2_luid_0x0_0x1_phys_0_eng_0_engtype_3D", 80.0)], [], [], [])
    assert capped == [{"name": "GPU 0", "util": 100.0, "engine": "3D", "mem_used": 0.0, "mem_total": None, "shared_used": None}]
    assert _gpu_aggregate([], [], [], []) == []


def test_gpu_toggle_and_settings(client):
    ctl = {"present": True, "available": True, "enabled": False}
    gpu = {"adapters": [{"name": "RTX", "util": 150, "engine": "3D", "mem_used": 5, "mem_total": 10, "shared_used": None}]}
    ingest(client, TOKEN_A, sample(platform="windows", gpu_ctl=ctl, gpu=gpu, docker_ctl=None))
    h = client.get("/api/hosts/alpha", headers=USER).json()
    assert h["gpu_ctl"] == ctl and h["gpu_pref"] is None and h["docker_ctl"] is None
    assert h["gpu"]["adapters"][0]["util"] == 100.0  # clamped
    assert "settings" not in ingest(client, TOKEN_A, sample()).json()

    assert client.post("/api/hosts/alpha/gpu", json={"enabled": True}, headers=USER).status_code == 403
    assert client.post("/api/hosts/alpha/gpu", json={"enabled": "yes"}, headers=ACTION).status_code == 400
    assert client.post("/api/hosts/alpha/gpu", json={"enabled": True}, headers=ACTION).status_code == 200
    assert ingest(client, TOKEN_A, sample()).json()["settings"] == {"gpu": True}
    # Docker and GPU choices are kept apart, and both reach the agent.
    assert client.post("/api/hosts/alpha/docker", json={"enabled": False}, headers=ACTION).status_code == 200
    assert ingest(client, TOKEN_A, sample()).json()["settings"] == {"docker": False, "gpu": True}
    h = client.get("/api/hosts/alpha", headers=USER).json()
    assert h["gpu_pref"] is True and h["docker_pref"] is False

    ingest(client, TOKEN_B, sample(gpu={"error": "no counters"}, gpu_ctl="nonsense"))
    h = client.get("/api/hosts/beta", headers=USER).json()
    assert h["gpu"] == {"error": "no counters"} and h["gpu_ctl"] is None


def test_host_prefs_table_gains_gpu_column(tmp_path):
    import sqlite3
    from app.store import Store

    db = tmp_path / "old.db"
    old = sqlite3.connect(db)
    old.executescript("CREATE TABLE host_prefs (name TEXT PRIMARY KEY, docker INTEGER);"
                      "INSERT INTO host_prefs VALUES ('alpha', 1);")
    old.commit()
    old.close()
    store = Store(db)
    assert store.docker_pref("alpha") is True and store.gpu_pref("alpha") is None
    store.set_gpu_pref("alpha", True)
    store.set_docker_pref("alpha", False)  # must not wipe the GPU choice
    assert store.gpu_pref("alpha") is True and store.docker_pref("alpha") is False


# -- Temperatures -----------------------------------------------------------------------

def _sysfs(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)


def test_hwmon_temps(tmp_path):
    from agent_collector import _hwmon_temps

    _sysfs(tmp_path, {
        "hwmon0/name": "coretemp\n",
        "hwmon0/temp1_input": "42000\n", "hwmon0/temp1_label": "Package id 0\n",
        "hwmon0/temp1_max": "100000\n", "hwmon0/temp1_crit": "100000\n",
        "hwmon0/temp2_input": "40000\n", "hwmon0/temp2_label": "Core 0\n",
        "hwmon0/temp3_input": "45500\n", "hwmon0/temp3_label": "Core 1\n",
        "hwmon1/name": "nvme\n", "hwmon1/device/model": "Samsung SSD 970   EVO\n",
        "hwmon1/temp1_input": "38000\n", "hwmon1/temp1_label": "Composite\n", "hwmon1/temp1_crit": "85000\n",
        "hwmon1/temp2_input": "41000\n", "hwmon1/temp2_label": "Sensor 1\n",
        "hwmon2/name": "thinkpad\n",
        "hwmon2/temp1_input": "40000\n", "hwmon2/temp2_input": "0\n",  # nothing attached: left out
        "hwmon3/name": "acpitz_0\n", "hwmon3/temp1_input": "30000\n",
        "hwmon4/name": "BAT0\n",  # no temperature at all
        "hwmon5/name": "amdgpu\n", "hwmon5/temp1_input": "61000\n", "hwmon5/temp1_label": "edge\n",
        "hwmon6/name": "broken\n", "hwmon6/temp1_input": "n/a\n", "hwmon6/temp2_input": "200000\n",
        "hwmon10/name": "iwlwifi_1_3\n", "hwmon10/temp1_input": "33000\n",
    })
    by = {(t["chip"], t["name"]): t for t in _hwmon_temps(str(tmp_path))}
    assert by[("coretemp", "Package id 0")] == {"chip": "coretemp", "kind": "cpu", "temp": 42.0, "high": 100.0,
                                                "crit": 100.0, "name": "Package id 0"}
    assert by[("coretemp", "Cores (hottest of 2)")]["temp"] == 45.5  # cores folded into one row
    assert not any("Core 0" in t["name"] for t in by.values())
    assert by[("nvme", "Samsung SSD 970 EVO")]["kind"] == "disk" and by[("nvme", "Samsung SSD 970 EVO")]["crit"] == 85.0
    assert by[("nvme", "Samsung SSD 970 EVO \u00b7 Sensor 1")]["temp"] == 41.0
    assert by[("thinkpad", "thinkpad temp1")]["temp"] == 40.0 and ("thinkpad", "thinkpad temp2") not in by
    assert by[("acpitz_0", "acpitz_0")]["kind"] == "board"
    assert by[("amdgpu", "edge")]["kind"] == "gpu"
    assert by[("iwlwifi_1_3", "iwlwifi_1_3")]["kind"] == "other"
    assert not any(t["chip"] in ("BAT0", "broken") for t in by.values())  # no sensor, unreadable, absurd
    assert _hwmon_temps(str(tmp_path / "missing")) == []


def test_thermal_zone_fallback(tmp_path):
    from agent_collector import _thermal_zone_temps

    _sysfs(tmp_path, {"thermal_zone0/type": "cpu-thermal\n", "thermal_zone0/temp": "55123\n",
                      "thermal_zone1/type": "gpu-thermal\n", "thermal_zone1/temp": "-274000\n",
                      "cooling_device0/type": "Processor\n"})
    zones = _thermal_zone_temps(str(tmp_path))
    assert zones == [{"name": "cpu-thermal", "chip": "thermal", "kind": "cpu", "temp": 55.1, "high": None, "crit": None}]


def test_windows_temperature_helpers():
    from agent_collector import _gpu_attach_temps, _win_zone_sensors

    zones = _win_zone_sensors([("\\_TZ.TZ00", 3231.5), ("\\_TZ.THRM", 0.0), ("TZ01", 9999.0)])
    assert zones == [{"name": "ACPI thermal zone TZ00", "chip": "acpi", "kind": "board", "temp": 50.0,
                      "high": None, "crit": None}]  # a zone at 0 K or absurdly hot isn't a reading

    gpus = [{"name": "Intel(R) UHD Graphics"}, {"name": "NVIDIA GeForce RTX 4070"}, {"name": "NVIDIA GeForce RTX 4070"}]
    _gpu_attach_temps(gpus, [("NVIDIA GeForce RTX 4070", 61.0), ("nvidia geforce rtx 4070", 70.0)])
    assert [g["temp"] for g in gpus] == [None, 61.0, 70.0]
    odd = [{"name": "NVIDIA RTX A2000 Laptop GPU"}]  # DXGI and NVML don't always spell the name the same
    _gpu_attach_temps(odd, [("NVIDIA RTX A2000 Laptop GPU 4GB", 55.0)])
    assert odd[0]["temp"] == 55.0


def test_temperatures_in_sample(client):
    temps = [
        {"name": "Package id 0", "chip": "coretemp", "kind": "cpu", "temp": 61.5, "high": 100, "crit": 100},
        {"name": "Samsung SSD", "chip": "nvme", "kind": "disk", "temp": 44},
        {"name": "Strange", "chip": "x", "kind": "nonsense", "temp": 30},
        {"name": "On fire", "kind": "cpu", "temp": 500},  # not a believable reading
        "junk", {"name": "no reading"},
    ]
    ingest(client, TOKEN_A, sample(temps=temps))
    h = client.get("/api/hosts/alpha", headers=USER).json()
    assert [t["name"] for t in h["temps"]] == ["Package id 0", "Samsung SSD", "Strange"]
    assert h["temps"][0] == {"name": "Package id 0", "chip": "coretemp", "kind": "cpu", "temp": 61.5,
                             "high": 100.0, "crit": 100.0}
    assert h["temps"][1]["high"] is None and h["temps"][2]["kind"] == "other"
    ingest(client, TOKEN_B, sample(temps="nonsense", gpu={"adapters": [{"name": "RTX", "temp": 999}]}))
    h = client.get("/api/hosts/beta", headers=USER).json()
    assert h["temps"] == [] and h["gpu"]["adapters"][0]["temp"] is None


def test_temperature_history(tmp_path):
    import sqlite3
    from app.store import Store, hottest_temp, metrics_from_sample

    cpu, disk = {"kind": "cpu", "temp": 60.0}, {"kind": "disk", "temp": 70.0}
    assert hottest_temp({"temps": [disk, cpu]}) == 60.0  # a CPU sensor is the one worth charting
    assert hottest_temp({"temps": [disk, {"kind": "board", "temp": 50.0}]}) == 70.0
    assert hottest_temp({"temps": []}) is None and hottest_temp({}) is None
    assert metrics_from_sample({"temps": [cpu]})["temp"] == 60.0

    # A database from before temperatures: the history tables and both roll-ups gain the column.
    db = tmp_path / "old.db"
    old = sqlite3.connect(db)
    for table in ("history", "history_5m", "history_1h"):
        old.execute(f"CREATE TABLE {table} (host TEXT NOT NULL, ts REAL NOT NULL, cpu REAL)")
    old.commit()
    old.close()
    store = Store(db)
    for table in ("history", "history_5m", "history_1h"):
        assert "temp" in {r[1] for r in store._db.execute(f"PRAGMA table_info({table})")}
    store.record("alpha", {"temps": [cpu]}, now=1000.0)
    assert store._db.execute("SELECT temp FROM history").fetchone() == (60.0,)


# -- agents keep their reports while the server is away ------------------------------

def _backfill(client, token, items, sent_at=None):
    import time
    return ingest(client, token, {"backfill": items, "sent_at": time.time() if sent_at is None else sent_at})


def _slim_reports(n, end, step=10.0):
    """n slim reports ending at `end`, `step` seconds apart, as an agent would have kept them."""
    from agent_collector import _slim
    base = sample(temps=[{"name": "Package", "chip": "coretemp", "kind": "cpu", "temp": 55.0}])
    out = []
    for i in range(n):
        s = _slim(dict(base, collected_at=end - (n - 1 - i) * step, interval=step))
        s["cpu"] = {"count": 4, "percent": float(i)}
        out.append(s)
    return out


def _history_rows(client, host="alpha"):
    store = client.app.state.store
    return store._db.execute("SELECT ts, cpu FROM history WHERE host = ? ORDER BY ts", (host,)).fetchall()


def test_ingest_tells_agents_they_may_buffer(client):
    from app.main import MAX_BACKFILL
    reply = ingest(client, TOKEN_A, sample()).json()
    assert reply["backfill"] == MAX_BACKFILL == 500


def test_backfill_fills_a_gap_without_touching_the_live_sample(client):
    import time
    ingest(client, TOKEN_A, sample())
    store = client.app.state.store
    before = (store.state("alpha").received_at, store.state("alpha").data)
    snaps = store._db.execute("SELECT COUNT(*) FROM load_snapshots").fetchone()[0]
    reports = _slim_reports(6, time.time() - 600)
    r = _backfill(client, TOKEN_A, reports)
    assert r.status_code == 200 and r.json() == {"ok": True, "host": "alpha", "stored": 6, "skipped": 0}
    rows = _history_rows(client)
    assert len(rows) == 7 and [c for _, c in rows[:6]] == [0.0, 1.0, 2.0, 3.0, 4.0, 5.0]
    assert (store.state("alpha").received_at, store.state("alpha").data) == before  # still the live one
    assert store._db.execute("SELECT COUNT(*) FROM load_snapshots").fetchone()[0] == snaps  # no process list, no snapshots
    # a host that only ever sent buffered reports does not look online
    _backfill(client, TOKEN_B, _slim_reports(3, time.time() - 300))
    assert store.state("beta").data is None
    assert client.get("/api/hosts/beta", headers=USER).json()["status"] != "online"


def test_backfill_is_repeat_safe_and_picky(client):
    import time
    now = time.time()
    good = _slim_reports(4, now - 200)
    assert _backfill(client, TOKEN_A, good).json()["stored"] == 4
    again = _backfill(client, TOKEN_A, good).json()
    assert (again["stored"], again["skipped"]) == (0, 4)  # nothing doubled
    no_time = dict(good[0], collected_at=None)
    future = dict(good[0], collected_at=now + 3600)
    old = dict(good[0], collected_at=now - 4 * 86400)
    r = _backfill(client, TOKEN_A, [no_time, future, old, "junk", 5, None]).json()
    assert (r["stored"], r["skipped"]) == (0, 6)
    assert len(_history_rows(client)) == 4
    assert _backfill(client, TOKEN_A, "nope").status_code == 400
    assert _backfill(client, TOKEN_A, [{}] * 501).status_code == 400
    assert _backfill(client, "x" * 40, good).status_code == 401


def test_backfill_corrects_a_skewed_agent_clock(client):
    import time
    now = time.time()
    # the agent's clock runs 1000 s behind: its "now" is our now - 1000
    skewed_now = now - 1000
    r = _backfill(client, TOKEN_A, _slim_reports(1, skewed_now - 60), sent_at=skewed_now)
    assert r.json()["stored"] == 1
    ts = _history_rows(client)[0][0]
    assert abs(ts - (now - 60)) < 5  # shifted onto the server's clock
    # a clock difference of more than a day is not trusted: timestamps stay as sent
    r = _backfill(client, TOKEN_B, _slim_reports(1, now - 60), sent_at=now + 3 * 86400)
    assert r.json()["stored"] == 1
    assert abs(_history_rows(client, "beta")[0][0] - (now - 60)) < 5


def test_backfill_storage_history_is_spaced(client):
    import time
    store = client.app.state.store
    _backfill(client, TOKEN_A, _slim_reports(5, time.time() - 100))  # 40 s of reports
    assert store._db.execute("SELECT COUNT(DISTINCT ts) FROM storage_history WHERE host = 'alpha'").fetchone()[0] == 1
    assert store._db.execute("SELECT COUNT(*) FROM history WHERE host = 'alpha'").fetchone()[0] == 5
    assert store.state("alpha").data is None


def test_slim_sample_gives_the_same_history_metrics():
    from agent_collector import _slim
    from app.store import metrics_from_sample
    temps = [{"name": "nvme", "kind": "disk", "temp": 70.0}, {"name": "core0", "kind": "cpu", "temp": 55.0},
             {"name": "core1", "kind": "cpu", "temp": 61.0}]
    full = sample(temps=temps, processes=[{"pid": 1}], docker={"containers": []}, gpu={"adapters": []})
    slim = _slim(full)
    assert metrics_from_sample(slim) == metrics_from_sample(full)
    assert slim["temps"] == [temps[2]] and "processes" not in slim and "docker" not in slim and "gpu" not in slim
    assert len(json.dumps(slim)) < len(json.dumps(full))
    assert _slim({})["temps"] == [] and metrics_from_sample(_slim({}))["cpu"] is None


def test_backlog_queue(tmp_path):
    import os
    import stat
    from agent_collector import _Backlog
    path = tmp_path / "backlog.jsonl"
    b = _Backlog(3, str(path))
    for i in range(5):
        b.add({"n": i})
    assert [x["n"] for x in b.items] == [2, 3, 4] and len(b) == 3  # the oldest are dropped
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert [x["n"] for x in _Backlog(3, str(path)).items] == [2, 3, 4]  # survives a restart
    assert [x["n"] for x in _Backlog(2, str(path)).items] == [3, 4]  # a smaller limit trims
    assert len(path.read_text().splitlines()) == 2
    b.drop(2)
    assert [x["n"] for x in b.items] == [4] and len(path.read_text().splitlines()) == 1
    assert b.peek(5) == [{"n": 4}]
    b.clear()
    assert not path.exists() and len(b) == 0
    # junk lines are dropped and the file cleaned
    path.write_text('{"n": 1}\nnot json\n[1, 2]\n{"n": 2}\n')
    b = _Backlog(10, str(path))
    assert [x["n"] for x in b.items] == [1, 2]
    assert path.read_text().splitlines() == ['{"n":1}', '{"n":2}']
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_backlog_file_stays_bounded(tmp_path):
    from agent_collector import _Backlog
    path = tmp_path / "b.jsonl"
    b = _Backlog(20, str(path))
    for i in range(500):
        b.add({"n": i})
    assert len(b) == 20 and len(path.read_text().splitlines()) <= 20 + 10
    assert [x["n"] for x in _Backlog(20, str(path)).items] == list(range(480, 500))


def test_backlog_without_a_usable_file(tmp_path, capsys):
    from agent_collector import _Backlog
    b = _Backlog(3, str(tmp_path / "missing-dir" / "b.jsonl"))
    for i in range(4):
        b.add({"n": i})
    assert [x["n"] for x in b.items] == [1, 2, 3] and b.path is None  # carries on in memory
    assert "keeping them in memory" in capsys.readouterr().err
    m = _Backlog(2)
    m.add({"n": 1})
    assert len(m) == 1 and not list(tmp_path.iterdir())


def test_make_backlog(tmp_path, monkeypatch):
    from agent_collector import _make_backlog
    monkeypatch.delenv("STATE_DIRECTORY", raising=False)
    monkeypatch.delenv("SERVERSTATS_STATE_DIR", raising=False)
    monkeypatch.delenv("SERVERSTATS_SPOOL_DIR", raising=False)
    assert _make_backlog(0, 15) is None and _make_backlog(-1, 15) is None
    b = _make_backlog(24, 15)
    assert b.limit == 5760 and b.path is None  # memory only without a place to keep it
    assert _make_backlog(1000, 15).limit == 11520  # capped at 48 hours
    assert _make_backlog(48, 2).limit == 20000  # and at 20000 reports
    monkeypatch.setenv("SERVERSTATS_STATE_DIR", str(tmp_path / "state"))
    assert _make_backlog(1, 15).path == str(tmp_path / "state" / "backlog.jsonl")
    monkeypatch.setenv("SERVERSTATS_SPOOL_DIR", str(tmp_path / "spool"))  # the spool folder wins
    assert _make_backlog(1, 15).path == str(tmp_path / "spool" / "backlog.jsonl")


def test_retry_delay():
    from agent_collector import _retry_delay, _transient
    assert [_retry_delay(f, 15) for f in (1, 2)] == [0.0, 0.0]
    assert _retry_delay(3, 15) == 30 and _retry_delay(10, 15) == 135 and _retry_delay(1000, 15) == 285
    assert all(_transient(c) for c in (408, 425, 429, 500, 502, 503, 504))
    assert not any(_transient(c) for c in (400, 401, 403, 404, 302))


class _Stop(Exception):
    pass


def _drive_agent(monkeypatch, tmp_path, srv, plan, cycles, hours=24, interval=10.0, spool="spool"):
    """Run the REAL run_agent loop against a pretend server on a fake clock.

    srv: {"down": None | "net" | HTTP code, "takes": what the server announces (None = old server),
          "backfill_status": None | HTTP code}; plan(cycle, srv) may change it between cycles.
    Returns what the server received and how long the agent waited each time.
    """
    import types
    import urllib.error
    import agent_collector as mod

    clock = {"mono": 1000.0, "wall": 1_700_000_000.0, "cycle": 0, "n": 0}
    out = {"live": [], "backfill": [], "chunks": [], "sleeps": [], "collected": 0}

    def fake_collect(sample_s, max_procs, prev):
        n = clock["n"] = clock["n"] + 1
        out["collected"] = n
        return {"collected_at": clock["wall"], "cpu": {"count": 1, "percent": float(n)},
                "memory": {"percent": 1.0}, "load": [0, 0, 0], "net": {}, "disk_io": {}, "tasks": {},
                "disks": [], "temps": []}, {}

    def fake_post(opener, url, token, payload, timeout=15):
        if "backfill" in payload:
            if srv.get("backfill_status"):
                raise urllib.error.HTTPError(url, srv["backfill_status"], "no", {}, None)
            out["chunks"].append(len(payload["backfill"]))
            out["backfill"] += [int(x["cpu"]["percent"]) for x in payload["backfill"]]
            return {"ok": True}
        if srv["down"] == "net":
            raise urllib.error.URLError("connection refused")
        if srv["down"]:
            raise urllib.error.HTTPError(url, srv["down"], "down", {}, None)
        out["live"].append(int(payload["cpu"]["percent"]))
        return {"ok": True} if srv["takes"] is None else {"ok": True, "backfill": srv["takes"]}

    def fake_sleep(s):
        out["sleeps"].append(s)
        clock["mono"] += s
        clock["wall"] += s
        clock["cycle"] += 1
        if clock["cycle"] >= cycles:
            raise _Stop()
        plan(clock["cycle"], srv)

    fake_time = types.SimpleNamespace(monotonic=lambda: clock["mono"], time=lambda: clock["wall"], sleep=fake_sleep)
    monkeypatch.setattr(mod, "time", fake_time)
    monkeypatch.setattr(mod, "collect", fake_collect)
    monkeypatch.setattr(mod, "_post", fake_post)
    monkeypatch.setattr(mod, "updates_enabled", lambda: False)
    monkeypatch.setattr(mod, "_mark_update_healthy", lambda: None)
    for var in ("STATE_DIRECTORY", "SERVERSTATS_STATE_DIR", "SERVERSTATS_SPOOL_DIR"):
        monkeypatch.delenv(var, raising=False)
    if spool:
        (tmp_path / spool).mkdir(exist_ok=True)
        monkeypatch.setenv("SERVERSTATS_SPOOL_DIR", str(tmp_path / spool))
    args = types.SimpleNamespace(url="http://server", token="t" * 40, interval=interval, sample=1.0,
                                 max_procs=10, ca_file=None, buffer_hours=hours)
    srv_down_plan = plan
    srv_down_plan(0, srv)
    with pytest.raises(_Stop):
        mod.run_agent(args, [])
    return out


def _outage(start, end, how):
    def plan(cycle, srv):
        srv["down"] = how if start <= cycle < end else None
    return plan


@pytest.mark.parametrize("how", ["net", 502, 503, 504, 429])
def test_agent_buffers_while_the_server_is_away(monkeypatch, tmp_path, capsys, how):
    srv = {"down": None, "takes": 500}
    out = _drive_agent(monkeypatch, tmp_path, srv, _outage(3, 14, how), cycles=40)
    # every report measured reached the server exactly once, the gap ones in order
    assert sorted(out["live"] + out["backfill"]) == list(range(1, out["collected"] + 1))
    assert out["backfill"] == sorted(out["backfill"]) and out["backfill"]
    assert not (tmp_path / "spool" / "backlog.jsonl").exists()  # emptied
    log = capsys.readouterr()
    assert "buffering up to" in log.out and "no buffering" not in log.out  # the startup line
    assert "buffering reports until the server is back" in log.out
    assert "reporting recovered" in log.out and "sent" in log.out and "buffered report(s)" in log.out
    # it kept measuring every interval while away, and tried the server less and less often
    assert set(out["sleeps"]) == {10.0}


@pytest.mark.parametrize("how", [400, 401, 403, 404, 302])
def test_agent_does_not_buffer_when_the_server_refuses(monkeypatch, tmp_path, how):
    srv = {"down": None, "takes": 500}
    out = _drive_agent(monkeypatch, tmp_path, srv, _outage(2, 9, how), cycles=30)
    assert out["backfill"] == [] and not (tmp_path / "spool" / "backlog.jsonl").exists()
    assert max(out["sleeps"]) > 10.0  # the old longer waits, not a measurement every interval


def test_agent_sends_buffered_reports_in_chunks(monkeypatch, tmp_path):
    srv = {"down": None, "takes": 2}
    out = _drive_agent(monkeypatch, tmp_path, srv, _outage(1, 12, "net"), cycles=40)
    assert max(out["chunks"]) == 2 and len(out["chunks"]) >= 3
    assert sorted(out["live"] + out["backfill"]) == list(range(1, out["collected"] + 1))


def test_agent_buffer_survives_a_restart(monkeypatch, tmp_path):
    first = _drive_agent(monkeypatch, tmp_path, {"down": "net", "takes": 500}, lambda c, s: None, cycles=8)
    assert first["live"] == [] and (tmp_path / "spool" / "backlog.jsonl").exists()
    kept = len((tmp_path / "spool" / "backlog.jsonl").read_text().splitlines())
    assert kept == first["collected"] == 8
    second = _drive_agent(monkeypatch, tmp_path, {"down": None, "takes": 500}, lambda c, s: None, cycles=4)
    assert len(second["backfill"]) == kept  # the first run's reports (numbered afresh by the fake) all went out
    assert not (tmp_path / "spool" / "backlog.jsonl").exists()


def test_agent_buffer_is_bounded(monkeypatch, tmp_path):
    # 0.01 hours of 10 s reports = 3 reports
    srv = {"down": None, "takes": 500}
    out = _drive_agent(monkeypatch, tmp_path, srv, _outage(1, 20, "net"), cycles=40, hours=0.01)
    assert len(out["backfill"]) == 3
    assert out["backfill"][-1] > out["backfill"][0] and out["backfill"] == sorted(out["backfill"])


def test_agent_buffering_can_be_turned_off(monkeypatch, tmp_path):
    out = _drive_agent(monkeypatch, tmp_path, {"down": None, "takes": 500}, _outage(2, 9, "net"), cycles=30, hours=0)
    assert out["backfill"] == [] and not list((tmp_path / "spool").iterdir())
    assert max(out["sleeps"]) > 10.0


def test_agent_buffers_in_memory_without_a_folder(monkeypatch, tmp_path):
    out = _drive_agent(monkeypatch, tmp_path, {"down": None, "takes": 500}, _outage(2, 9, "net"), cycles=30, spool=None)
    assert sorted(out["live"] + out["backfill"]) == list(range(1, out["collected"] + 1))
    assert not list(tmp_path.iterdir())


def test_agent_does_not_buffer_for_an_older_server(monkeypatch, tmp_path):
    spool = tmp_path / "spool"
    spool.mkdir()
    (spool / "backlog.jsonl").write_text('{"collected_at":1,"cpu":{"percent":1}}\n')  # left over from a newer server
    srv = {"down": None, "takes": None}  # replies without "backfill"
    out = _drive_agent(monkeypatch, tmp_path, srv, _outage(3, 9, "net"), cycles=30)
    assert out["backfill"] == [] and not (spool / "backlog.jsonl").exists()
    assert max(out["sleeps"]) > 10.0


def test_agent_backfill_refused_or_not_ready(monkeypatch, tmp_path):
    def plan(refused):
        def go(cycle, srv):
            srv["down"] = "net" if 1 <= cycle < 6 else None
            srv["backfill_status"] = (refused if cycle < 14 else None)
        return go
    # refused (400): that chunk is dropped, the agent carries on reporting
    out = _drive_agent(monkeypatch, tmp_path, {"down": None, "takes": 500}, plan(400), cycles=20)
    assert out["backfill"] == [] and len(out["live"]) > 10
    assert not (tmp_path / "spool" / "backlog.jsonl").exists()
    # not ready (503): kept, and sent once the server takes it
    out = _drive_agent(monkeypatch, tmp_path, {"down": None, "takes": 500}, plan(503), cycles=20)
    assert len(out["backfill"]) >= 4 and sorted(out["live"] + out["backfill"]) == list(range(1, out["collected"] + 1))


def test_backfill_shows_in_long_ranges_after_a_rollup(tmp_path):
    """Buffered history older than the last roll-up must reach the 5-minute and hourly
    tiers too, or day/week/month charts keep the hole (only short ranges read raw rows)."""
    import time
    from app.schema import normalize
    from app.store import Store
    store = Store(tmp_path / "db.sqlite")
    now = time.time()
    # three days of live history, rolled up as the server does; then the server was away for the
    # last 6 hours of the first day, and the agent sends what it kept afterwards
    live = [s for s in range(0, 72 * 3600, 900) if not (24 * 3600 <= s < 30 * 3600)]
    t0 = now - 72 * 3600
    for s in live:
        store.record("alpha", normalize(sample(collected_at=t0 + s, cpu={"count": 4, "percent": 10.0}), 10))
    store.rollup(now)
    gap = []
    for s in range(24 * 3600, 30 * 3600, 900):
        d = normalize(sample(collected_at=t0 + s, interval=900.0, cpu={"count": 4, "percent": 90.0}), 0)
        gap.append(d)
    stored, skipped = store.record_backfill("alpha", gap, now)
    assert stored == len(gap) and skipped == 0

    def gap_rows(hours):
        rows = store.history("alpha", hours)["metrics"]
        return [r for r in rows if r["cpu"] is not None and r["cpu"] > 50], rows
    for hours in (72, 24 * 7, 24 * 30):  # 5-minute tier and then the hourly tier
        high, rows = gap_rows(hours)
        assert high, f"the backfilled gap is missing from the {hours}h chart"
    # re-sending changes nothing, and it stays consistent with a fresh roll-up
    assert store.record_backfill("alpha", gap, now) == (0, len(gap))
    store.rollup(now)
    assert gap_rows(72)[0]
