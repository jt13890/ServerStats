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
