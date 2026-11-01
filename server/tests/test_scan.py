"""Disk scans: the agent's walker, its inhibitors, and the on-demand request/result flow."""

import json
import os
import threading
import time

import pytest
from fastapi.testclient import TestClient

TOKEN_A = "a" * 40
USER = {"X-authentik-username": "alice", "X-ServerStats-Action": "1"}
CONFIG = f"""
settings:
  require_auth_header: true
hosts:
  - name: alpha
    mode: agent
    token: {TOKEN_A}
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


def report(client, **over):
    """An agent report; returns the server's reply."""
    from agent_collector import collect

    data = collect(0.05, 20)[0]
    data.update(agent_version="1.8.0", updates=True)
    data.update(over)
    return client.post("/api/ingest", content=json.dumps(data),
                       headers={"Authorization": f"Bearer {TOKEN_A}", "Content-Type": "application/json"})


def post(client, payload):
    return client.post("/api/ingest", content=json.dumps(payload),
                       headers={"Authorization": f"Bearer {TOKEN_A}", "Content-Type": "application/json"})


def write(path, size):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(b"x" * size)


@pytest.fixture()
def tree(tmp_path):
    root = tmp_path / "scanme"
    for i in range(6):
        for j in range(4):
            write(str(root / f"d{i}" / f"s{j}" / "data.bin"), 300_000 + i * 1000 + j)
            write(str(root / f"d{i}" / f"s{j}" / "tiny.txt"), 100)
    write(str(root / "big" / "huge.iso"), 5_000_000)
    os.link(root / "big" / "huge.iso", root / "big" / "huge-copy.iso")  # one file, two names
    os.symlink(root / "big", root / "alias")                            # never followed
    return root


def run_scan(path, **kw):
    import agent_collector as ac

    scan = ac._Scan(str(path), kw.pop("cross_fs", False), threading.Event())
    tree = scan.run()
    return scan, scan.result(tree, 1.0, 2.0)


def test_scan_totals_are_exact_and_each_file_counts_once(tree):
    scan, result = run_scan(tree)
    on_disk = {os.stat(os.path.join(d, f)).st_ino: os.stat(os.path.join(d, f)).st_blocks * 512
               for d, _, files in os.walk(tree) for f in files if not os.path.islink(os.path.join(d, f))}
    assert result["alloc"] == sum(on_disk.values())  # the hard link and the symlink add nothing
    assert result["tree"]["s"] == result["alloc"]
    assert result["links"] == 1
    assert result["top"][0][0].endswith(".iso") and result["top"][0][1] >= 5_000_000
    assert any(row[0] == ".bin" for row in result["exts"])
    # small files are folded into "smaller items", not lost
    d0 = next(c for c in result["tree"]["c"] if c.get("n") == "big")
    assert d0["s"] > 0


def test_unreadable_folders_are_counted_not_hidden(tree):
    if os.geteuid() == 0:
        pytest.skip("root can read everything")
    locked = tree / "locked"
    locked.mkdir()
    locked.chmod(0)
    try:
        _, result = run_scan(tree)
    finally:
        locked.chmod(0o700)
    assert result["unreadable"] == 1 and result["unreadable_paths"] == [str(locked)]


def test_other_filesystems_are_skipped_unless_asked(tree, monkeypatch):
    import agent_collector as ac

    real = os.stat_result
    scan = ac._Scan(str(tree), False, threading.Event())
    scan.root_dev = -1  # pretend everything below is a different mount
    # Walk with a wrong root device: every subfolder looks like another filesystem.
    monkeypatch.setattr(os, "lstat", lambda p: type("S", (), {"st_mode": 0o40755, "st_dev": -1})())
    tree_node = scan.run()
    assert tree_node["s"] == scan.alloc  # only top-level files; the mounts weren't entered
    assert scan.skipped_mounts


def test_memory_inhibitor_folds_detail_but_keeps_totals(tree, monkeypatch):
    import agent_collector as ac

    monkeypatch.setattr(ac, "SCAN_LIVE_NODES", 6)
    for i in range(300):  # the check runs every 256 entries
        write(str(tree / "pad" / f"p{i}.txt"), 10)
    scan, result = run_scan(tree)
    assert result["keep_min"] > ac.SCAN_KEEP_MIN
    assert result["tree"]["s"] == result["alloc"]  # coarser, never wrong
    assert any("folded away" in n for n in result["notes"])


def test_hardlink_memory_is_capped(tree, monkeypatch):
    import agent_collector as ac

    monkeypatch.setattr(ac, "SCAN_MAX_HARDLINKS", 0)
    scan, result = run_scan(tree)
    assert len(scan.seen) == 0
    assert any("hard-linked" in n for n in result["notes"])


def test_depth_inhibitor_limits_open_folders(tmp_path, monkeypatch):
    import agent_collector as ac

    monkeypatch.setattr(ac, "SCAN_MAX_WALK_DEPTH", 5)
    deep = tmp_path / "/".join("x" * 1 for _ in range(12))
    write(str(deep / "f.bin"), 1000)
    scan, result = run_scan(tmp_path)
    assert result["unreadable"] == 0  # too deep is not the same as unreadable
    assert any("levels deep" in n and "were not entered" in n for n in result["notes"]) or any("was not entered" in n for n in result["notes"])


def test_memory_limit_aborts_instead_of_growing(tree, monkeypatch):
    import agent_collector as ac

    scan = ac._Scan(str(tree), False, threading.Event())
    scan.rss0 = 0
    monkeypatch.setattr(ac, "_rss", lambda: ac.SCAN_MAX_RSS * 2)
    with pytest.raises(MemoryError):
        scan._check_memory([], 0)


def test_busy_host_pauses_the_scan_and_cancel_ends_the_pause(tree, monkeypatch):
    import agent_collector as ac

    monkeypatch.setattr(ac, "_host_busy", lambda: True)
    scan = ac._Scan(str(tree), False, threading.Event())
    scan.stop.set()
    with pytest.raises(ac._Cancelled):
        scan._wait_while_busy()


def test_cancel_stops_the_walk(tmp_path):
    import agent_collector as ac

    for i in range(600):  # the walker checks for a cancel every 256 entries
        write(str(tmp_path / f"f{i}.txt"), 10)
    stop = threading.Event()
    stop.set()
    with pytest.raises(ac._Cancelled):
        ac._Scan(str(tmp_path), False, stop).run()


def test_result_stays_under_the_server_limit(tmp_path, monkeypatch):
    import agent_collector as ac

    monkeypatch.setattr(ac, "SCAN_MAX_NODES", 50)
    for i in range(300):
        write(str(tmp_path / f"d{i}" / "f.bin"), 300_000 + i)
    scan, result = run_scan(tmp_path)
    assert ac._count_nodes(result["tree"]) <= 50 + 1
    assert result["tree"]["s"] == result["alloc"]
    assert len(json.dumps(result)) < ac.SCAN_MAX_BYTES


# -- the request / result flow ------------------------------------------------------

def test_scan_flow_from_click_to_saved_history(client, tree):
    import agent_collector as ac

    assert report(client).status_code == 200
    r = client.get("/api/hosts/alpha/scans", headers=USER).json()
    assert r["scans"] == [] and r["unavailable"] is None

    # Nothing is scanned unless someone asks.
    assert "scan" not in report(client).json()

    started = client.post("/api/hosts/alpha/scans", json={"path": str(tree)}, headers=USER)
    assert started.status_code == 200
    sid = started.json()["id"]

    # A second request while one is in progress is refused.
    assert client.post("/api/hosts/alpha/scans", json={"path": "/"}, headers=USER).status_code == 409

    # The agent's next report carries the request (and keeps carrying it until it says it started).
    offer = report(client).json()["scan"]
    assert offer == {"id": sid, "path": str(tree), "cross_fs": False}
    assert report(client).json()["scan"]["id"] == sid
    assert post(client, {"scan_progress": {"id": sid, "files": 5, "dirs": 2, "bytes": 99, "current": "/x"}}).json() == {
        "ok": True, "cancel": False}
    assert "scan" not in report(client).json()
    listed = client.get("/api/hosts/alpha/scans", headers=USER).json()["scans"][0]
    assert listed["status"] == "running" and listed["progress"]["files"] == 5

    scan, result = run_scan(tree)
    assert post(client, {"scan_result": {"id": sid, "result": result}}).json()["stored"] is True

    done = client.get(f"/api/hosts/alpha/scans/{sid}", headers=USER).json()
    assert done["status"] == "done" and done["alloc"] == result["alloc"]
    assert done["result"]["tree"]["s"] == result["alloc"] and done["result"]["top"]

    # A second run is kept alongside the first.
    sid2 = client.post("/api/hosts/alpha/scans", json={"path": str(tree)}, headers=USER).json()["id"]
    assert sid2 != sid
    post(client, {"scan_result": {"id": sid2, "error": "boom"}})
    runs = client.get("/api/hosts/alpha/scans", headers=USER).json()["scans"]
    assert [(s["id"], s["status"]) for s in runs] == [(sid2, "failed"), (sid, "done")]

    # Deleting is explicit, and pruning history leaves scans alone.
    client.app.state.store.prune_older_than(0.0001)
    assert client.get(f"/api/hosts/alpha/scans/{sid}", headers=USER).status_code == 200
    assert client.post(f"/api/hosts/alpha/scans/{sid}/delete", headers=USER).status_code == 200
    assert client.get(f"/api/hosts/alpha/scans/{sid}", headers=USER).status_code == 404


def test_cancel_tells_the_agent_to_stop(client):
    report(client)
    sid = client.post("/api/hosts/alpha/scans", json={"path": "/"}, headers=USER).json()["id"]
    report(client)
    post(client, {"scan_progress": {"id": sid, "files": 1}})
    assert client.post(f"/api/hosts/alpha/scans/{sid}/cancel", headers=USER).status_code == 200
    assert post(client, {"scan_progress": {"id": sid, "files": 2}}).json()["cancel"] is True
    assert client.get(f"/api/hosts/alpha/scans/{sid}", headers=USER).json()["status"] == "cancelled"
    # A result for a scan nobody is waiting for is ignored.
    assert post(client, {"scan_result": {"id": sid, "error": "late"}}).json()["stored"] is False
    # A running scan can't be deleted, only cancelled.
    sid2 = client.post("/api/hosts/alpha/scans", json={"path": "/"}, headers=USER).json()["id"]
    assert client.post(f"/api/hosts/alpha/scans/{sid2}/delete", headers=USER).status_code == 409


def test_requests_are_validated(client):
    report(client)
    for bad in ({"path": "relative/dir"}, {"path": ""}, {"path": "/a\nb"}, {"path": "/" + "x" * 2000},
                {"path": 5}, {"path": "/", "cross_fs": "yes"}, {}):
        assert client.post("/api/hosts/alpha/scans", json=bad, headers=USER).status_code == 400, bad
    assert client.post("/api/hosts/alpha/scans", json={"path": "C:\\Users"}, headers=USER).status_code == 200
    # Changing state needs the action header, like every other change.
    assert client.post("/api/hosts/alpha/scans", json={"path": "/"},
                       headers={"X-authentik-username": "alice"}).status_code == 403


def test_old_agents_and_silent_hosts_cannot_be_scanned(client):
    assert client.post("/api/hosts/alpha/scans", json={"path": "/"}, headers=USER).status_code == 409  # never reported
    report(client, agent_version="1.7.0")
    r = client.post("/api/hosts/alpha/scans", json={"path": "/"}, headers=USER)
    assert r.status_code == 409 and "update" in r.json()["detail"]
    assert "scan" not in report(client, agent_version="1.7.0").json()


def test_stuck_scans_expire(client):
    report(client)
    store = client.app.state.store
    sid = client.post("/api/hosts/alpha/scans", json={"path": "/"}, headers=USER).json()["id"]
    store.scan_expire(time.time() + 601)  # the agent never picked it up
    s = client.get(f"/api/hosts/alpha/scans/{sid}", headers=USER).json()
    assert s["status"] == "failed" and "pick up" in s["error"]

    sid = client.post("/api/hosts/alpha/scans", json={"path": "/"}, headers=USER).json()["id"]
    post(client, {"scan_progress": {"id": sid}})
    store.scan_expire(time.time() + 601)  # it started, then went quiet
    assert client.get(f"/api/hosts/alpha/scans/{sid}", headers=USER).json()["error"].startswith("the agent stopped")


def test_hostile_results_are_rebuilt_not_trusted(client):
    report(client)
    sid = client.post("/api/hosts/alpha/scans", json={"path": "/"}, headers=USER).json()["id"]
    deep = {"t": "d", "n": "x", "s": 1, "a": 1, "f": 1}
    node = deep
    for _ in range(500):
        node["c"] = [{"t": "d", "n": "y" * 5000, "s": "<script>", "a": float("inf"), "f": -5}]
        node = node["c"][0]
    evil = {"path": "/" * 5000, "alloc": "lots", "files": [], "tree": deep, "exts": [["x", 1, 2]] + [["e", 1, 1, 1]] * 9999,
            "top": "nope", "notes": ["n"] * 500, "fs": "full", "unreadable_paths": [1, 2, 3]}
    evil["alloc"] = 10 ** 40
    r = post(client, {"scan_result": {"id": sid, "result": evil}})
    assert r.status_code == 200
    s = client.get(f"/api/hosts/alpha/scans/{sid}", headers=USER).json()
    assert s["status"] == "done"
    res = s["result"]
    depth, n = 0, res["tree"]
    while n.get("c"):
        n, depth = n["c"][0], depth + 1
    assert depth <= 64 and len(n["n"]) <= 255 and n["s"] == 0 and n["f"] == 0
    assert len(res["exts"]) <= 201 and len(res["notes"]) <= 10 and res["top"] == [] and res["fs"] is None
    # No tree at all: recorded as a failed scan, not a crash.
    sid2 = client.post("/api/hosts/alpha/scans", json={"path": "/"}, headers=USER).json()["id"]
    assert post(client, {"scan_result": {"id": sid2, "result": {"tree": 5}}}).status_code == 200
    assert client.get(f"/api/hosts/alpha/scans/{sid2}", headers=USER).json()["status"] == "failed"


def test_agents_cannot_touch_each_others_scans(client, tmp_path):
    report(client)
    sid = client.post("/api/hosts/alpha/scans", json={"path": "/"}, headers=USER).json()["id"]
    store = client.app.state.store
    assert store.scan_progress("beta", sid, {}, time.time()) is False
    assert store.scan_finish("beta", sid, time.time(), error="x") is False
    assert client.get(f"/api/hosts/alpha/scans/{sid}", headers=USER).json()["status"] == "pending"
    assert store.scan_cancel("beta", sid, time.time()) is False and store.scan_delete("beta", sid) is False


def test_scans_follow_a_host_being_removed(client):
    store = client.app.state.store
    report(client)
    client.post("/api/hosts/alpha/scans", json={"path": "/"}, headers=USER)
    store.compact({"alpha"})
    assert store.scan_list("alpha", time.time())
    store.compact(set())  # host no longer configured
    assert store.scan_list("alpha", time.time()) == []


def test_scan_cap_per_host(client, monkeypatch):
    from app import store as store_mod

    report(client)
    monkeypatch.setattr(store_mod, "MAX_SCANS_PER_HOST", 1)
    sid = client.post("/api/hosts/alpha/scans", json={"path": "/"}, headers=USER).json()["id"]
    client.post(f"/api/hosts/alpha/scans/{sid}/cancel", headers=USER)
    r = client.post("/api/hosts/alpha/scans", json={"path": "/"}, headers=USER)
    assert r.status_code == 409 and "delete some" in r.json()["detail"]


# -- the root scan helper -------------------------------------------------------------

import builtins
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

AGENT = Path(__file__).resolve().parents[2] / "agent"


@pytest.fixture()
def helper(monkeypatch):
    """A scan helper listening on a short temp socket (unix socket paths are length-limited)."""
    import agent_collector as ac

    d = tempfile.mkdtemp(prefix="ss")
    h = ac._ScanHelper(os.path.join(d, "s.sock"))
    h.bind()
    threading.Thread(target=h.serve_forever, daemon=True).start()
    monkeypatch.setattr(ac, "SCAN_HELPER_SOCK", h.path)
    yield h
    h.close()
    shutil.rmtree(d, ignore_errors=True)


def ask(path, **kw):
    """Send a request line to the helper by hand and read its first reply line."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(path)
    s.sendall(kw["raw"])
    data = b""
    while b"\n" not in data:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    s.close()
    return json.loads(data.split(b"\n")[0])


def slow_visit(monkeypatch):
    """Make every directory entry take a moment, so a scan stays in flight long enough to interrupt."""
    import agent_collector as ac

    real = ac._Scan._visit

    def slow(self, entry, frame, stack):
        time.sleep(0.002)
        return real(self, entry, frame, stack)

    monkeypatch.setattr(ac._Scan, "_visit", slow)


def test_helper_gives_the_same_answer_as_scanning_directly(tree, helper):
    import agent_collector as ac

    progress = []
    kind, got = ac._scan_via_helper(str(tree), False, threading.Event(), progress.append)
    assert kind == "result"
    _, direct = run_scan(tree)
    assert (got["alloc"], got["files"], got["dirs"]) == (direct["alloc"], direct["files"], direct["dirs"])
    assert got["tree"]["s"] == got["alloc"]
    assert got["root"] == (os.geteuid() == 0)  # the result says who did the reading
    assert progress and set(progress[0]) >= {"files", "dirs", "bytes", "unreadable", "current"}
    assert oct(os.stat(helper.path).st_mode & 0o777) == "0o660"  # the agent's group and nobody else


def test_helper_cancel_stops_the_scan_and_frees_it(tmp_path, helper, monkeypatch):
    import agent_collector as ac

    for i in range(1500):
        write(str(tmp_path / f"f{i}.bin"), 10)
    slow_visit(monkeypatch)
    stop = threading.Event()
    started = time.monotonic()
    kind, _ = ac._scan_via_helper(str(tmp_path), False, stop, lambda info: stop.set())
    assert kind == "cancelled" and time.monotonic() - started < 3  # not the ~3 s a full scan takes
    # the helper notices the hang-up and takes the next request
    for _ in range(40):
        again = ac._scan_via_helper(str(tmp_path), False, threading.Event(), lambda i: None)
        if again and again[0] != "error":
            break
        time.sleep(0.1)
    assert again[0] in ("result", "cancelled")


def test_helper_runs_one_scan_at_a_time(tmp_path, helper, monkeypatch):
    import agent_collector as ac

    for i in range(1200):
        write(str(tmp_path / f"f{i}.bin"), 10)
    slow_visit(monkeypatch)
    first_stop = threading.Event()
    first = []
    t = threading.Thread(target=lambda: first.append(ac._scan_via_helper(str(tmp_path), False, first_stop, lambda i: None)))
    t.start()
    time.sleep(0.5)
    kind, why = ac._scan_via_helper(str(tmp_path), False, threading.Event(), lambda i: None)
    assert kind == "error" and "already running" in why
    first_stop.set()
    t.join(5)


@pytest.mark.parametrize("raw", [
    b"not json\n",
    b"[]\n",
    b'{"v":1,"path":"relative/dir","cross_fs":false}\n',
    b'{"v":1,"path":"/a\\u0000b","cross_fs":false}\n',
    b'{"v":1,"path":"/a\\nb","cross_fs":false}\n',
    b'{"v":2,"path":"/","cross_fs":false}\n',
    b'{"v":1,"path":"/","cross_fs":"yes"}\n',
    b'{"v":1,"path":5,"cross_fs":false}\n',
    b'{"v":1,"path":"/' + b"x" * 2000 + b'","cross_fs":false}\n',
    b"x" * 6000,  # a request that never ends
])
def test_helper_rejects_bad_requests_and_keeps_serving(tree, helper, raw):
    import agent_collector as ac

    assert "error" in ask(helper.path, raw=raw)
    kind, got = ac._scan_via_helper(str(tree), False, threading.Event(), lambda i: None)
    assert kind == "result" and got["files"] > 0


def test_scanning_never_opens_the_files_it_measures(tree, monkeypatch):
    real_open = builtins.open

    def guarded(path, *a, **k):
        if str(path).startswith(str(tree)):
            raise AssertionError("opened a scanned file: %s" % path)
        return real_open(path, *a, **k)

    monkeypatch.setattr(builtins, "open", guarded)
    _, result = run_scan(tree)
    assert result["files"] > 0


def test_no_helper_means_the_agent_scans_for_itself(tree, tmp_path, monkeypatch):
    import agent_collector as ac

    monkeypatch.setattr(ac, "SCAN_HELPER_SOCK", str(tmp_path / "missing.sock"))
    assert ac._scan_via_helper(str(tree), False, threading.Event(), lambda i: None) is None
    stale = tmp_path / "stale.sock"  # a socket file with nothing listening, or one we may not use
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(str(stale))
    s.close()
    monkeypatch.setattr(ac, "SCAN_HELPER_SOCK", str(stale))
    assert ac._scan_via_helper(str(tree), False, threading.Event(), lambda i: None) is None


def posted_through_scanner(monkeypatch, tree):
    """Run the agent's scan flow end to end with the network stubbed; returns what it would have sent."""
    import agent_collector as ac

    sent = []
    monkeypatch.setattr(ac, "_post", lambda opener, url, token, payload, timeout=15: sent.append(payload) or {})
    scanner = ac._Scanner()
    scanner.maybe_start(None, "http://x", "t", {"id": 7, "path": str(tree), "cross_fs": False})
    scanner.thread.join(20)
    results = [p["scan_result"] for p in sent if "scan_result" in p]
    assert len(results) == 1 and results[0]["id"] == 7
    assert any("scan_progress" in p and p["scan_progress"]["id"] == 7 for p in sent)
    return results[0]


def posted_through_scanner_raw(monkeypatch, tree):
    import agent_collector as ac

    sent = []
    monkeypatch.setattr(ac, "_post", lambda opener, url, token, payload, timeout=15: sent.append(payload) or {})
    scanner = ac._Scanner()
    scanner.maybe_start(None, "http://x", "t", {"id": 9, "path": str(tree), "cross_fs": False})
    scanner.thread.join(20)
    return [p["scan_result"] for p in sent if "scan_result" in p][0]


def test_agent_hands_the_scan_to_the_helper_when_there_is_one(tree, helper, monkeypatch):
    import agent_collector as ac

    seen = []
    real = ac._scan_via_helper
    monkeypatch.setattr(ac, "_scan_via_helper", lambda *a, **k: seen.append(1) or real(*a, **k))
    result = posted_through_scanner(monkeypatch, tree)["result"]
    assert seen and result["files"] > 0 and result["root"] == (os.geteuid() == 0)


def test_agent_scans_itself_when_there_is_no_helper(tree, tmp_path, monkeypatch):
    import agent_collector as ac

    monkeypatch.setattr(ac, "SCAN_HELPER_SOCK", str(tmp_path / "none.sock"))
    result = posted_through_scanner(monkeypatch, tree)["result"]
    assert result["files"] > 0 and result["root"] == (os.geteuid() == 0)


def test_a_helper_error_is_reported_not_quietly_retried_without_root(tree, helper, monkeypatch):
    import agent_collector as ac

    monkeypatch.setattr(ac, "_scan_via_helper", lambda *a, **k: ("error", "the helper said no"))
    direct = []
    monkeypatch.setattr(ac._Scan, "run", lambda self: direct.append(1))  # would mean it scanned for itself
    payload = posted_through_scanner_raw(monkeypatch, tree)
    assert payload["error"] == "the helper said no" and "result" not in payload and not direct


def test_helper_with_a_different_protocol_says_so(helper, monkeypatch):
    import agent_collector as ac

    monkeypatch.setattr(ac, "SCAN_HELPER_PROTOCOL", 99)  # a helper from a different release
    reply = ask(helper.path, raw=b'{"v":1,"path":"/","cross_fs":false}\n')
    assert "unsupported request" in reply["error"] and "re-run the installer" in reply["error"]


def test_helper_process_starts_from_the_command_line(tree):
    import agent_collector as ac

    d = tempfile.mkdtemp(prefix="ss")
    sock = os.path.join(d, "s.sock")
    p = subprocess.Popen([sys.executable, str(AGENT / "serverstats_agent.py"), "--scan-helper", sock],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        for _ in range(100):
            if os.path.exists(sock):
                break
            time.sleep(0.05)
        old, ac.SCAN_HELPER_SOCK = ac.SCAN_HELPER_SOCK, sock
        try:
            kind, got = ac._scan_via_helper(str(tree), False, threading.Event(), lambda i: None)
        finally:
            ac.SCAN_HELPER_SOCK = old
        assert kind == "result" and got["files"] > 0
    finally:
        p.terminate()
        p.wait(5)
        shutil.rmtree(d, ignore_errors=True)


def test_server_keeps_only_a_real_root_flag():
    from app.schema import normalize_scan

    _, result = run_scan(Path(__file__).parent)
    for given, kept in ((True, True), (False, False), ("yes", None), (1, None), (None, None)):
        assert normalize_scan(dict(result, root=given))["root"] is kept


# -- the installer -----------------------------------------------------------------------

INSTALL = (AGENT / "install.sh").read_text()


def scan_unit_text():
    start = INSTALL.index('cat > "$SCAN_UNIT" <<\'EOF\'') + len('cat > "$SCAN_UNIT" <<\'EOF\'\n')
    return INSTALL[start:INSTALL.index("\nEOF\n", start) + 1]


def test_installer_is_valid_shell():
    assert subprocess.run(["sh", "-n", str(AGENT / "install.sh")], capture_output=True).returncode == 0


def test_scan_helper_unit_is_locked_down():
    unit = scan_unit_text()
    for needed in ("CapabilityBoundingSet=CAP_DAC_READ_SEARCH", "NoNewPrivileges=yes", "ProtectSystem=strict",
                   "PrivateNetwork=yes", "RestrictAddressFamilies=AF_UNIX", "MemoryMax=", "TasksMax=",
                   "OOMScoreAdjust=", "IOSchedulingClass=idle", "Group=serverstats-agent", "--scan-helper"):
        assert needed in unit, needed
    # nothing that would let it write or reach out: no extra capabilities, no writable paths, no network
    assert "ReadWritePaths" not in unit and "AmbientCapabilities" not in unit and "PrivateNetwork=no" not in unit
    assert unit.count("CapabilityBoundingSet=") == 1


@pytest.mark.skipif(not shutil.which("systemd-analyze"), reason="needs systemd-analyze")
def test_scan_helper_unit_is_accepted_by_systemd(tmp_path):
    f = tmp_path / "serverstats-scan.service"
    f.write_text(scan_unit_text())
    out = subprocess.run(["systemd-analyze", "verify", str(f)], capture_output=True, text=True)
    problems = [l for l in (out.stdout + out.stderr).splitlines()
                if any(w in l for w in ("Unknown key", "Unknown lvalue", "Failed to parse", "Invalid"))]
    assert not problems, problems


def test_installer_can_opt_out_and_uninstall_removes_the_helper():
    assert "--no-root-scan) NO_ROOT_SCAN=1" in INSTALL
    uninstall = INSTALL[INSTALL.index('if [ "$UNINSTALL" -eq 1 ]'):INSTALL.index("MODES=0")]
    assert "serverstats-scan" in uninstall and '"$SCAN_UNIT"' in uninstall and '"$SCAN_INITD"' in uninstall
    assert "--no-root-scan" in INSTALL.split("set -eu")[0]  # documented in the header
