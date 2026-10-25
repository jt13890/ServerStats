"""Out-of-memory alerts, the Rocket.Chat webhook, and pinging hosts that stop reporting."""
import asyncio
import json

import pytest
from fastapi.testclient import TestClient

TOKEN = "a" * 40


def _inline(notifier, sent):
    notifier.spawn = lambda fn, *a: fn(*a)
    notifier.send = sent.append
    return notifier


def _rc(**over):
    from app.config import RocketChat

    return RocketChat(webhook_url="https://chat.example.com/hooks/abc/def", **over)


# -- agent and schema ---------------------------------------------------------

def test_agent_reads_oom_kill_counter(monkeypatch):
    import agent_collector as a

    monkeypatch.setattr(a, "IS_WINDOWS", False)
    monkeypatch.setattr(a, "_read", lambda p: "nr_free_pages 1\noom_kill 7\npgfault 3\n")
    assert a._oom_kills() == 7
    monkeypatch.setattr(a, "_read", lambda p: "nr_free_pages 1\n")
    assert a._oom_kills() is None
    monkeypatch.setattr(a, "_read", lambda p: "oom_kill nope\n")
    assert a._oom_kills() is None
    monkeypatch.setattr(a, "IS_WINDOWS", True)
    assert a._oom_kills() is None


def test_schema_keeps_a_sane_oom_counter():
    from app.schema import normalize
    from agent_collector import collect

    base = collect(0.05, 20)[0]
    assert normalize({**base, "oom_kills": 3}, 20)["oom_kills"] == 3
    for bad in (None, "x", -1, float("nan"), 10 ** 30, [1]):
        assert normalize({**base, "oom_kills": bad}, 20)["oom_kills"] is None


# -- out-of-memory alerts -----------------------------------------------------

def test_oom_alert_only_on_a_rise():
    from app.notify import Notifier

    sent = []
    n = _inline(Notifier(_rc()), sent)
    mem = {"total": 1 << 30, "used": 900 << 20, "percent": 88.0, "swap_total": 1 << 29, "swap_used": 1 << 28}
    procs = [{"name": "small", "rss": 1 << 20}, {"name": "big`one", "rss": 600 << 20}]

    n.sample("TTS5", None, {"oom_kills": 4, "memory": mem}, now=1000)      # first sight: just a baseline
    n.sample("TTS5", {"oom_kills": 4}, {"oom_kills": 4, "memory": mem}, now=1015)
    assert sent == []
    n.sample("TTS5", {"oom_kills": 4}, {"oom_kills": 6, "memory": mem, "processes": procs}, now=1030)
    assert len(sent) == 1
    text = sent[0]["text"]
    assert "*TTS5*" in text and "killed 2 processes" in text and "6 since boot" in text
    assert "88% used" in text and "`big'one` (600 MB)" in text
    assert sent[0]["alias"] == "ServerStats" and "channel" not in sent[0]


def test_oom_counts_restart_after_reboot_and_respects_cooldown():
    from app.notify import Notifier

    sent = []
    n = _inline(Notifier(_rc(cooldown=300, channel="#alerts")), sent)
    n.sample("h", {"oom_kills": 9}, {"oom_kills": 1}, now=1000)  # rebooted, then one kill
    assert len(sent) == 1 and "killed 1 process." in sent[0]["text"] and sent[0]["channel"] == "#alerts"
    n.sample("h", {"oom_kills": 1}, {"oom_kills": 2}, now=1060)  # inside the cooldown: held back
    n.sample("h", {"oom_kills": 2}, {"oom_kills": 3}, now=1120)
    assert len(sent) == 1
    n.sample("h", {"oom_kills": 3}, {"oom_kills": 3}, now=1301)  # cooldown over: both are announced
    assert len(sent) == 2 and "killed 2 processes" in sent[1]["text"]


def test_oom_alerts_off_without_url_or_when_disabled():
    from app.config import RocketChat
    from app.notify import Notifier

    for conf in (None, RocketChat(), _rc(on_oom=False)):
        sent = []
        _inline(Notifier(conf), sent).sample("h", {"oom_kills": 1}, {"oom_kills": 5}, now=1)
        assert sent == []


def test_failed_delivery_is_swallowed():
    from app.notify import Notifier

    n = Notifier(_rc())
    n.spawn = lambda fn, *a: fn(*a)

    def boom(payload):
        raise OSError("down")

    n.send = boom
    n.sample("h", {"oom_kills": 1}, {"oom_kills": 2}, now=1)  # must not raise


def test_oom_alert_through_ingest(tmp_path, monkeypatch):
    from app import config
    from agent_collector import collect

    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(f"hosts:\n  - name: alpha\n    mode: agent\n    token: {TOKEN}\n")
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config.load, "__defaults__", (cfg_file,))
    from app.main import app

    with TestClient(app) as c:
        sent = []
        n = _inline(app.state.notifier, sent)
        n.conf = _rc()
        base = collect(0.05, 20)[0]

        def post(kills):
            r = c.post("/api/ingest", content=json.dumps({**base, "oom_kills": kills}),
                       headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"})
            assert r.status_code == 200

        post(0)
        post(0)
        assert sent == []
        post(2)
        assert len(sent) == 1 and "*alpha*" in sent[0]["text"]


# -- config -------------------------------------------------------------------

def _load(tmp_path, text):
    from app import config

    f = tmp_path / "c.yaml"
    f.write_text(text)
    return config.load(f)


def test_config_notifications_and_ping(tmp_path, monkeypatch):
    monkeypatch.delenv("SERVERSTATS_ROCKETCHAT_WEBHOOK", raising=False)
    c = _load(tmp_path, "hosts: []\n")
    assert c.notifications.rocketchat.webhook_url == "" and c.ping.enabled and c.ping.failures == 3
    c = _load(tmp_path, """
notifications:
  rocketchat:
    webhook_url: https://chat.example.com/hooks/a/b
    on_oom: false
    cooldown: 60
    channel: "#ops"
    on_recovery: false
ping:
  interval: 10
  failures: 2
  port: 2222
hosts:
  - name: gamma
    mode: agent
    token: %s
    ping_host: gamma.example.ts.net
""" % TOKEN)
    rc = c.notifications.rocketchat
    assert (rc.webhook_url, rc.on_oom, rc.cooldown, rc.channel, rc.on_offline, rc.on_recovery) == (
        "https://chat.example.com/hooks/a/b", False, 60.0, "#ops", True, False)
    assert (c.ping.interval, c.ping.failures, c.ping.port) == (10.0, 2, 2222)
    assert c.hosts[0].ping_host == "gamma.example.ts.net"
    monkeypatch.setenv("SERVERSTATS_ROCKETCHAT_WEBHOOK", "http://rc.local/hooks/x/y")
    assert _load(tmp_path, "hosts: []\n").notifications.rocketchat.webhook_url == "http://rc.local/hooks/x/y"


@pytest.mark.parametrize("text", [
    "notifications:\n  rocketchat:\n    webhook_url: ftp://nope\n",
    "notifications:\n  rocketchat:\n    webhook_url: javascript:alert(1)\n",
    "notifications:\n  rocketchat:\n    cooldown: soon\n",
    "ping:\n  failures: 0\n",
    "ping:\n  interval: 1\n",
    "ping:\n  port: 70000\n",
    "hosts:\n  - name: g\n    mode: agent\n    token: " + "t" * 30 + "\n    ping_host: 'a b;rm'\n",
])
def test_config_rejects_bad_values(tmp_path, monkeypatch, text):
    from app import config

    monkeypatch.delenv("SERVERSTATS_ROCKETCHAT_WEBHOOK", raising=False)
    with pytest.raises(config.ConfigError):
        _load(tmp_path, text)


# -- pinging hosts that stopped reporting -------------------------------------

class Probe:
    def __init__(self, *results):
        self.results, self.calls = list(results), []

    def __call__(self, target, port, timeout, tailscale_only=True):
        self.calls.append((target, port, tailscale_only))
        return self.results.pop(0) if len(self.results) > 1 else self.results[0]


@pytest.fixture()
def mon(tmp_path):
    from app.config import Ping
    from app.notify import Notifier
    from app.pingmon import PingMonitor
    from app.store import Store

    store = Store(tmp_path / "t.db")
    sent = []
    notifier = _inline(Notifier(_rc()), sent)

    def make(probe, **over):
        m = PingMonitor(Ping(interval=30, failures=3, **over), store, notifier, probe_fn=probe, grace=0)
        m.start_after = 0
        return m

    return make, store, sent


def run(coro):
    return asyncio.run(coro)


def items(**status):
    from app.pingmon import Item

    return [Item(n, s, f"{n.lower()}.ts.net", last_seen=100.0) for n, s in status.items()]


def test_offline_needs_consecutive_failed_rounds(mon):
    make, store, sent = mon
    probe = Probe("down")
    m = make(probe)
    fleet = items(TTS1="online", TTS5="offline")
    run(m.check(fleet, 1000))
    run(m.check(fleet, 1010))  # too soon: the next round is 30 s after the last
    assert len(probe.calls) == 1 and m.info("TTS5")["state"] == "checking" and sent == []
    run(m.check(fleet, 1030))
    assert sent == [] and store.flag("offline:TTS5") is None
    run(m.check(fleet, 1060))  # third unanswered round
    assert m.info("TTS5")["state"] == "offline" and store.flag("offline:TTS5") == 1060
    assert len(sent) == 1 and ":red_circle:" in sent[0]["text"] and "*TTS5*" in sent[0]["text"]
    assert "tts5.ts.net" in sent[0]["text"] and "16 min ago" in sent[0]["text"]
    run(m.check(fleet, 1090))
    run(m.check(fleet, 1120))
    assert len(sent) == 1  # one message per outage


def test_answering_host_is_an_agent_problem_not_an_outage(mon):
    make, store, sent = mon
    m = make(Probe("down", "down", "up", "down"))
    fleet = items(TTS1="online", TTS5="offline")
    for t in (1000, 1030, 1060):
        run(m.check(fleet, t))
    assert m.info("TTS5")["state"] == "agent-unresponsive" and sent == []
    run(m.check(fleet, 1090))  # the count started over, so one failure isn't enough
    assert m.info("TTS5")["state"] == "checking" and sent == []


def test_unresolvable_name_never_counts_as_offline(mon):
    make, store, sent = mon
    m = make(Probe("unknown"))
    fleet = items(TTS1="online", TTS5="offline")
    for t in (1000, 1030, 1060, 1090, 1120):
        run(m.check(fleet, t))
    assert m.info("TTS5")["state"] == "unknown" and sent == [] and store.flag("offline:TTS5") is None


def test_recovery_message_when_reports_resume(mon):
    make, store, sent = mon
    m = make(Probe("down"))
    down = items(TTS1="online", TTS5="offline")
    for t in (1000, 1030, 1060):
        run(m.check(down, t))
    assert len(sent) == 1
    run(m.check(items(TTS1="online", TTS5="online"), 1360))
    assert len(sent) == 2 and ":large_green_circle:" in sent[1]["text"] and "after 5 min." in sent[1]["text"]
    assert store.flag("offline:TTS5") is None and m.info("TTS5") is None
    run(m.check(items(TTS1="online", TTS5="online"), 1400))
    assert len(sent) == 2


def test_recovery_when_machine_answers_before_agent_does(mon):
    make, store, sent = mon
    m = make(Probe("down", "down", "down", "up"))
    fleet = items(TTS1="online", TTS5="offline")
    for t in (1000, 1030, 1060, 1090):
        run(m.check(fleet, t))
    assert len(sent) == 2 and "agent isn't reporting yet" in sent[1]["text"]
    assert store.flag("offline:TTS5") is None


def test_offline_flag_survives_a_restart(mon, tmp_path):
    make, store, sent = mon
    store.set_flag("offline:TTS5", 900)
    m = make(Probe("down"))
    fleet = items(TTS1="online", TTS5="offline")
    for t in (1000, 1030, 1060):
        run(m.check(fleet, t))
    assert sent == []  # already announced before the restart


def test_nothing_reporting_means_the_problem_is_here(mon):
    make, store, sent = mon
    probe = Probe("down")
    m = make(probe)
    fleet = items(TTS1="offline", TTS2="offline", TTS3="offline")
    for t in (1000, 1030, 1060, 1090):
        run(m.check(fleet, t))
    assert probe.calls == [] and sent == []


def test_only_hosts_that_stopped_reporting_are_pinged(mon):
    make, store, sent = mon
    probe = Probe("up")
    m = make(probe)
    fleet = items(TTS1="online", TTS2="pending", TTS3="offline", TTS4="error")
    run(m.check(fleet, 1000))
    assert sorted(c[0] for c in probe.calls) == ["tts3.ts.net", "tts4.ts.net"]


def test_disabled_and_grace_period(mon):
    make, store, sent = mon
    probe = Probe("down")
    m = make(probe, enabled=False)
    run(m.check(items(TTS1="online", TTS5="offline"), 1000))
    assert probe.calls == [] and m.info("TTS5") is None
    m = make(probe)
    m.start_after = 5000
    run(m.check(items(TTS1="online", TTS5="offline"), 1000))
    assert probe.calls == []


def test_removed_host_forgets_its_flag(mon):
    make, store, sent = mon
    store.enroll("TTS9", "hash", "tts9")
    store.set_flag("offline:TTS9", 5)
    store.remove_host("TTS9")
    assert store.flag("offline:TTS9") is None


# -- the probe itself ---------------------------------------------------------

def test_probe_only_follows_tailscale_addresses_for_reported_names(monkeypatch):
    from app import pingmon

    monkeypatch.setattr(pingmon, "icmp_echo", lambda addr, timeout: False)
    monkeypatch.setattr(pingmon, "tcp_answers", lambda addr, port, timeout: addr == "100.64.1.2")

    def resolve(addr):
        monkeypatch.setattr(pingmon.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", (addr, 0))])

    resolve("10.0.0.5")  # a LAN address named by an agent: not ours to probe
    assert pingmon.probe("evil", 22, 1) == "unknown"
    assert pingmon.probe("lan-box", 22, 1, tailscale_only=False) == "down"  # admin chose it
    resolve("100.64.1.2")
    assert pingmon.probe("ts-box", 22, 1) == "up"
    resolve("100.64.1.3")
    assert pingmon.probe("ts-box", 22, 1) == "down"
    assert pingmon.probe("bad name;", 22, 1) == "unknown"

    def nxdomain(*a, **k):
        raise OSError("nope")

    monkeypatch.setattr(pingmon.socket, "getaddrinfo", nxdomain)
    assert pingmon.probe("gone", 22, 1) == "unknown"


def test_icmp_checksum():
    from app.pingmon import _checksum

    pkt = bytes.fromhex("0800" "0000" "0000" "0001")
    c = _checksum(pkt)
    assert _checksum(pkt[:2] + c.to_bytes(2, "big") + pkt[4:]) == 0
