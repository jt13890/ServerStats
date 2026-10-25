"""Chat notifications: tell a Rocket.Chat incoming webhook about events in agent reports.

There is one event so far: the kernel killing processes because a host ran out
of memory. Agents report the kernel's OOM-kill counter with every report, and a
rise in that counter is an OOM.
"""

import json
import logging
import threading
import time
import urllib.request

log = logging.getLogger("serverstats")

TIMEOUT = 10  # seconds to wait for Rocket.Chat
TOP_PROCS = 3  # biggest memory users to list in the message


def _mb(n) -> str:
    return f"{(n or 0) / 1048576:.0f} MB"


def _span(seconds: float) -> str:
    s = max(int(seconds), 0)
    if s < 90:
        return f"{s} s"
    if s < 5400:
        return f"{round(s / 60)} min"
    if s < 172800:
        return f"{s // 3600} h {s % 3600 // 60} min"
    return f"{s // 86400} d {s % 86400 // 3600} h"


def _spawn(fn, *args) -> None:
    """Deliver in the background so a slow chat server never delays a report."""
    threading.Thread(target=fn, args=args, daemon=True).start()


class Notifier:
    def __init__(self, conf=None):
        self.conf = conf  # config.RocketChat, or None
        self.spawn = _spawn  # tests run deliveries inline
        self.send = self._post  # tests capture payloads here
        self._pending: dict[str, int] = {}  # host -> OOM kills not yet announced
        self._sent_at: dict[str, float] = {}  # host -> when we last messaged about it
        self._lock = threading.Lock()

    @property
    def configured(self) -> bool:
        return bool(self.conf and self.conf.webhook_url)

    @property
    def enabled(self) -> bool:
        """Out-of-memory alerts are on."""
        return self.configured and self.conf.on_oom

    def sample(self, host: str, prev: dict | None, cur: dict, now: float | None = None) -> None:
        """Called with every stored report; `prev` is the host's previous one, if any."""
        if not self.enabled:
            return
        new = cur.get("oom_kills")
        if new is None:  # an agent that doesn't report it (older, or not Linux)
            return
        old = (prev or {}).get("oom_kills")
        now = time.time() if now is None else now
        if old is None:
            delta = 0  # first report with the counter: just a starting point
        elif new >= old:
            delta = new - old
        else:
            delta = new  # the host rebooted and the counter started over
        with self._lock:
            n = self._pending.get(host, 0) + delta
            if not n:
                return
            if now - self._sent_at.get(host, float("-inf")) < self.conf.cooldown:
                self._pending[host] = n  # sent with the next message, once the cooldown is over
                return
            self._pending.pop(host, None)
            self._sent_at[host] = now
        self.spawn(self._deliver, self._payload(host, n, cur))

    def _payload(self, host: str, n: int, cur: dict) -> dict:
        total = cur.get("oom_kills") or n
        text = f":rotating_light: *{host}* ran out of memory: the kernel killed {n} process{'' if n == 1 else 'es'}"
        text += f" ({total} since boot)." if total != n else "."
        mem = cur.get("memory") or {}
        facts = []
        if mem.get("total"):
            facts.append(f"memory {mem.get('percent', 0):.0f}% used ({_mb(mem.get('used'))} of {_mb(mem['total'])})")
        if mem.get("swap_total"):
            facts.append(f"swap {_mb(mem.get('swap_used'))} of {_mb(mem['swap_total'])}")
        if facts:
            text += "\nAt the last report: " + ", ".join(facts) + "."
        procs = sorted((p for p in cur.get("processes") or [] if isinstance(p, dict)),
                       key=lambda p: p.get("rss") or 0, reverse=True)[:TOP_PROCS]
        if procs:
            text += "\nUsing the most memory now: " + ", ".join(
                "`%s` (%s)" % (str(p.get("name") or "?").replace("`", "'"), _mb(p.get("rss"))) for p in procs) + "."
        return self._message(text)

    def _message(self, text: str) -> dict:
        payload = {"alias": "ServerStats", "text": text}
        if self.conf.channel:
            payload["channel"] = self.conf.channel
        return payload

    def offline(self, host: str, target: str | None, last_seen: float | None, rounds: int, now: float | None = None) -> None:
        """A host stopped reporting and didn't answer ping `rounds` times in a row."""
        if not (self.configured and self.conf.on_offline):
            return
        now = time.time() if now is None else now
        text = f":red_circle: *{host}* looks offline: it doesn't answer ping"
        text += f" ({target})" if target else ""
        text += f" and has stopped reporting"
        text += f" (last report {_span(now - last_seen)} ago)." if last_seen else "."
        self.spawn(self._deliver, self._message(text))

    def recovered(self, host: str, down_for: float | None, agent_reporting: bool) -> None:
        """A host we called offline is answering again."""
        if not (self.configured and self.conf.on_offline and self.conf.on_recovery):
            return
        text = f":large_green_circle: *{host}* is back"
        text += f" after {_span(down_for)}" if down_for else ""
        text += "." if agent_reporting else ": it answers ping again, but its ServerStats agent isn't reporting yet."
        self.spawn(self._deliver, self._message(text))

    def _deliver(self, payload: dict) -> None:
        try:
            self.send(payload)
        except Exception as e:  # a chat outage must never touch monitoring
            log.warning("Rocket.Chat notification failed: %s", e)

    def _post(self, payload: dict) -> None:
        req = urllib.request.Request(
            self.conf.webhook_url, data=json.dumps(payload).encode(), method="POST",
            headers={"Content-Type": "application/json", "User-Agent": "ServerStats"},
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            resp.read(1024)
