"""Tells a stopped agent from a stopped machine.

When a host stops reporting, ping it by its Tailscale name. A host that still
answers has an agent (or SSH collector) problem; a host that stays silent for
several rounds in a row is confirmed offline, and only then is the chat told.

No root or extra capabilities are needed: the ICMP echo goes through the
kernel's unprivileged "ping socket", and a TCP connect backs it up (a refusal
counts as an answer, because only a machine that is up can refuse).
"""

import asyncio
import ipaddress
import logging
import os
import re
import socket
import struct
import time
from dataclasses import dataclass

from .notify import Notifier
from .store import Store

log = logging.getLogger("serverstats")

TAILSCALE_NET = ipaddress.ip_network("100.64.0.0/10")
NAME_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
ECHOES = 2  # ICMP echoes per round
MAX_PARALLEL = 8  # hosts pinged at once


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def icmp_echo(addr: str, timeout: float) -> bool | None:
    """True if addr answers an echo, False if not, None if this process can't send ICMP at all."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    except OSError:
        return None
    with sock:
        seq = os.getpid() & 0xFFFF
        body = b"serverstats"
        packet = struct.pack("!BBHHH", 8, 0, 0, 0, seq) + body
        packet = struct.pack("!BBHHH", 8, 0, _checksum(packet), 0, seq) + body
        try:
            sock.sendto(packet, (addr, 0))
        except OSError:
            return False  # no route, network unreachable
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                return False
            sock.settimeout(left)
            try:
                data, src = sock.recvfrom(1024)
            except OSError:  # includes the timeout
                return False
            # An echo reply (type 0) for our sequence number. The kernel swaps in its own id.
            if src[0] == addr and len(data) >= 8 and data[0] == 0 and struct.unpack("!H", data[6:8])[0] == seq:
                return True


def tcp_answers(addr: str, port: int, timeout: float) -> bool:
    try:
        socket.create_connection((addr, port), timeout).close()
        return True
    except ConnectionRefusedError:
        return True  # a reset: the machine is up, just nothing listening
    except OSError:
        return False


def probe(target: str, port: int, timeout: float, tailscale_only: bool = True) -> str:
    """One round: "up" if the machine answers, "down" if it doesn't, "unknown" if it couldn't be checked.

    `tailscale_only` is for names an agent reported about itself (untrusted): they're
    only pinged if they resolve to a Tailscale address, so a bad report can't point the
    server at anything else.
    """
    if not NAME_OK.match(target) and not _is_ip(target):
        return "unknown"
    try:
        addr = socket.getaddrinfo(target, None, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    except (OSError, IndexError):
        return "unknown"
    if tailscale_only and ipaddress.ip_address(addr) not in TAILSCALE_NET:
        return "unknown"
    for _ in range(ECHOES):
        if icmp_echo(addr, timeout):
            return "up"
        if icmp_echo(addr, 0) is None:
            break  # this process can't ping: the TCP check below has to do
    return "up" if tcp_answers(addr, port, timeout) else "down"


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


@dataclass
class Item:
    """A host that may need pinging, as the server sees it right now."""
    name: str
    status: str  # online, offline, error, pending
    target: str | None  # what to ping
    trusted: bool = False  # target came from the admin (config.yaml), not from the host's own report
    last_seen: float | None = None


@dataclass
class _Track:
    fails: int = 0
    next_at: float = 0.0
    state: str | None = None  # agent-unresponsive, checking, offline, unknown
    checked_at: float | None = None


class PingMonitor:
    def __init__(self, conf, store: Store, notifier: Notifier, probe_fn=probe, grace: float = 30.0):
        self.conf = conf  # config.Ping
        self.store = store
        self.notifier = notifier
        self.probe = probe_fn
        self.start_after = time.time() + grace  # reports are still arriving just after a restart
        self.tracks: dict[str, _Track] = {}
        self._warned: set[str] = set()
        self._guard_logged = False

    def info(self, name: str) -> dict | None:
        """What the last ping found, for the API: None when the host is reporting."""
        t = self.tracks.get(name)
        if not self.conf.enabled or t is None or t.state is None:
            return None
        return {"state": t.state, "checked_at": t.checked_at}

    async def check(self, items: list[Item], now: float | None = None) -> None:
        now = time.time() if now is None else now
        if not self.conf.enabled or now < self.start_after:
            return
        reporting = {i.name for i in items if i.status == "online"}
        due = []
        for it in items:
            t = self.tracks.setdefault(it.name, _Track())
            if it.status == "online":
                self._reporting_again(it.name, t, now)
            elif it.status in ("offline", "error") and it.target and now >= t.next_at:
                due.append((it, t))
        if not due:
            return
        # If nothing at all is reporting, the problem is more likely on this side (this
        # server's own network or Tailscale) than a whole fleet dying at once.
        if not reporting and len(items) >= 3:
            if not self._guard_logged:
                log.warning("no host is reporting: not pinging, since this server's own network may be down")
                self._guard_logged = True
            return
        self._guard_logged = False
        sem = asyncio.Semaphore(MAX_PARALLEL)

        async def one(it):
            async with sem:
                return await asyncio.to_thread(
                    self.probe, it.target, self.conf.port, self.conf.timeout, not it.trusted)

        results = await asyncio.gather(*(one(it) for it, _ in due), return_exceptions=True)
        for (it, t), res in zip(due, results):
            if isinstance(res, BaseException):
                log.warning("%s: ping failed: %s", it.name, res)
                res = "unknown"
            self._apply(it, t, res, now)

    def _apply(self, it: Item, t: _Track, result: str, now: float) -> None:
        t.next_at = now + self.conf.interval
        t.checked_at = now
        if result == "up":
            t.fails = 0
            t.state = "agent-unresponsive"  # the machine answers; the agent doesn't
            self._warned.discard(it.name)
            if self.store.flag(f"offline:{it.name}") is not None:
                self._recovered(it.name, agent_reporting=False, now=now)
        elif result == "down":
            t.fails += 1
            t.state = "offline" if t.fails >= self.conf.failures else "checking"
            if t.fails >= self.conf.failures and self.store.flag(f"offline:{it.name}") is None:
                self.store.set_flag(f"offline:{it.name}", now)
                log.warning("%s: confirmed offline (no answer to %d rounds of ping)", it.name, t.fails)
                self.notifier.offline(it.name, it.target, it.last_seen, t.fails, now)
        else:
            t.state = "unknown"  # couldn't be checked: never counts towards "offline"
            if it.name not in self._warned:
                self._warned.add(it.name)
                log.warning("%s: can't ping %r (it doesn't resolve to a Tailscale address)", it.name, it.target)

    def _reporting_again(self, name: str, t: _Track, now: float) -> None:
        t.fails, t.state = 0, None
        self._warned.discard(name)
        if self.store.flag(f"offline:{name}") is not None:
            self._recovered(name, agent_reporting=True, now=now)

    def _recovered(self, name: str, agent_reporting: bool, now: float) -> None:
        since = self.store.flag(f"offline:{name}")
        self.store.clear_flag(f"offline:{name}")
        log.info("%s: back after being offline", name)
        self.notifier.recovered(name, now - since if since else None, agent_reporting)
