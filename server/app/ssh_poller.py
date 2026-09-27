"""Pull mode: collect stats from hosts over SSH without ever sending code.

The server never asks a host to run the collector, let alone code of its own.
Each host must pin the ServerStats key to the collector in authorized_keys:

    restrict,command="/usr/local/bin/serverstats-agent --once" ssh-ed25519 AAAA...

sshd then ignores whatever command the client requests and runs exactly that,
so the key (and anyone who steals it from this server) can do nothing else.
The only command we request is a harmless `echo` marker: a correctly locked
host answers with collector JSON; a host without the forced command runs our
echo instead, and we refuse to use it until it's fixed.
"""

import asyncio
import json
import logging
import os
from pathlib import Path

import asyncssh

from .config import DATA_DIR, Host
from .schema import normalize
from .store import Store

log = logging.getLogger("serverstats.ssh")

_default_script = Path(__file__).resolve().parents[2] / "agent" / "serverstats_agent.py"
AGENT_SCRIPT = Path(os.environ.get("SERVERSTATS_AGENT_SCRIPT", "/app/agent/serverstats_agent.py"))
if not AGENT_SCRIPT.exists():
    AGENT_SCRIPT = _default_script  # running from a source checkout

KNOWN_HOSTS = DATA_DIR / "known_hosts.json"
MAX_OUTPUT = 8 * 1024 * 1024
UNRESTRICTED_MARKER = "serverstats-key-not-restricted"
PROBE_COMMAND = f"echo {UNRESTRICTED_MARKER}"
FORCED_COMMAND = "/usr/local/bin/serverstats-agent --once"


def load_or_create_key(path: Path) -> asyncssh.SSHKey:
    if path.exists():
        return asyncssh.read_private_key(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = asyncssh.generate_private_key("ssh-ed25519", comment="serverstats")
    key.write_private_key(path)
    key.write_public_key(path.with_suffix(".pub"))
    os.chmod(path, 0o600)
    log.info("generated new SSH key at %s", path)
    return key


class HostKeyError(Exception):
    pass


class UnrestrictedKeyError(Exception):
    pass


async def _read_limited(stream, limit: int, truncate: bool = False) -> bytes:
    """Read a stream to EOF without ever buffering more than `limit` bytes."""
    buf = bytearray()
    while True:
        chunk = await stream.read(65536)
        if not chunk:
            return bytes(buf)
        room = limit - len(buf)
        if len(chunk) > room:
            if not truncate:
                raise RuntimeError("collector output too large")
            chunk = chunk[:max(room, 0)]
        buf += chunk


class SSHPoller:
    def __init__(self, hosts: list[Host], store: Store, key: asyncssh.SSHKey, max_procs: int):
        self.hosts = hosts
        self.store = store
        self.key = key
        self.max_procs = max_procs
        self._tasks: list[asyncio.Task] = []
        self._known = self._load_known()

    # -- host key trust-on-first-use -------------------------------------
    def _load_known(self) -> dict[str, str]:
        try:
            return json.loads(KNOWN_HOSTS.read_text())
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as e:
            log.error("could not read %s: %s", KNOWN_HOSTS, e)
            return {}

    def _check_host_key(self, host: Host, fingerprint: str) -> None:
        if host.host_key:
            if fingerprint != host.host_key:
                raise HostKeyError(f"host key mismatch: got {fingerprint}, config pins {host.host_key}")
            return
        ident = f"{host.address}:{host.port}"
        known = self._known.get(ident)
        if known is None:
            self._known[ident] = fingerprint
            KNOWN_HOSTS.write_text(json.dumps(self._known, indent=2, sort_keys=True))
            log.info("%s: trusting new host key %s", host.name, fingerprint)
        elif known != fingerprint:
            raise HostKeyError(
                f"HOST KEY CHANGED: got {fingerprint}, expected {known}. If this is expected, "
                f"remove {ident!r} from {KNOWN_HOSTS}."
            )

    # -- polling ----------------------------------------------------------
    def start(self) -> None:
        for host in self.hosts:
            if host.mode == "ssh":
                self._tasks.append(asyncio.create_task(self._run(host), name=f"ssh:{host.name}"))

    async def stop(self) -> None:
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)

    async def _connect(self, host: Host) -> asyncssh.SSHClientConnection:
        conn = await asyncio.wait_for(
            asyncssh.connect(
                host.address,
                port=host.port,
                username=host.user,
                client_keys=[self.key],
                known_hosts=None,  # verified below, before anything is sent
                agent_path=None,
                config=None,
                keepalive_interval=30,
            ),
            timeout=15,
        )
        try:
            server_key = conn.get_server_host_key()
            fingerprint = server_key.get_fingerprint("sha256") if server_key else "unknown"
            self.store.state(host.name).host_key = fingerprint
            self._check_host_key(host, fingerprint)
        except Exception:
            conn.close()
            raise
        return conn

    async def _collect(self, conn: asyncssh.SSHClientConnection, host: Host) -> dict:
        async def run():
            async with conn.create_process(PROBE_COMMAND, stdin=asyncssh.DEVNULL, encoding=None) as proc:
                out, err = await asyncio.gather(
                    _read_limited(proc.stdout, MAX_OUTPUT),
                    _read_limited(proc.stderr, 4096, truncate=True),
                )
                await proc.wait()
                return out, err, proc.exit_status

        out, err, status = await asyncio.wait_for(run(), timeout=45)
        text = out.decode("utf-8", "replace").strip()
        if text == UNRESTRICTED_MARKER:
            raise UnrestrictedKeyError(
                "refusing to use this host: its authorized_keys entry for ServerStats lets the key run any "
                f'command. Prefix it with restrict,command="{FORCED_COMMAND}" (see Add host → SSH).'
            )
        if status is None:
            raise RuntimeError("SSH session closed before the collector finished")
        if status != 0:
            lines = err.decode("utf-8", "replace").strip().splitlines()
            detail = lines[-1] if lines else f"exit status {status}"
            if status == 127:
                detail = f"collector not installed at {FORCED_COMMAND.split()[0]} ({detail})"
            raise RuntimeError(f"collector failed: {detail}")
        data = json.loads(text)
        if not isinstance(data, dict):
            raise RuntimeError("collector returned unexpected output")
        return normalize(data, self.max_procs)

    async def _run(self, host: Host) -> None:
        loop = asyncio.get_running_loop()
        conn: asyncssh.SSHClientConnection | None = None
        failures = 0
        while True:
            started = loop.time()
            try:
                if conn is None:
                    conn = await self._connect(host)
                self.store.record(host.name, await self._collect(conn, host))
                failures = 0
            except asyncio.CancelledError:
                if conn:
                    conn.close()
                raise
            except Exception as e:
                failures += 1
                msg = _describe(e, host)
                if failures == 1 or failures % 20 == 0:
                    log.warning("%s: %s", host.name, msg)
                self.store.record_error(host.name, msg)
                if conn is not None:
                    conn.close()
                    conn = None
            delay = host.interval if failures < 3 else min(host.interval * failures, 300)
            await asyncio.sleep(max(delay - (loop.time() - started), 1))


def _describe(e: Exception, host: Host) -> str:
    if isinstance(e, asyncssh.PermissionDenied):
        return f"SSH authentication failed for {host.user}@{host.address} - is the ServerStats public key in authorized_keys?"
    if isinstance(e, (asyncio.TimeoutError, TimeoutError)):
        return "timed out"
    if isinstance(e, (HostKeyError, UnrestrictedKeyError)):
        return str(e)
    if isinstance(e, asyncssh.Error):
        return f"SSH error: {e.reason}"
    if isinstance(e, OSError):
        return f"connection failed: {e.strerror or e}"
    if isinstance(e, (json.JSONDecodeError, RecursionError)):
        return "collector returned invalid JSON"
    return str(e) or e.__class__.__name__
