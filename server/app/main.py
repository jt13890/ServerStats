"""ServerStats web app."""

import asyncio
import hashlib
import hmac
import json
import logging
import re
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from . import config as cfg
from .schema import normalize
from .ssh_poller import AGENT_SCRIPT, SSHPoller, load_or_create_key
from .store import Store

VERSION = "1.8.1"
STATIC = Path(__file__).parent / "static"
INSTALL_SH = AGENT_SCRIPT.parent / "install.sh"
MAX_INGEST_BYTES = 4 * 1024 * 1024

# The agent this server hands out: agents update to it when you ask them to.
_agent_code = AGENT_SCRIPT.read_bytes()
AGENT_SHA256 = hashlib.sha256(_agent_code).hexdigest()
AGENT_VERSION = re.search(rb'^VERSION = "([0-9.]+)"', _agent_code, re.M).group(1).decode()
# State-changing UI requests must carry this header. Browsers won't send a
# custom header cross-site without a CORS preflight (which we never allow), so
# another site can't trigger updates through a signed-in user's browser.
ACTION_HEADER = "X-ServerStats-Action"
MAX_UPDATE_OFFERS = 3
MAX_ENROLLED = 1000
LOAD_CACHE_SECONDS = 300
# "Delete history older than ...": the only choices the prune endpoint accepts.
PRUNE_OPTIONS = {30: "1 month", 90: "3 months", 180: "6 months", 365: "1 year", 730: "2 years", 1095: "3 years"}


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _load_join_key(rotate: bool = False) -> str:
    """The shared key agents use to join; generated once, kept in /data."""
    path = cfg.DATA_DIR / "join_key"
    if not rotate and path.exists():
        key = path.read_text().strip()
        if len(key) >= 32:
            return key
    key = secrets.token_urlsafe(32)
    path.write_text(key + "\n")
    path.chmod(0o600)
    return key


def all_hosts(app) -> list[cfg.Host]:
    """Hosts from config.yaml, then hosts that joined with the join key."""
    conf = app.state.conf
    names = {h.name for h in conf.hosts}
    enrolled = [
        cfg.Host(name=name, mode="agent", enrolled=True, token_hash=token_hash)
        for name, token_hash in app.state.store.enrolled_hosts()
        if name not in names  # config.yaml wins on a clash
    ]
    return conf.hosts + enrolled


def _version_tuple(v: str | None) -> tuple:
    try:
        return tuple(int(x) for x in (v or "").split("."))
    except ValueError:
        return ()

# Paths that must stay reachable without the SSO session. Agents use a
# per-host bearer token instead. Mirror these in Authentik's
# "Unauthenticated Paths". Exact matches only, so path tricks like
# /api/agent/../hosts can't widen the exemption.
PUBLIC_PATHS = frozenset({
    "/api/ingest",
    "/api/enroll",
    "/api/agent/serverstats_agent.py",
    "/api/agent/install.sh",
    "/healthz",
})

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("serverstats")
logging.getLogger("asyncssh").setLevel(logging.WARNING)


@asynccontextmanager
async def lifespan(app: FastAPI):
    conf = cfg.load()
    log.info("config: %s", cfg.config_path())
    store = Store(cfg.DATA_DIR / "serverstats.db")
    key = load_or_create_key(conf.settings.ssh_key)
    poller = SSHPoller(conf.hosts, store, key, conf.settings.max_procs)

    app.state.conf = conf
    app.state.store = store
    # host -> times the update was offered; it's offered on each report until
    # the agent runs the new version, at most MAX_UPDATE_OFFERS times.
    app.state.update_pending = {}
    app.state.public_key = key.export_public_key("openssh").decode().strip()
    app.state.join_key = _load_join_key() if conf.settings.enrollment else None
    poller.start()

    async def maintenance():
        # Roll samples up into the 5-minute/hourly tiers; drop what they now cover.
        while True:
            try:
                store.rollup()
                store.compact({h.name for h in all_hosts(app)})
            except Exception:
                log.exception("history maintenance failed")
            await asyncio.sleep(300)

    pruner = asyncio.create_task(maintenance())
    log.info("loaded %d host(s) from config (%d agent, %d ssh), %d joined with the join key",
             len(conf.hosts), sum(h.mode == "agent" for h in conf.hosts),
             sum(h.mode == "ssh" for h in conf.hosts), len(store.enrolled_hosts()))
    yield
    pruner.cancel()
    await poller.stop()


app = FastAPI(title="ServerStats", version=VERSION, lifespan=lifespan, docs_url=None, redoc_url=None)


@app.middleware("http")
async def auth_and_headers(request: Request, call_next):
    settings = request.app.state.conf.settings
    path = request.url.path
    if (
        settings.require_auth_header
        and path not in PUBLIC_PATHS
        and not request.headers.get(settings.auth_header)
    ):
        return PlainTextResponse(
            f"Unauthorized: missing {settings.auth_header} header. Access ServerStats through your "
            "Authentik-protected URL, or set settings.require_auth_header: false for local testing.",
            status_code=401,
        )
    response = await call_next(request)
    if path == "/":
        # Never cache the page: it names the current app.js/style.css versions.
        response.headers["Cache-Control"] = "no-store"
    elif path.startswith("/static/"):
        # Revalidate on every load so an update never leaves a stale UI.
        response.headers["Cache-Control"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    )
    return response


# -- helpers ---------------------------------------------------------------

def _status(host: cfg.Host, st, settings: cfg.Settings, now: float) -> str:
    limit = settings.stale_after
    if host.mode == "ssh":
        limit = max(limit, host.interval * 3)
    elif st.data and st.data.get("interval"):
        limit = max(limit, st.data["interval"] * 3)
    if st.received_at is None:
        return "error" if st.error else "pending"
    if now - st.received_at > limit:
        return "error" if st.error else "offline"
    return "online"


def _summary(request: Request, host: cfg.Host, with_processes: bool = False) -> dict:
    conf = request.app.state.conf
    st = request.app.state.store.state(host.name)
    now = time.time()
    data = st.data or {}
    # Per-process and per-container data is only sent for the host detail view.
    out = {k: v for k, v in data.items() if k not in ("processes", "docker")}
    out.update(
        name=host.name,
        mode=host.mode,
        description=host.description,
        target=f"{host.user}@{host.address}:{host.port}" if host.mode == "ssh" else None,
        status=_status(host, st, conf.settings, now),
        last_seen=st.received_at,
        # Only surface errors that are newer than the last good sample.
        error=st.error if st.error and (st.received_at is None or st.error_at > st.received_at) else None,
        host_key=st.host_key,
        enrolled=host.enrolled,
        server_time=now,
        update_pending=host.name in request.app.state.update_pending,
        docker_pref=request.app.state.store.docker_pref(host.name),
        update_available=host.mode == "agent" and bool(data)
        and _version_tuple(data.get("agent_version")) < _version_tuple(AGENT_VERSION),
    )
    if with_processes:
        out["processes"] = data.get("processes") or []
        out["docker"] = data.get("docker")
    return out


def _host_or_404(request: Request, name: str) -> cfg.Host:
    host = next((h for h in all_hosts(request.app) if h.name == name), None)
    if host is None:
        raise HTTPException(404, "unknown host")
    return host


# -- UI API ----------------------------------------------------------------

@app.get("/api/meta")
async def meta(request: Request):
    settings = request.app.state.conf.settings
    return {
        "version": VERSION,
        "user": request.headers.get(settings.auth_header),
        "ssh_public_key": request.app.state.public_key,
        "stale_after": settings.stale_after,
        "prune_options": [{"days": d, "label": label} for d, label in PRUNE_OPTIONS.items()],
        "agent_version": AGENT_VERSION,
        "join_key": request.app.state.join_key,
    }


@app.get("/api/hosts")
async def list_hosts(request: Request):
    return [_summary(request, h) for h in all_hosts(request.app)]


@app.get("/api/hosts/{name}")
async def get_host(request: Request, name: str):
    return _summary(request, _host_or_404(request, name), with_processes=True)


@app.get("/api/hosts/{name}/history")
async def get_history(request: Request, name: str, hours: float = 1.0):
    host = _host_or_404(request, name)
    return request.app.state.store.history(host.name, hours)


@app.get("/api/hosts/{name}/load")
async def get_load(request: Request, name: str):
    """The past week's load per 5 minutes, its 1% high and busiest times."""
    host = _host_or_404(request, name)
    return request.app.state.store.load_week(host.name)


@app.get("/api/hosts/{name}/moment")
async def get_moment(request: Request, name: str, t: float, span: float = 300):
    """Stats averaged over [t, t+span), plus top processes, stacks and disks
    at the busiest recorded moment in it (null if none was recorded)."""
    host = _host_or_404(request, name)
    return request.app.state.store.moment(host.name, t, span)


@app.get("/api/trends")
async def get_trends(request: Request):
    """Last hour of CPU/memory/disk/storage, plus the 3-day load and 7-day 1% high, for every host."""
    known = {h.name for h in all_hosts(request.app)}
    trends = request.app.state.store.trends()
    trends["hosts"] = {k: v for k, v in trends["hosts"].items() if k in known}
    # Days of data move slowly, so recompute the load scores every few minutes.
    now = time.monotonic()
    cached = getattr(request.app.state, "load_cache", None)
    if cached is None or now - cached[0] > LOAD_CACHE_SECONDS:
        cached = (now, request.app.state.store.load_scores())
        request.app.state.load_cache = cached
    scores = cached[1]
    trends["load"] = {"window_hours": scores["window_hours"], "peak_days": scores["peak_days"],
                      "hosts": {k: v for k, v in scores["hosts"].items() if k in known}}
    return trends


def _require_action_header(request: Request) -> None:
    if request.headers.get(ACTION_HEADER) != "1":
        raise HTTPException(403, f"missing {ACTION_HEADER} header")


def _request_update(request: Request, host: cfg.Host) -> str | None:
    """Queue an update; returns why it can't be done, or None."""
    data = request.app.state.store.state(host.name).data or {}
    if host.mode != "agent":
        return "SSH hosts run the collector installed on them; rerun the installer there to update it"
    if not data:
        return "this agent hasn't reported yet"
    if _version_tuple(data.get("agent_version")) >= _version_tuple(AGENT_VERSION):
        return "already up to date"
    if data.get("update_failed") == AGENT_VERSION:
        return f"{AGENT_VERSION} failed to start on this host before; check its log, then rerun the installer to retry"
    if not data.get("updates"):
        return "this agent doesn't accept remote updates (installed with --no-updates, or older than 1.2.0); rerun the installer on it"
    request.app.state.update_pending[host.name] = 0
    return None


@app.post("/api/hosts/{name}/update")
async def update_host(request: Request, name: str):
    _require_action_header(request)
    reason = _request_update(request, _host_or_404(request, name))
    if reason:
        raise HTTPException(409, reason)
    return {"ok": True, "pending": True}


@app.post("/api/hosts/{name}/docker")
async def set_docker(request: Request, name: str):
    """Turn Docker stats on or off for an agent host; applied on its next report."""
    _require_action_header(request)
    host = _host_or_404(request, name)
    if host.mode != "agent":
        raise HTTPException(409, "SSH hosts report Docker when the installer was run with --docker")
    try:
        enabled = (await request.json())["enabled"]
    except (ValueError, KeyError, TypeError):
        raise HTTPException(400, 'expected {"enabled": true|false}')
    if not isinstance(enabled, bool):
        raise HTTPException(400, 'expected {"enabled": true|false}')
    request.app.state.store.set_docker_pref(host.name, enabled)
    return {"ok": True, "enabled": enabled}


@app.post("/api/update-agents")
async def update_all(request: Request):
    """Queue updates for every outdated agent that accepts them."""
    _require_action_header(request)
    queued, skipped = [], {}
    for host in all_hosts(request.app):
        if host.mode != "agent":
            continue
        reason = _request_update(request, host)
        if reason is None:
            queued.append(host.name)
        elif reason != "already up to date":
            skipped[host.name] = reason
    return {"queued": queued, "skipped": skipped}


# -- agent endpoints (bypass SSO, token-authenticated) ---------------------

def _host_for_token(request: Request, token: str) -> cfg.Host | None:
    match = None
    hashed = _token_hash(token)
    for h in all_hosts(request.app):
        # Compare against every token so timing doesn't reveal which exist.
        if h.token and hmac.compare_digest(h.token.encode(), token.encode()):
            match = h
        if h.token_hash and hmac.compare_digest(h.token_hash, hashed):
            match = h
    return match


@app.post("/api/enroll")
async def enroll(request: Request):
    """An agent joins: join key in, its own name and token out."""
    try:
        body = json.loads(await request.body() or b"{}")
    except ValueError:
        raise HTTPException(400, "invalid JSON")
    join_key = request.app.state.join_key
    key = str(body.get("key") or "")
    if not join_key or not key or not hmac.compare_digest(key.encode(), join_key.encode()):
        await asyncio.sleep(0.5)  # slow down guessing
        raise HTTPException(401, "invalid join key (or enrollment is turned off)")
    name = str(body.get("name") or "").strip()
    if not cfg.NAME_RE.match(name):
        raise HTTPException(400, "name must be 1-64 letters, digits, '.', '_' or '-'")
    if any(h.name == name for h in all_hosts(request.app)):
        raise HTTPException(409, f"a host named {name!r} already exists; pick another name with --name, "
                                 "or remove the old one in the dashboard")
    if len(request.app.state.store.enrolled_hosts()) >= MAX_ENROLLED:
        raise HTTPException(429, "too many enrolled hosts")
    token = secrets.token_hex(32)
    if not request.app.state.store.enroll(name, _token_hash(token), str(body.get("hostname") or "")[:253]):
        raise HTTPException(409, f"a host named {name!r} already exists")
    log.info("host %s joined", name)
    return {"name": name, "token": token}


@app.post("/api/join-key/rotate")
async def rotate_join_key(request: Request):
    """New join key; hosts that already joined keep working."""
    _require_action_header(request)
    if not request.app.state.conf.settings.enrollment:
        raise HTTPException(409, "enrollment is turned off in config.yaml")
    request.app.state.join_key = _load_join_key(rotate=True)
    return {"join_key": request.app.state.join_key}


def _prune_args(request: Request, days, host) -> tuple[int, str | None]:
    if not isinstance(days, int) or isinstance(days, bool) or days not in PRUNE_OPTIONS:
        raise HTTPException(400, f"days must be one of {sorted(PRUNE_OPTIONS)}")
    if host is not None:
        host = _host_or_404(request, str(host)).name
    return days, host


@app.get("/api/prune")
async def prune_preview(request: Request, days: int, host: str | None = None):
    """How much history a prune would delete."""
    days, host = _prune_args(request, days, host)
    return request.app.state.store.prune_preview(days, host)


@app.post("/api/prune")
async def prune(request: Request):
    """Delete history older than one of PRUNE_OPTIONS, for all hosts or one."""
    _require_action_header(request)
    try:
        body = await request.json()
    except ValueError:
        raise HTTPException(400, "expected a JSON body") from None
    if not isinstance(body, dict):
        raise HTTPException(400, "expected a JSON object")
    days, host = _prune_args(request, body.get("days"), body.get("host"))
    result = await asyncio.to_thread(request.app.state.store.prune_older_than, days, host)
    request.app.state.load_cache = None  # the load scores may have lost data
    log.info("pruned history older than %s%s: %d rows, %d bytes freed", PRUNE_OPTIONS[days],
             f" for {host}" if host else "", result["rows"], result["freed"])
    return result


@app.post("/api/hosts/{name}/remove")
async def remove_host(request: Request, name: str):
    """Remove a host that joined with the join key, with all its data."""
    _require_action_header(request)
    host = _host_or_404(request, name)
    if not host.enrolled:
        raise HTTPException(409, "this host is defined in config.yaml; remove it there")
    request.app.state.store.remove_host(host.name)
    request.app.state.update_pending.pop(host.name, None)
    return {"ok": True}


@app.post("/api/ingest")
async def ingest(request: Request):
    auth = request.headers.get("authorization", "")
    token = auth[7:].strip() if auth[:7].lower() == "bearer " else ""
    host = _host_for_token(request, token) if token else None
    if host is None:
        await asyncio.sleep(0.5)  # slow down token guessing a little
        raise HTTPException(401, "invalid token")

    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_INGEST_BYTES:
            raise HTTPException(413, "payload too large")
    try:
        data = json.loads(body)
    except (ValueError, RecursionError):  # RecursionError: absurdly nested JSON
        raise HTTPException(400, "invalid JSON")
    if not isinstance(data, dict):
        raise HTTPException(400, "unexpected payload")

    sample = normalize(data, request.app.state.conf.settings.max_procs)
    request.app.state.store.record(host.name, sample)
    reply = {"ok": True, "host": host.name}
    docker_pref = request.app.state.store.docker_pref(host.name)
    if docker_pref is not None:
        reply["settings"] = {"docker": docker_pref}
    pending = request.app.state.update_pending
    if host.name in pending:
        done = _version_tuple(sample["agent_version"]) >= _version_tuple(AGENT_VERSION)
        failed = sample["update_failed"] == AGENT_VERSION  # agent won't retry it anyway
        if done or failed or not sample["updates"] or pending[host.name] >= MAX_UPDATE_OFFERS:
            pending.pop(host.name)  # done, not possible, or not taking (see update_failed)
        else:
            pending[host.name] += 1
            reply["update"] = {"version": AGENT_VERSION, "sha256": AGENT_SHA256}
    return reply


@app.get("/api/agent/serverstats_agent.py")
async def agent_script():
    return FileResponse(AGENT_SCRIPT, media_type="text/x-python", filename="serverstats_agent.py")


@app.get("/api/agent/install.sh")
async def agent_installer():
    return FileResponse(INSTALL_SH, media_type="text/x-shellscript", filename="install.sh")


@app.get("/healthz")
async def healthz():
    return {"ok": True}


# -- static UI -------------------------------------------------------------

def _index_html() -> str:
    """index.html with the script and stylesheet URLs tagged with a hash of
    their contents, so browsers (and any cache in between) pick up a new
    release instead of running a stale app.js against the new server."""
    html = (STATIC / "index.html").read_text()
    for name in ("app.js", "style.css"):
        digest = hashlib.sha256((STATIC / name).read_bytes()).hexdigest()[:12]
        html = html.replace(f'"/static/{name}"', f'"/static/{name}?v={digest}"')
    return html


INDEX_HTML = _index_html()


@app.get("/")
async def index():
    return HTMLResponse(INDEX_HTML)


app.mount("/static", StaticFiles(directory=STATIC), name="static")
