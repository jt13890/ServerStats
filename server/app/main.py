"""ServerStats web app."""

import asyncio
import hmac
import json
import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from . import config as cfg
from .schema import normalize
from .ssh_poller import AGENT_SCRIPT, SSHPoller, load_or_create_key
from .store import Store

VERSION = "1.0.0"
STATIC = Path(__file__).parent / "static"
INSTALL_SH = AGENT_SCRIPT.parent / "install.sh"
MAX_INGEST_BYTES = 4 * 1024 * 1024

# Paths that must stay reachable without the SSO session. Agents use a
# per-host bearer token instead. Mirror these in Authentik's
# "Unauthenticated Paths". Exact matches only, so path tricks like
# /api/agent/../hosts can't widen the exemption.
PUBLIC_PATHS = frozenset({
    "/api/ingest",
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
    store = Store(cfg.DATA_DIR / "serverstats.db", conf.settings.history_hours)
    key = load_or_create_key(conf.settings.ssh_key)
    poller = SSHPoller(conf.hosts, store, key, conf.settings.max_procs)

    app.state.conf = conf
    app.state.store = store
    app.state.public_key = key.export_public_key("openssh").decode().strip()
    poller.start()

    async def prune_loop():
        while True:
            try:
                store.prune({h.name for h in conf.hosts})
            except Exception:
                log.exception("prune failed")
            await asyncio.sleep(3600)

    pruner = asyncio.create_task(prune_loop())
    log.info("loaded %d host(s): %d agent, %d ssh", len(conf.hosts),
             sum(h.mode == "agent" for h in conf.hosts), sum(h.mode == "ssh" for h in conf.hosts))
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
    out = {k: v for k, v in data.items() if k != "processes"}
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
        server_time=now,
    )
    if with_processes:
        out["processes"] = data.get("processes") or []
    return out


def _host_or_404(request: Request, name: str) -> cfg.Host:
    host = request.app.state.conf.host(name)
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
        "history_hours": settings.history_hours,
    }


@app.get("/api/hosts")
async def list_hosts(request: Request):
    return [_summary(request, h) for h in request.app.state.conf.hosts]


@app.get("/api/hosts/{name}")
async def get_host(request: Request, name: str):
    return _summary(request, _host_or_404(request, name), with_processes=True)


@app.get("/api/hosts/{name}/history")
async def get_history(request: Request, name: str, hours: float = 1.0):
    host = _host_or_404(request, name)
    return request.app.state.store.history(host.name, hours)


# -- agent endpoints (bypass SSO, token-authenticated) ---------------------

def _host_for_token(request: Request, token: str) -> cfg.Host | None:
    match = None
    for h in request.app.state.conf.hosts:
        # Compare against every token so timing doesn't reveal which exist.
        if h.token and hmac.compare_digest(h.token.encode(), token.encode()):
            match = h
    return match


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
    except ValueError:
        raise HTTPException(400, "invalid JSON")
    if not isinstance(data, dict):
        raise HTTPException(400, "unexpected payload")

    request.app.state.store.record(host.name, normalize(data, request.app.state.conf.settings.max_procs))
    return {"ok": True, "host": host.name}


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

@app.get("/")
async def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
