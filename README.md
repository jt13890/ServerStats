# ServerStats

A small, self-hosted dashboard for the Linux machines you run. It tracks:

- **CPU**: total utilization, per-core count, load average
- **RAM**: used/available memory and swap
- **Disk utilization**: per-device busy %, read/write throughput
- **Storage space**: used/free per filesystem, tracked over time so you can see disks filling up
- **Network** throughput, **load average**, **task counts** and **processes** (sortable/filterable, like `top` for your whole fleet)
- **Docker** (optional): CPU, memory, disk I/O, network and disk space per compose stack and container

History is kept for 400 days by default, so the charts go from the last hour out to a full year. Full-detail samples are kept for 3 days, 5-minute averages for 90 days, and hourly averages after that, so a year of history is only a few MB per host. It runs in one Docker container with SQLite, has no build step, and is designed to sit behind **Authentik**.

## How hosts are monitored: agent or SSH

Both modes run the same collector (`agent/serverstats_agent.py`). It uses only the Python standard library, needs Python 3.6+, and reads everything from `/proc`. You can mix both modes in one fleet.

| | **Push agent** (recommended) | **SSH pull** |
|---|---|---|
| Install on host | One Python file plus a systemd or OpenRC service (a one-line installer) | One Python file plus a locked-down `authorized_keys` entry (a one-line installer) |
| Network | Host makes outbound HTTPS to ServerStats. Works behind NAT, and the host needs no open ports | ServerStats must reach the host's SSH port |
| If the ServerStats server is compromised | The attacker can push agent code to hosts that accept [remote updates](#updating-agents) (the default), running as the agent's user. Install with `--no-updates` and the server only receives data | The attacker can make hosts run the collector, and nothing else: the key is locked to it by a forced command |
| Runs as | Unprivileged user: a throwaway `DynamicUser` in a locked-down systemd sandbox, or `serverstats-agent` under OpenRC | Unprivileged `serverstats` user |
| Accuracy | CPU and disk rates are averaged over the whole report interval | 1-second sample at each poll |

**Why agents are the default:** a monitoring server that holds SSH keys to every machine is a juicy target, and this one is internet-facing. With the push model, the server never has credentials for your hosts. Each host only has a token that lets it submit its own stats. The one thing a host trusts the server with is remote updates, and you can turn those off per host. SSH mode is handy when a host can't reach the server, or you'd rather not run a service on it.

## Quick start

```sh
git clone <this repo> serverstats && cd serverstats
mkdir -p config
cp config.example.yaml config/config.yaml   # optional: settings, SSH hosts, hosts with fixed tokens
docker compose up -d --build
```

The app listens on `127.0.0.1:8080`, so it's not reachable from other machines until you put a reverse proxy in front (see [Putting it behind Authentik](#putting-it-behind-authentik)). By default it **rejects UI and API requests that don't carry Authentik's `X-authentik-username` header** (`require_auth_header: true`). For a quick local test without a proxy, set that to `false` temporarily.

Agents join by themselves (see [Adding hosts](#adding-hosts)), so you only need to touch `config/config.yaml` for settings and SSH hosts. Restart the container (`docker compose restart`) after editing it. Without a config file, ServerStats starts with the defaults.

**Trying it on your LAN before Authentik is set up:** create a `.env` file next to `docker-compose.yml` containing `SERVERSTATS_BIND=0.0.0.0` (and `SERVERSTATS_PORT=…` if 8080 is taken), and set `require_auth_header: false` in the config. Anyone on your network can then view the dashboard, so undo both once Authentik is in front.

## Adding hosts

The easiest way is the **Add host** button in the UI. It generates a token and gives you ready-to-paste config and commands. Here is what it does, for reference:

### Agent

On the host (needs systemd or OpenRC, `python3`, and `curl` or `wget`), run the command from **Add host** in the UI. It looks like this:
```sh
curl -fsSL https://stats.example.com/api/agent/install.sh \
  | sudo sh -s -- --url https://stats.example.com --join <join key> [--name nas]
```
The host joins with the server's **join key** and appears on the dashboard within seconds. No config edit or restart is needed.
- **Tokens:** the server gives the host its own token, and stores only a hash of it.
- **Naming:** the host uses its hostname unless you pass `--name`. Names must be unique, so a host can't take over another's name.
- **Reinstalling** keeps the token the host already has.
- **The join key** is only good for adding hosts, but anyone with it can add one, so treat it like a password. **Add host → Make a new join key** replaces it; hosts that already joined keep working.
- **Removing:** enrolled hosts have a **Remove host** button, which deletes them and their history.
- **Turning joining off:** set `enrollment: false` in the config.

Alternatively, list the host in `config/config.yaml` yourself (`name`, `mode: agent`, and a token from `openssl rand -hex 32`), restart ServerStats, and install with `--token <the token>` instead of `--join`.

   This installs `/usr/local/bin/serverstats-agent`, writes the token to `/etc/serverstats-agent.env`, and starts the service:
   - **systemd:** a hardened `serverstats-agent.service` running as a throwaway user. Logs: `journalctl -u serverstats-agent -f`.
   - **OpenRC** (Alpine, postmarketOS, Gentoo): an `/etc/init.d/serverstats-agent` service supervised by `supervise-daemon`, running as a dedicated unprivileged `serverstats-agent` user. The agent reads the token from the env file (readable only by root and that user), so it never appears in `ps`. Logs: `/var/log/serverstats-agent.log`.

   To remove it, run the same script with `--uninstall`.

   Add `--docker` for the Docker section (see below), and `--no-updates` to refuse [remote updates](#updating-agents). Other installer options: `--interval 15` sets seconds between reports, and `--ca-file /path/ca.pem` is for a private CA. Longer intervals are fine: the agent tells the server its interval, so a host is only marked offline after it misses about three reports.

   You can also run the installer from a checkout of this repo (`sudo ./agent/install.sh --url … --token …`). With neither systemd nor OpenRC (e.g. inside a container), run the agent under your init system of choice: `/usr/local/bin/serverstats-agent --env-file /etc/serverstats-agent.env`.

The agent identifies itself only by its token. A host can't report as another host.

### Updating agents

When the server has a newer agent than a host is running, the host's page shows **Update agent**, and the overview shows **Update agents (N)** for all of them. Updating the server (`git pull` plus `docker compose up -d --build`) is what makes a new agent version available.

- **How it works:** after you click, the server answers the host's next report with the new version and its SHA-256 hash. The agent downloads the code from the server, checks the hash, saves it in its own state directory (`/var/lib/serverstats-agent`) and restarts into it. It keeps running as the same unprivileged user.
- **Safety net:** the installed copy stays untouched. If an update fails to start three times in a row, the agent goes back to the installed version, won't retry that version, and the host page tells you it failed. Rerun the installer to retry.
- **Only agents from 1.2.0 on can be updated this way.** Older agents, and SSH hosts, need the installer rerun once.
- **What you're trusting:** an agent that accepts updates runs whatever code the server gives it, so anyone who takes over the ServerStats server can run code on those hosts. On hosts installed with `--docker` that includes the Docker socket, which is root-equivalent. Install with `--no-updates` on hosts where that's not acceptable; the dashboard then says the host doesn't accept remote updates.

### SSH

1. On the host, run the installer in SSH mode. **Add host → SSH** in the UI fills in the server's public key for you:
   ```sh
   curl -fsSL https://stats.example.com/api/agent/install.sh \
     | sudo sh -s -- --url https://stats.example.com --ssh-key 'ssh-ed25519 AAAA… serverstats'
   ```
   This installs the collector as `/usr/local/bin/serverstats-agent`, creates a `serverstats` user, and authorizes the key with:
   ```
   restrict,command="/usr/local/bin/serverstats-agent --once" ssh-ed25519 AAAA… serverstats
   ```
   Add `--ssh-from 10.0.0.5` to accept the key only from ServerStats' address. To set a host up by hand, write that same line yourself. The server's key is also in `/data/ssh/id_ed25519.pub` inside the container.
2. Add the host to `config/config.yaml` and restart ServerStats:
   ```yaml
     - name: pi
       mode: ssh
       address: 192.168.1.20
       user: serverstats
       # port: 22
       # interval: 15
   ```

**The key can only ever run the collector.** With `command=` in `authorized_keys`, sshd ignores whatever command the client asks for and runs the collector instead. `restrict` blocks port forwarding, SFTP, PTYs and `~/.ssh/rc`. ServerStats never sends code or asks for a shell: the only command it requests is a harmless `echo` marker. A correctly set-up host runs the collector instead and returns stats. A host whose key isn't locked down would run the `echo`, and ServerStats refuses to use it and shows how to fix it. So even someone who steals the server's key can't do anything on your hosts except read stats.

The host key is **trusted on first use** and pinned in `/data/known_hosts.json`. If it later changes, ServerStats refuses to connect and shows an error on the dashboard. You can pin a key up front with `host_key: "SHA256:…"` (get it with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`).

### Docker and compose stacks (optional)

Add `--docker` to either installer command to get a **Docker** section on the host's page. It shows how much of the host's CPU, memory, disk I/O, network and disk space each compose stack uses, and you can expand each stack into its containers.

- **Usage comes from the kernel.** CPU, memory and I/O are read from each container's cgroup, the same numbers `docker stats` uses, without its per-container delay.
- **Disk space** is each container's writable layer plus its volumes (bind mounts aren't counted). The push agent measures it every 15 minutes; it isn't available in SSH mode.
- **Grouping into stacks needs the Docker API.** Stacks are identified by the `com.docker.compose.project` label, which only the Docker API has. So `--docker` adds the collector to the `docker` group, and **access to the Docker socket is root-equivalent on that host**. The collector only ever sends three fixed, read-only requests (`GET /containers/json`, `GET /containers/<id>/json`, `GET /system/df`). It never acts on anything the server sends, but it's still your call whether that access is acceptable. Without `--docker`, nothing changes.
- Per-container disk I/O needs cgroup v2 (the default on current distros). On cgroup v1 hosts it shows 0, as it does in `docker stats`.

## Putting it behind Authentik

The UI and its API sit behind Authentik. These five exact paths **must bypass** Authentik, because agents authenticate with their own per-host tokens or the join key:

| Path | Purpose |
|---|---|
| `/api/ingest` | agents POST their stats here (bearer token required) |
| `/api/enroll` | new agents join here (join key required) |
| `/api/agent/serverstats_agent.py` | agent download, used by the installer |
| `/api/agent/install.sh` | installer download |
| `/healthz` | health check |

If your agents can reach ServerStats on your LAN, you can also point them at an internal address instead. Nothing else changes.

### 1. Authentik

1. **Applications → Providers → Create → Proxy Provider**
   - Mode: **Forward auth (single application)**. **Proxy** mode also works if you want Authentik's outpost to be the reverse proxy.
   - External host: `https://stats.example.com`
   - Under *Advanced protocol settings → Unauthenticated Paths*, add:
     ```
     ^/api/ingest$
     ^/api/enroll$
     ^/api/agent/serverstats_agent\.py$
     ^/api/agent/install\.sh$
     ^/healthz$
     ```
2. **Applications → Create**: name it ServerStats, select the provider, and optionally restrict it to a group via *Policy / Group bindings*.
3. **Outposts**: add the application to your outpost (e.g. the embedded outpost).

Authentik passes the signed-in user in the `X-authentik-username` header. ServerStats shows it in the top bar and rejects UI/API requests without it (`require_auth_header`).

### 2. Reverse proxy

<details>
<summary><b>Traefik</b> (Docker labels)</summary>

Attach ServerStats to Traefik's network instead of publishing a port:

```yaml
services:
  serverstats:
    build: .
    restart: unless-stopped
    volumes:
      - ./config:/config:ro
      - serverstats-data:/data
    networks: [proxy]
    labels:
      - traefik.enable=true
      - traefik.http.routers.serverstats.rule=Host(`stats.example.com`)
      - traefik.http.routers.serverstats.entrypoints=websecure
      - traefik.http.routers.serverstats.tls.certresolver=letsencrypt
      - traefik.http.routers.serverstats.middlewares=authentik@docker
      - traefik.http.services.serverstats.loadbalancer.server.port=8080
networks:
  proxy:
    external: true
volumes:
  serverstats-data:
```

If you don't already have an `authentik` forward-auth middleware, define one (e.g. on the Authentik server container):

```yaml
      - traefik.http.middlewares.authentik.forwardauth.address=http://authentik-server:9000/outpost.goauthentik.io/auth/traefik
      - traefik.http.middlewares.authentik.forwardauth.trustForwardHeader=true
      - traefik.http.middlewares.authentik.forwardauth.authResponseHeaders=X-authentik-username,X-authentik-groups,X-authentik-email,X-authentik-name,X-authentik-uid
```

You also need a router for `/outpost.goauthentik.io/` on the same host pointing to Authentik, as described in [Authentik's Traefik docs](https://docs.goauthentik.io/docs/add-secure-apps/providers/proxy/server_traefik).
</details>

<details>
<summary><b>nginx</b></summary>

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name stats.example.com;
    # ssl_certificate / ssl_certificate_key ...

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        auth_request /outpost.goauthentik.io/auth/nginx;
        error_page 401 = @goauthentik_proxy_signin;
        auth_request_set $auth_cookie $upstream_http_set_cookie;
        add_header Set-Cookie $auth_cookie;
        auth_request_set $authentik_username $upstream_http_x_authentik_username;
        proxy_set_header X-authentik-username $authentik_username;
    }

    location /outpost.goauthentik.io {
        proxy_pass http://authentik-server:9000/outpost.goauthentik.io;
        proxy_set_header Host $host;
        proxy_set_header X-Original-URL $scheme://$http_host$request_uri;
        add_header Set-Cookie $auth_cookie;
        auth_request_set $auth_cookie $upstream_http_set_cookie;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
    }

    location @goauthentik_proxy_signin {
        internal;
        add_header Set-Cookie $auth_cookie;
        return 302 /outpost.goauthentik.io/start?rd=$scheme://$http_host$request_uri;
    }
}
```
</details>

For Caddy, Nginx Proxy Manager, and others, follow [Authentik's proxy provider docs](https://docs.goauthentik.io/docs/add-secure-apps/providers/proxy/). ServerStats needs nothing special beyond the unauthenticated paths above.

## Security notes

**Where code can come from:**
- **Remote updates are the one deliberate exception.** An agent that accepts them (the default) runs agent code the server provides when you click Update, so the server is trusted with code on those hosts. Install with `--no-updates` to opt a host out; see [Updating agents](#updating-agents). Update requests need the SSO header and a custom request header, so another site can't trigger one through your browser.
- Apart from updates, the **agent** only sends data. It doesn't interpret anything else the server returns, and it refuses HTTP redirects, so the token can't be bounced elsewhere.
- In **SSH mode** the key is locked to the collector (see above), and ServerStats refuses hosts where it isn't.
- The **server** never executes, evaluates or unpickles anything. The config is read with `yaml.safe_load`, SQL is parameterized, and host data is validated against a strict schema. A test checks the server code for exec paths.
- **Install time is the exception.** `curl … | sudo sh` trusts whoever serves the installer at that moment. The files come from the read-only container image, but for the strongest guarantee, install from a git checkout you've reviewed (`sudo ./agent/install.sh …`).

Also:

- **Don't expose port 8080 directly.** The SSO check trusts the `X-authentik-username` header, which is only meaningful when every request comes through your proxy. The compose file binds to `127.0.0.1`; with Traefik, use a Docker network and no published port.
- Agent tokens are compared in constant time. Ingest payloads are capped at 4 MiB and normalized to a strict schema. Everything from hosts (process names, command lines) is rendered as text, never HTML. The UI sends a strict Content-Security-Policy.
- Apart from the update buttons, the UI is read-only.
- The container runs as a non-root user with a read-only root filesystem and all capabilities dropped. Persistent state lives in the `/data` volume: the SQLite DB, the SSH key, and pinned host keys.

## Configuration

See [`config.example.yaml`](config.example.yaml) for all options: offline threshold, history retention (`retention_days`, default 400), SSH poll interval, process cap, and auth header.

| Env var | Default | |
|---|---|---|
| `SERVERSTATS_CONFIG` | `/config/config.yaml` | config file path |
| `SERVERSTATS_DATA` | `/data` | SQLite DB, SSH key, `known_hosts.json` |

If you bind-mount a host directory as `/data` instead of using the named volume, make it writable by UID `10001`.

## Development

```sh
cd server
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
pytest

# run locally without a proxy
mkdir -p ../data
printf 'settings:\n  require_auth_header: false\nhosts: []\n' > ../data/config.yaml
SERVERSTATS_CONFIG=../data/config.yaml SERVERSTATS_DATA=../data uvicorn app.main:app --reload --port 8080
```

`python3 agent/serverstats_agent.py --once` prints a single sample, which is handy for checking what a host reports.

Layout:

```
agent/serverstats_agent.py   collector + push agent (stdlib only)
agent/install.sh             installer: systemd or OpenRC agent service, or locked SSH access
server/app/main.py           FastAPI app: UI API, agent ingest, auth gate
server/app/ssh_poller.py     SSH pull mode (asyncssh): forced-command check, host key pinning
server/app/store.py          latest samples + tiered SQLite history (raw / 5 min / 1 h)
server/app/schema.py         payload normalization
server/app/static/           the UI (plain HTML/CSS/JS, no build step)
```
