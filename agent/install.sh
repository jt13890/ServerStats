#!/bin/sh
# Installs the ServerStats collector on this host, in one of two modes.
#
# Push agent (a hardened systemd service that reports to the server):
#   curl -fsSL https://stats.example.com/api/agent/install.sh \
#     | sudo sh -s -- --url https://stats.example.com --token <TOKEN>
#
# SSH pull (the server connects in; its key may only run the collector):
#   curl -fsSL https://stats.example.com/api/agent/install.sh \
#     | sudo sh -s -- --url https://stats.example.com --ssh-key 'ssh-ed25519 AAAA... serverstats'
#
# Options:
#   --docker          also report Docker containers/compose stacks. This gives
#                     the collector read access to the Docker socket (docker
#                     group), which is root-equivalent: only enable it if you
#                     trust this setup. The collector only sends fixed GETs.
#   --ssh-from ADDR   SSH mode: only accept the key from this address/CIDR
#   --interval N      agent mode: seconds between reports (default 15)
#   --ca-file PATH    CA bundle for a server with a private certificate
#   --uninstall       remove the service, collector and SSH key entry
#
# Run from a checkout of the repo (sudo ./agent/install.sh ...) to install the
# copy next to this script instead of downloading it.
set -eu

URL=""
TOKEN=""
SSH_KEY=""
SSH_FROM=""
DOCKER=0
INTERVAL="15"
CA_FILE=""
UNINSTALL=0

BIN=/usr/local/bin/serverstats-agent
ENV_FILE=/etc/serverstats-agent.env
UNIT=/etc/systemd/system/serverstats-agent.service
DROPIN_DIR=/etc/systemd/system/serverstats-agent.service.d
SSH_USER=serverstats
FORCED='command="/usr/local/bin/serverstats-agent --once"'

die() { echo "error: $*" >&2; exit 1; }
usage() { die "usage: install.sh --url <server url> (--token <token> | --ssh-key '<public key>') [--docker] [--ssh-from addr] [--interval 15] [--ca-file path] | --uninstall"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --url) URL="${2:-}"; shift 2 ;;
        --token) TOKEN="${2:-}"; shift 2 ;;
        --ssh-key) SSH_KEY="${2:-}"; shift 2 ;;
        --ssh-from) SSH_FROM="${2:-}"; shift 2 ;;
        --docker) DOCKER=1; shift ;;
        --interval) INTERVAL="${2:-}"; shift 2 ;;
        --ca-file) CA_FILE="${2:-}"; shift 2 ;;
        --uninstall) UNINSTALL=1; shift ;;
        *) usage ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "must run as root (use sudo)"

ssh_home() { getent passwd "$SSH_USER" | cut -d: -f6; }

if [ "$UNINSTALL" -eq 1 ]; then
    if command -v systemctl >/dev/null 2>&1; then
        systemctl disable --now serverstats-agent 2>/dev/null || true
    fi
    rm -rf "$BIN" "$ENV_FILE" "$UNIT" "$DROPIN_DIR"
    command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload
    if HOME_DIR=$(ssh_home) && [ -f "$HOME_DIR/.ssh/authorized_keys" ]; then
        grep -v 'serverstats-agent --once' "$HOME_DIR/.ssh/authorized_keys" > "$HOME_DIR/.ssh/authorized_keys.tmp" || true
        mv "$HOME_DIR/.ssh/authorized_keys.tmp" "$HOME_DIR/.ssh/authorized_keys"
        echo "Removed the ServerStats key from $HOME_DIR/.ssh/authorized_keys (user $SSH_USER kept)."
    fi
    echo "ServerStats collector removed."
    exit 0
fi

if [ -n "$TOKEN" ] && [ -n "$SSH_KEY" ]; then die "use either --token (agent) or --ssh-key (SSH), not both"; fi
[ -n "$TOKEN" ] || [ -n "$SSH_KEY" ] || usage
URL="${URL%/}"
command -v python3 >/dev/null 2>&1 || die "python3 is required"

# -- install the collector ---------------------------------------------------
SRC_DIR=$(dirname "$0" 2>/dev/null || echo .)
if [ -f "$SRC_DIR/serverstats_agent.py" ]; then
    install -m 0755 -o root -g root "$SRC_DIR/serverstats_agent.py" "$BIN"
else
    [ -n "$URL" ] || die "--url is required to download the collector"
    TMP=$(mktemp)
    trap 'rm -f "$TMP"' EXIT
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --max-redirs 0 ${CA_FILE:+--cacert "$CA_FILE"} "$URL/api/agent/serverstats_agent.py" -o "$TMP"
    elif command -v wget >/dev/null 2>&1; then
        wget -q --max-redirect=0 ${CA_FILE:+--ca-certificate="$CA_FILE"} -O "$TMP" "$URL/api/agent/serverstats_agent.py"
    else
        die "need curl or wget to download the collector"
    fi
    head -n 1 "$TMP" | grep -q python3 || die "download did not return the collector (is /api/agent/ excluded from SSO?)"
    install -m 0755 -o root -g root "$TMP" "$BIN"
fi

# -- SSH pull mode -------------------------------------------------------------
if [ -n "$SSH_KEY" ]; then
    # One line, a known key type, and no quotes that could smuggle in options.
    case "$SSH_KEY" in
        *'"'*|*"'"*|*'
'*) die "--ssh-key contains unexpected characters" ;;
        ssh-ed25519\ *|ssh-rsa\ *|ecdsa-sha2-*\ *) ;;
        *) die "--ssh-key must be an OpenSSH public key (ssh-ed25519 AAAA...)" ;;
    esac
    OPTS="restrict,$FORCED"
    if [ -n "$SSH_FROM" ]; then
        case "$SSH_FROM" in
            *[!0-9A-Fa-f.:/,*]*) die "--ssh-from must be an IP address or CIDR" ;;
        esac
        OPTS="restrict,from=\"$SSH_FROM\",$FORCED"
    fi

    if ! getent passwd "$SSH_USER" >/dev/null; then
        useradd --system --create-home --shell /bin/sh "$SSH_USER" 2>/dev/null \
            || adduser -S -D -h "/home/$SSH_USER" -s /bin/sh "$SSH_USER" \
            || die "could not create user $SSH_USER"
    fi
    # No usable password, but not "locked" either: sshd refuses key logins to
    # locked (!) accounts when it isn't using PAM.
    if getent shadow "$SSH_USER" 2>/dev/null | cut -d: -f2 | grep -q '^!'; then
        usermod -p '*' "$SSH_USER" 2>/dev/null || passwd -u "$SSH_USER" >/dev/null 2>&1 || true
    fi
    HOME_DIR=$(ssh_home)
    GROUP=$(id -gn "$SSH_USER")
    install -d -m 700 -o "$SSH_USER" -g "$GROUP" "$HOME_DIR/.ssh"
    AK="$HOME_DIR/.ssh/authorized_keys"
    KEY_BODY=$(echo "$SSH_KEY" | awk '{print $2}')
    touch "$AK"
    # Replace any earlier entry for this key, whatever options it had.
    grep -vF "$KEY_BODY" "$AK" > "$AK.tmp" || true
    echo "$OPTS $SSH_KEY" >> "$AK.tmp"
    mv "$AK.tmp" "$AK"
    chown "$SSH_USER:$GROUP" "$AK"
    chmod 600 "$AK"

    if [ "$DOCKER" -eq 1 ]; then
        getent group docker >/dev/null || die "--docker: no docker group on this host"
        usermod -aG docker "$SSH_USER" 2>/dev/null || addgroup "$SSH_USER" docker
    fi
    echo "Ready for SSH collection: $SSH_USER's key can only run '$BIN --once'."
    echo "Add this host to ServerStats' config.yaml with mode: ssh and user: $SSH_USER."
    exit 0
fi

# -- push agent mode -----------------------------------------------------------
command -v systemctl >/dev/null 2>&1 || die "systemd not found; run $BIN manually (see README)"
[ -n "$URL" ] || die "--url is required for agent mode"

umask 077
cat > "$ENV_FILE" <<EOF
SERVERSTATS_URL=$URL
SERVERSTATS_TOKEN=$TOKEN
SERVERSTATS_INTERVAL=$INTERVAL
SERVERSTATS_DOCKER=$DOCKER
EOF
[ -n "$CA_FILE" ] && echo "SERVERSTATS_CA_FILE=$CA_FILE" >> "$ENV_FILE"
chmod 0600 "$ENV_FILE"
umask 022

cat > "$UNIT" <<'EOF'
[Unit]
Description=ServerStats agent
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=/etc/serverstats-agent.env
ExecStart=/usr/local/bin/serverstats-agent
Restart=always
RestartSec=10

# Runs as a throwaway unprivileged user; /proc and cgroup stats are
# world-readable so no privileges are needed to read them.
DynamicUser=yes
NoNewPrivileges=yes
CapabilityBoundingSet=
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF

rm -rf "$DROPIN_DIR"
if [ "$DOCKER" -eq 1 ]; then
    getent group docker >/dev/null || die "--docker: no docker group on this host"
    mkdir -p "$DROPIN_DIR"
    cat > "$DROPIN_DIR/docker.conf" <<'EOF'
# Read access to the Docker socket for the Docker/compose section.
[Service]
SupplementaryGroups=docker
EOF
fi

systemctl daemon-reload
systemctl enable serverstats-agent >/dev/null 2>&1
systemctl restart serverstats-agent
echo "ServerStats agent installed and running. Logs: journalctl -u serverstats-agent -f"
