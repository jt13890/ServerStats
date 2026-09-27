#!/bin/sh
# Installs the ServerStats agent as a hardened systemd service.
#
#   curl -fsSL https://stats.example.com/api/agent/install.sh \
#     | sudo sh -s -- --url https://stats.example.com --token <TOKEN>
#
# Or from a checkout of the repo:  sudo ./agent/install.sh --url ... --token ...
# Uninstall:                       sudo sh install.sh --uninstall
set -eu

URL=""
TOKEN=""
INTERVAL="15"
CA_FILE=""
UNINSTALL=0

BIN=/usr/local/bin/serverstats-agent
ENV_FILE=/etc/serverstats-agent.env
UNIT=/etc/systemd/system/serverstats-agent.service

die() { echo "error: $*" >&2; exit 1; }
usage() { die "usage: install.sh --url <server url> --token <token> [--interval 15] [--ca-file /path/ca.pem] | --uninstall"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --url) URL="${2:-}"; shift 2 ;;
        --token) TOKEN="${2:-}"; shift 2 ;;
        --interval) INTERVAL="${2:-}"; shift 2 ;;
        --ca-file) CA_FILE="${2:-}"; shift 2 ;;
        --uninstall) UNINSTALL=1; shift ;;
        *) usage ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "must run as root (use sudo)"
command -v systemctl >/dev/null 2>&1 || die "systemd not found; run $BIN manually (see README)"

if [ "$UNINSTALL" -eq 1 ]; then
    systemctl disable --now serverstats-agent 2>/dev/null || true
    rm -f "$BIN" "$ENV_FILE" "$UNIT"
    systemctl daemon-reload
    echo "ServerStats agent removed."
    exit 0
fi

[ -n "$URL" ] && [ -n "$TOKEN" ] || usage
URL="${URL%/}"
command -v python3 >/dev/null 2>&1 || die "python3 is required"

# Use the copy next to this script when run from a checkout, else download.
SRC_DIR=$(dirname "$0" 2>/dev/null || echo .)
if [ -f "$SRC_DIR/serverstats_agent.py" ]; then
    install -m 0755 "$SRC_DIR/serverstats_agent.py" "$BIN"
else
    TMP=$(mktemp)
    trap 'rm -f "$TMP"' EXIT
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL ${CA_FILE:+--cacert "$CA_FILE"} "$URL/api/agent/serverstats_agent.py" -o "$TMP"
    elif command -v wget >/dev/null 2>&1; then
        wget -q ${CA_FILE:+--ca-certificate="$CA_FILE"} -O "$TMP" "$URL/api/agent/serverstats_agent.py"
    else
        die "need curl or wget to download the agent"
    fi
    head -n 1 "$TMP" | grep -q python3 || die "download did not return the agent script (is /api/agent/ excluded from SSO?)"
    install -m 0755 "$TMP" "$BIN"
fi

umask 077
cat > "$ENV_FILE" <<EOF
SERVERSTATS_URL=$URL
SERVERSTATS_TOKEN=$TOKEN
SERVERSTATS_INTERVAL=$INTERVAL
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

# Runs as a throwaway unprivileged user; /proc is world-readable so no
# privileges are needed to read process stats.
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

systemctl daemon-reload
systemctl enable serverstats-agent >/dev/null 2>&1
systemctl restart serverstats-agent
echo "ServerStats agent installed and running. Logs: journalctl -u serverstats-agent -f"
