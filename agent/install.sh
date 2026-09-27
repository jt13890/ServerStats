#!/bin/sh
# Installs the ServerStats collector on this host, in one of two modes.
#
# Push agent (a service that reports to the server; systemd or OpenRC). Join
# with the server's join key (shown under "Add host"), no config edit needed:
#   curl -fsSL https://stats.example.com/api/agent/install.sh \
#     | sudo sh -s -- --url https://stats.example.com --join <JOIN KEY> [--name NAME]
# ...or with a token you put in config.yaml yourself: --token <TOKEN>
#
# SSH pull (the server connects in; its key may only run the collector):
#   curl -fsSL https://stats.example.com/api/agent/install.sh \
#     | sudo sh -s -- --url https://stats.example.com --ssh-key 'ssh-ed25519 AAAA... serverstats'
#
# Options:
#   --name NAME       with --join: the name to show (default: this hostname)
#   --docker          also report Docker containers/compose stacks. This gives
#                     the collector read access to the Docker socket (docker
#                     group), which is root-equivalent: only enable it if you
#                     trust this setup. The collector only sends fixed GETs.
#   --ssh-from ADDR   SSH mode: only accept the key from this address/CIDR
#   --no-updates      agent mode: refuse remote updates from the server (by
#                     default the "Update agent" button in the UI can replace
#                     this agent's code with the version the server serves)
#   --interval N      agent mode: seconds between reports (default 15)
#   --ca-file PATH    CA bundle for a server with a private certificate
#   --uninstall       remove the service, collector and SSH key entry
#
# Works on systemd distros and on OpenRC ones (Alpine, postmarketOS).
# Run from a checkout of the repo (sudo ./agent/install.sh ...) to install the
# copy next to this script instead of downloading it.
set -eu

URL=""
TOKEN=""
JOIN=""
NAME=""
SSH_KEY=""
SSH_FROM=""
DOCKER=0
INTERVAL="15"
CA_FILE=""
UNINSTALL=0
UPDATES=1

BIN=/usr/local/bin/serverstats-agent
ENV_FILE=/etc/serverstats-agent.env
UNIT=/etc/systemd/system/serverstats-agent.service
DROPIN_DIR=/etc/systemd/system/serverstats-agent.service.d
INITD=/etc/init.d/serverstats-agent
OPENRC_LOG=/var/log/serverstats-agent.log
AGENT_USER=serverstats-agent   # OpenRC only; systemd uses a DynamicUser
# Where remote updates are stored (systemd: StateDirectory, maybe under private/).
STATE_DIRS="/var/lib/serverstats-agent /var/lib/private/serverstats-agent"
SSH_USER=serverstats
FORCED='command="/usr/local/bin/serverstats-agent --once"'

die() { echo "error: $*" >&2; exit 1; }
usage() { die "usage: install.sh --url <server url> (--join <join key> [--name name] | --token <token> | --ssh-key '<public key>') [--docker] [--no-updates] [--ssh-from addr] [--interval 15] [--ca-file path] | --uninstall"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --url) URL="${2:-}"; shift 2 ;;
        --token) TOKEN="${2:-}"; shift 2 ;;
        --join) JOIN="${2:-}"; shift 2 ;;
        --name) NAME="${2:-}"; shift 2 ;;
        --ssh-key) SSH_KEY="${2:-}"; shift 2 ;;
        --ssh-from) SSH_FROM="${2:-}"; shift 2 ;;
        --docker) DOCKER=1; shift ;;
        --no-updates) UPDATES=0; shift ;;
        --interval) INTERVAL="${2:-}"; shift 2 ;;
        --ca-file) CA_FILE="${2:-}"; shift 2 ;;
        --uninstall) UNINSTALL=1; shift ;;
        *) usage ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "must run as root (use sudo)"

# -- helpers that work with both shadow-utils and busybox (Alpine) --------------
user_exists() { grep -q "^$1:" /etc/passwd; }
user_home() { awk -F: -v u="$1" '$1 == u { print $6 }' /etc/passwd; }
group_exists() { grep -q "^$1:" /etc/group; }
add_to_group() { usermod -aG "$2" "$1" 2>/dev/null || addgroup "$1" "$2"; }
nologin_shell() { command -v nologin 2>/dev/null || echo /bin/false; }

if [ -d /run/systemd/system ]; then
    INIT=systemd
elif command -v openrc-run >/dev/null 2>&1 || [ -x /sbin/openrc-run ]; then
    INIT=openrc
else
    INIT=none
fi

if [ "$UNINSTALL" -eq 1 ]; then
    if [ "$INIT" = systemd ]; then
        systemctl disable --now serverstats-agent 2>/dev/null || true
    fi
    if [ -f "$INITD" ]; then
        rc-service serverstats-agent stop 2>/dev/null || true
        rc-update del serverstats-agent default 2>/dev/null || true
    fi
    rm -rf "$BIN" "$ENV_FILE" "$UNIT" "$DROPIN_DIR" "$INITD" $STATE_DIRS
    [ "$INIT" = systemd ] && systemctl daemon-reload
    if user_exists "$SSH_USER"; then
        AK="$(user_home "$SSH_USER")/.ssh/authorized_keys"
        if [ -f "$AK" ]; then
            grep -v 'serverstats-agent --once' "$AK" > "$AK.tmp" || true
            mv "$AK.tmp" "$AK"
            echo "Removed the ServerStats key from $AK (user $SSH_USER kept)."
        fi
    fi
    echo "ServerStats collector removed."
    exit 0
fi

MODES=0
for v in "$TOKEN" "$JOIN" "$SSH_KEY"; do [ -n "$v" ] && MODES=$((MODES + 1)); done
[ "$MODES" -eq 1 ] || { [ "$MODES" -eq 0 ] && usage; die "use one of --join, --token or --ssh-key"; }
URL="${URL%/}"
command -v python3 >/dev/null 2>&1 || die "python3 is required (e.g. apt install python3 / apk add python3)"
if [ "$DOCKER" -eq 1 ]; then group_exists docker || die "--docker: no docker group on this host"; fi

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
        if wget --help 2>&1 | grep -q -- --max-redirect; then  # GNU wget
            wget -q --max-redirect=0 ${CA_FILE:+--ca-certificate="$CA_FILE"} -O "$TMP" "$URL/api/agent/serverstats_agent.py"
        else  # busybox wget: no redirect or CA options
            [ -z "$CA_FILE" ] || die "--ca-file needs curl or GNU wget"
            wget -q -O "$TMP" "$URL/api/agent/serverstats_agent.py"
        fi
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

    if ! user_exists "$SSH_USER"; then
        useradd --system --create-home --shell /bin/sh "$SSH_USER" 2>/dev/null \
            || adduser -S -D -h "/home/$SSH_USER" -s /bin/sh "$SSH_USER" \
            || die "could not create user $SSH_USER"
    fi
    # No usable password, but not "locked" (!) either: sshd refuses key logins
    # to locked accounts when it isn't using PAM (e.g. Alpine, postmarketOS).
    if awk -F: -v u="$SSH_USER" '$1 == u && $2 ~ /^!/ { found = 1 } END { exit !found }' /etc/shadow 2>/dev/null; then
        echo "$SSH_USER:*" | chpasswd -e 2>/dev/null || usermod -p '*' "$SSH_USER" 2>/dev/null \
            || die "could not unlock $SSH_USER for key logins; set its password field in /etc/shadow to *"
    fi
    HOME_DIR=$(user_home "$SSH_USER")
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

    [ "$DOCKER" -eq 1 ] && add_to_group "$SSH_USER" docker
    echo "Ready for SSH collection: $SSH_USER's key can only run '$BIN --once'."
    echo "Add this host to ServerStats' config.yaml with mode: ssh and user: $SSH_USER."
    exit 0
fi

# -- push agent mode -----------------------------------------------------------
[ -n "$URL" ] || die "--url is required for agent mode"
# A fresh install replaces any remotely-updated copy.
for d in $STATE_DIRS; do rm -f "$d/serverstats_agent.py" "$d/serverstats_agent.py.failed" "$d/update-attempts"; done
[ "$INIT" != none ] || die "no systemd or OpenRC found; run '$BIN --env-file $ENV_FILE' under your init system (see README)"

if [ -n "$JOIN" ]; then
    # Reinstalling? Keep the token this host already has for this server.
    if [ -f "$ENV_FILE" ] && [ "$(sed -n 's/^SERVERSTATS_URL=//p' "$ENV_FILE")" = "$URL" ]; then
        TOKEN=$(sed -n 's/^SERVERSTATS_TOKEN=//p' "$ENV_FILE")
    fi
    if [ -z "$TOKEN" ]; then
        [ -n "$NAME" ] || NAME=$(hostname -s 2>/dev/null || hostname)
        NAME=$(printf '%s' "$NAME" | tr -c 'A-Za-z0-9._-' '-' | cut -c1-64)
        # The key goes in via the environment, not argv, so `ps` can't show it.
        OUT=$(SERVERSTATS_JOIN_KEY="$JOIN" python3 "$BIN" --enroll "$NAME" --url "$URL" ${CA_FILE:+--ca-file "$CA_FILE"}) || exit 1
        TOKEN=${OUT#* }
        echo "Joined ServerStats as ${OUT%% *}."
    fi
fi

write_env() {
    cat > "$ENV_FILE" <<EOF
SERVERSTATS_URL=$URL
SERVERSTATS_TOKEN=$TOKEN
SERVERSTATS_INTERVAL=$INTERVAL
SERVERSTATS_DOCKER=$DOCKER
SERVERSTATS_UPDATES=$UPDATES
EOF
    [ -n "$CA_FILE" ] && echo "SERVERSTATS_CA_FILE=$CA_FILE" >> "$ENV_FILE"
    return 0
}

if [ "$INIT" = systemd ]; then
    umask 077
    write_env
    chmod 0600 "$ENV_FILE"   # systemd reads it as root
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
# Writable home for remote updates (the rest of the system stays read-only).
StateDirectory=serverstats-agent

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
    exit 0
fi

# OpenRC: no DynamicUser, so run as a dedicated unprivileged system user. The
# token is read from the env file (root:$AGENT_USER 0640) rather than passed on
# the command line, where any user could see it in `ps`.
if ! user_exists "$AGENT_USER"; then
    useradd --system --no-create-home --home-dir /nonexistent --shell "$(nologin_shell)" "$AGENT_USER" 2>/dev/null \
        || { addgroup -S "$AGENT_USER" 2>/dev/null || true; adduser -S -D -H -h /nonexistent -s "$(nologin_shell)" -G "$AGENT_USER" "$AGENT_USER"; } \
        || die "could not create user $AGENT_USER"
fi
AGENT_GROUP=$(id -gn "$AGENT_USER")
if [ "$DOCKER" -eq 1 ]; then
    add_to_group "$AGENT_USER" docker
elif id -Gn "$AGENT_USER" | tr ' ' '\n' | grep -qx docker; then
    # Re-run without --docker: take the access away again.
    if command -v gpasswd >/dev/null 2>&1; then gpasswd -d "$AGENT_USER" docker >/dev/null; else delgroup "$AGENT_USER" docker; fi
fi

umask 077
write_env
echo "SERVERSTATS_STATE_DIR=/var/lib/serverstats-agent" >> "$ENV_FILE"
umask 022
chown "root:$AGENT_GROUP" "$ENV_FILE"
chmod 0640 "$ENV_FILE"
install -d -m 0750 -o "$AGENT_USER" -g "$AGENT_GROUP" /var/lib/serverstats-agent

cat > "$INITD" <<EOF
#!/sbin/openrc-run
# ServerStats agent (installed by install.sh)
name="serverstats-agent"
description="Reports host stats to ServerStats"
command="$BIN"
command_args="--env-file $ENV_FILE"
command_user="$AGENT_USER:$AGENT_GROUP"
supervisor="supervise-daemon"
respawn_delay=10
respawn_max=0
output_log="$OPENRC_LOG"
error_log="$OPENRC_LOG"
no_new_privs="yes"

depend() {
    need net
    after firewall
}

start_pre() {
    checkpath --file --owner "$AGENT_USER:$AGENT_GROUP" --mode 0640 "$OPENRC_LOG"
}
EOF
chmod 0755 "$INITD"

rc-update add serverstats-agent default >/dev/null 2>&1 || true
rc-service serverstats-agent restart >/dev/null 2>&1 || rc-service serverstats-agent start
echo "ServerStats agent installed and running (OpenRC). Logs: tail -f $OPENRC_LOG"
