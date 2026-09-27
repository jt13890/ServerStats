#!/bin/sh
# Runs as root only long enough to let the app write the bind-mounted
# ./config folder (so it can generate config.yaml there), then drops to the
# unprivileged serverstats user for good. Switching to a non-root uid clears
# all capabilities, and no-new-privileges keeps them from coming back.
set -e
APP_UID=10001
if [ "$(id -u)" = 0 ]; then
    for dir in /config /data; do
        if [ -d "$dir" ] && [ "$(stat -c %u "$dir")" != "$APP_UID" ]; then
            chown "$APP_UID:$APP_UID" "$dir" \
                || echo "warning: can't take ownership of $dir; mount it writable for uid $APP_UID" >&2
        fi
    done
    exec setpriv --reuid="$APP_UID" --regid="$APP_UID" --clear-groups -- "$@"
fi
exec "$@"
