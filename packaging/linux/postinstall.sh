#!/bin/sh
# NetworkVision post-install (deb: configure, rpm: %post). Idempotent: also runs on upgrade.
set -e

CONF_DIR=/etc/networkvision
CONF="$CONF_DIR/networkvision.env"
DATA=/var/lib/networkvision

if ! getent group networkvision >/dev/null 2>&1; then
    groupadd --system networkvision
fi
if ! getent passwd networkvision >/dev/null 2>&1; then
    NOLOGIN=$(command -v nologin || echo /usr/sbin/nologin)
    useradd --system --gid networkvision --home-dir "$DATA" --no-create-home \
        --shell "$NOLOGIN" --comment "NetworkVision" networkvision
fi

install -d -m 0750 -o networkvision -g networkvision "$DATA"
install -d -m 0750 -o root -g networkvision "$CONF_DIR"
if [ ! -e "$CONF" ]; then
    install -m 0640 -o root -g networkvision /opt/networkvision/share/networkvision.env "$CONF"
fi

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable networkvision.service >/dev/null 2>&1 || true
    # Fresh install: start. Upgrade: restart onto the new version.
    systemctl restart networkvision.service || true
fi

PORT=$(sed -n 's/^NV_PORT=\([0-9]*\).*/\1/p' "$CONF" | tail -n1)
HOST=$(hostname -I 2>/dev/null | awk '{print $1}')
echo ""
echo "NetworkVision is running. Open http://${HOST:-localhost}:${PORT:-8080}/ to finish setup."
echo "Config: $CONF   Data: $DATA   Logs: journalctl -u networkvision"
exit 0
