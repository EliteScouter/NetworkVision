#!/bin/sh
# Data (/var/lib/networkvision) and config (/etc/networkvision) are kept on remove.
# "apt purge networkvision" also deletes them and the service user.
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
if [ "$1" = "purge" ]; then
    rm -rf /var/lib/networkvision /etc/networkvision
    if getent passwd networkvision >/dev/null 2>&1; then userdel networkvision >/dev/null 2>&1 || true; fi
    if getent group networkvision >/dev/null 2>&1; then groupdel networkvision >/dev/null 2>&1 || true; fi
fi
exit 0
