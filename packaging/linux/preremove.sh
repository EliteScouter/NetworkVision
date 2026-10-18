#!/bin/sh
# Stop the service on removal (not on upgrade). deb passes "remove"/"upgrade", rpm passes 0/1.
set -e
case "$1" in
    remove|purge|0)
        if [ -d /run/systemd/system ]; then
            systemctl disable --now networkvision.service >/dev/null 2>&1 || true
        fi
        ;;
esac
exit 0
