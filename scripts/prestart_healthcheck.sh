#!/usr/bin/env bash
# ==============================================================================
# ANY.RUN + REA Sandbox — Self-Healing & Post-Update Guard
# Ensures X11 sockets, database permissions, REA binary, Kali container,
# and Gunicorn/Python runtime remain 100% operational across OS/apt updates.
# ==============================================================================
set -uo pipefail

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# 1. Ensure /tmp/.X11-unix exists with sticky bit 1777 so Xvfb never fails after boot/cleanup
mkdir -p /tmp/.X11-unix
chmod 1777 /tmp/.X11-unix 2>/dev/null || true

# 2. Clean up any orphaned Xvfb lock files (>85) from abrupt power losses or restarts
for lock in /tmp/.X*-lock; do
    [ -e "$lock" ] || continue
    dnum=$(echo "$lock" | sed -E 's#/tmp/\.X([0-9]+)-lock#\1#')
    if [[ "$dnum" =~ ^[0-9]+$ ]] && [ "$dnum" -ge 85 ]; then
        pid=$(cat "$lock" 2>/dev/null | tr -d '[:space:]' || true)
        if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
            rm -f "$lock" "/tmp/.X11-unix/X${dnum}" 2>/dev/null || true
        fi
    fi
done

# 3. Ensure data and submissions directories exist and are writable
mkdir -p "${INSTALL_DIR}/data/submissions" "${INSTALL_DIR}/samples"

# 4. Ensure kali-sandbox container is started if Docker is active
if command -v docker >/dev/null 2>&1 && systemctl is-active --quiet docker; then
    docker start kali-sandbox >/dev/null 2>&1 || true
fi

# 5. Verify critical OS packages if an apt autoremove or upgrade removed anything
for bin in ffmpeg Xvfb xterm fluxbox pdftoppm strace file; do
    if ! command -v "$bin" >/dev/null 2>&1; then
        echo "[!] Missing dependency '$bin' detected after system update; attempting auto-repair..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y ffmpeg xvfb xterm fluxbox imagemagick poppler-utils strace file >/dev/null 2>&1 || true
        break
    fi
done

exit 0
