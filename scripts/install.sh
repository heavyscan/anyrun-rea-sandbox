#!/usr/bin/env bash
# ==============================================================================
# ANY.RUN + REA Universal Malware & Binary Detonation Sandbox — Installer
# 100% Open-Source, Self-Hosted, Unlimited Uploads, Video Recording & AI Reports
# Includes APT Post-Invoke Hook, needrestart protection & Self-Healing Systemd
# ==============================================================================
set -euo pipefail

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
USER_NAME="${SUDO_USER:-$(whoami)}"

AI_PROVIDER="${ANYRUN_AI_PROVIDER:-ollama}"
AI_MODEL="${ANYRUN_AI_MODEL:-qwen3-hermes:latest}"
AI_BASE_URL="${ANYRUN_AI_BASE_URL:-http://127.0.0.1:11434}"
AI_API_KEY="${ANYRUN_AI_API_KEY:-}"
PORT="${ANYRUN_PORT:-9550}"

if [[ "${1:-}" == "--interactive" ]]; then
    echo "=================================================================="
    echo "  ANY.RUN + REA Sandbox — Configuração do Motor de IA"
    echo "=================================================================="
    read -rp "Provedor IA [ollama / openai_compatible] (${AI_PROVIDER}): " input_prov
    AI_PROVIDER="${input_prov:-$AI_PROVIDER}"
    read -rp "Modelo IA (${AI_MODEL}): " input_mod
    AI_MODEL="${input_mod:-$AI_MODEL}"
    read -rp "Endpoint URL (${AI_BASE_URL}): " input_url
    AI_BASE_URL="${input_url:-$AI_BASE_URL}"
    if [[ "$AI_PROVIDER" != "ollama" ]]; then
        read -rsp "API Key: " input_key
        echo ""
        AI_API_KEY="${input_key:-$AI_API_KEY}"
    fi
fi

chmod +x "${INSTALL_DIR}/scripts/prestart_healthcheck.sh" \
         "${INSTALL_DIR}/server/app.py" \
         "${INSTALL_DIR}/engine/detonator.py"

echo "[*] Instalando e marcando dependências críticas como manuais (proteção contra apt autoremove)..."
sudo apt-get update -q
sudo apt-get install -y ffmpeg xvfb xterm fluxbox imagemagick poppler-utils gunicorn python3-flask python3-reportlab python3-requests strace file binutils >/dev/null 2>&1 || true
sudo apt-mark manual ffmpeg xvfb xterm fluxbox imagemagick poppler-utils gunicorn python3-flask python3-reportlab python3-requests strace file binutils >/dev/null 2>&1 || true

# 1. Systemd Service with infinite Restart, PreStart Self-Healing, and Fallback WSGI Runner
sudo tee /etc/systemd/system/anyrun-rea.service >/dev/null <<EOF
[Unit]
Description=ANY.RUN + REA Universal Malware & Binary Detonation Sandbox
After=network-online.target docker.service ollama.service kali-sandbox.service
Wants=network-online.target docker.service ollama.service
StartLimitIntervalSec=0

[Service]
Type=simple
User=${USER_NAME}
WorkingDirectory=${INSTALL_DIR}/server
Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="ANYRUN_PORT=${PORT}"
Environment="ANYRUN_AI_PROVIDER=${AI_PROVIDER}"
Environment="ANYRUN_AI_MODEL=${AI_MODEL}"
Environment="ANYRUN_AI_BASE_URL=${AI_BASE_URL}"
Environment="ANYRUN_AI_API_KEY=${AI_API_KEY}"
PermissionsStartOnly=true
ExecStartPre=${INSTALL_DIR}/scripts/prestart_healthcheck.sh
ExecStart=/bin/sh -c 'if command -v gunicorn >/dev/null 2>&1; then exec gunicorn --workers 2 --threads 8 --bind 0.0.0.0:${PORT} --timeout 300 --keep-alive 15 --limit-request-line 0 --limit-request-field_size 0 app:app; else exec /usr/bin/python3 ${INSTALL_DIR}/server/app.py; fi'
Restart=always
RestartSec=3
TimeoutStopSec=25
KillMode=control-group

[Install]
WantedBy=multi-user.target
EOF

# 2. Protect active detonation jobs from abrupt `needrestart` kills during apt upgrades,
#    and use an APT Post-Invoke hook to smoothly validate & ensure services are running after upgrades.
if [ -d /etc/needrestart/conf.d ]; then
    sudo tee /etc/needrestart/conf.d/90-anyrun-threatlocker.conf >/dev/null <<'EOF'
# Prevent needrestart from abruptly killing active malware detonation recordings
$nrconf{override_rc}{qr(^anyrun-rea\.service$)} = 0;
$nrconf{override_rc}{qr(^kali-sandbox\.service$)} = 0;
EOF
fi

sudo tee /etc/apt/apt.conf.d/99-anyrun-rea-selfheal >/dev/null <<EOF
DPkg::Post-Invoke {
    "if [ -x ${INSTALL_DIR}/scripts/prestart_healthcheck.sh ]; then ${INSTALL_DIR}/scripts/prestart_healthcheck.sh >/dev/null 2>&1 || true; fi; systemctl is-active --quiet anyrun-rea.service || systemctl start anyrun-rea.service >/dev/null 2>&1 || true; systemctl is-active --quiet threatlocker-zt.service || systemctl start threatlocker-zt.service >/dev/null 2>&1 || true; systemctl is-active --quiet threatlocker-agent.service || systemctl start threatlocker-agent.service >/dev/null 2>&1 || true;";
};
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now anyrun-rea.service

if command -v ufw >/dev/null 2>&1; then
    sudo ufw allow "${PORT}/tcp" comment 'ANY.RUN REA Sandbox Portal' >/dev/null 2>&1 || true
fi

echo "[+] ANY.RUN + REA Sandbox blindado no systemd e contra atualizações em http://0.0.0.0:${PORT}"
