#!/usr/bin/env bash
# ==============================================================================
# ANY.RUN + REA Universal Malware & Binary Detonation Sandbox — Installer
# 100% Open-Source, Self-Hosted, Unlimited Uploads, Video Recording & AI Reports
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

echo "[*] Instalando dependências de sistema (FFmpeg, Xvfb, XTerm, Fluxbox, Gunicorn)..."
sudo apt-get update -q
sudo apt-get install -y ffmpeg xvfb xterm fluxbox imagemagick gunicorn python3-flask python3-reportlab strace file binutils >/dev/null 2>&1 || true

sudo tee /etc/systemd/system/anyrun-rea.service >/dev/null <<EOF
[Unit]
Description=ANY.RUN + REA Universal Malware & Binary Detonation Sandbox
After=network-online.target docker.service ollama.service
Wants=network-online.target

[Service]
Type=simple
User=${USER_NAME}
WorkingDirectory=${INSTALL_DIR}/server
Environment="ANYRUN_PORT=${PORT}"
Environment="ANYRUN_AI_PROVIDER=${AI_PROVIDER}"
Environment="ANYRUN_AI_MODEL=${AI_MODEL}"
Environment="ANYRUN_AI_BASE_URL=${AI_BASE_URL}"
Environment="ANYRUN_AI_API_KEY=${AI_API_KEY}"
ExecStart=/usr/bin/gunicorn --workers 2 --threads 8 --bind 0.0.0.0:${PORT} --timeout 300 app:app
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now anyrun-rea.service

if command -v ufw >/dev/null 2>&1; then
    sudo ufw allow "${PORT}/tcp" comment 'ANY.RUN REA Sandbox Portal' || true
fi

echo "[+] ANY.RUN + REA Sandbox ativo em http://0.0.0.0:${PORT}"
