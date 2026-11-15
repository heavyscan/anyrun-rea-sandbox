# 🔬 ANY.RUN + REA Universal Detonation Sandbox (Open-Source & Self-Hosted)

![REA Powered](https://img.shields.io/badge/Engine-REA_v6.7.0-00d2ff?style=for-the-badge)
![Video Recording](https://img.shields.io/badge/Session_Video-MP4_H.264_15fps-10b981?style=for-the-badge)
![Multi-OS](https://img.shields.io/badge/Targets-Windows_%7C_Linux_%7C_Android_%7C_macOS_%7C_Web-0072ff?style=for-the-badge)
![AI Reports](https://img.shields.io/badge/AI_Forensics-Ollama_Local_%7C_OpenAI_API-8b5cf6?style=for-the-badge)

Reprodução completa, **100% Open-Source e Auto-Hospedada** de uma plataforma interativa de análise e detonação de malwares/binários estilo **ANY.RUN**, construída sobre o motor **REA (Reverse Engineer Anything v6.7.0)**.

---

## ✨ Diferenciais & Recursos Principais

1. **Sem Limites de Upload (`MAX_CONTENT_LENGTH = None`)**:
   - Envie quantos arquivos quiser simultaneamente (Drag & Drop em lote), sem restrição de tamanho ou cota diária.
2. **Suporte Universal Multi-Sistema Operacional**:
   - **Windows (`PE32 / PE32+ / .exe / .dll / .msi / .sys / .NET CLI / .ps1 / .bat`)**: Inspeção de recursos PE (`rea inspect-pe-resources`), assemblies `.NET` (`rea inspect-managed-artifact`), descompilação Rizin e execução monitorada via Wine no container `kali-sandbox`.
   - **Linux (`ELF / .so / .bin / .deb / .sh / .py`)**: Layout binário e mitigações (`rea inspect-binary-layout`), metadados Go (`rea inspect-go-binary`) e Rust (`rea inspect-rust-binary`), rastreamento de syscalls em tempo real via `strace` e `rea capture-process`.
   - **Android (`APK / DEX / Flutter`)**: Manifesto, permissões e classes via `rea inspect-android-package` + `apktool` / `jadx`.
   - **macOS / iOS (`Mach-O / DMG / IPA`)**: `rea inspect-macho` e inventário de pacotes.
   - **Web / Electron / Node.js / WASM / SQLite / PCAP**: `rea analyze-javascript-application`, `rea inspect-wasm-artifact`, `rea inspect-sqlite-database` e `rea inspect-pcap-capture`.
3. **Gravação em Vídeo da Sessão de Instalação & Execução (`.mp4` + `.png`)**:
   - Cada submissão inicia um display X11 isolado (`Xvfb` + `fluxbox`), executa o instalador/programa monitorado e grava toda a sessão visual em **vídeo MP4 (`H.264 yuv420p`)** via `FFmpeg`, salvo junto ao relatório para assistir no navegador ou baixar.
4. **Relatório Forense Gerado Automaticamente por IA (Local ou API)**:
   - Configurável na instalação (`scripts/install.sh --interactive`) ou a qualquer momento pela interface Web:
     - **IA Local (Padrão)**: Ollama (`qwen3-hermes:latest`, `deepseek-v4`, `llama3`, etc.).
     - **IA via API Externa**: Qualquer endpoint compatível com OpenAI (`OpenAI`, `Groq`, `DeepSeek`, `OpenRouter`, `Gemini`, `Anthropic Proxy`).
   - Exportação em **PDF Forense Executivo (`forensic_report.pdf`)**, **Markdown (`report.md`)**, **JSON de Evidências REA (`report.json`)** e **Vídeo da Sessão (`session_recording.mp4`)**.

---

## 🚀 Instalação Rápida

```bash
git clone https://github.com/heavyscan/anyrun-rea-sandbox.git
cd anyrun-rea-sandbox
sudo bash scripts/install.sh
```

Para configurar interativamente o provedor de IA durante a instalação:
```bash
sudo bash scripts/install.sh --interactive
```

Acesse no navegador (PC ou Celular):
- `http://<IP_DO_SERVIDOR>:9550`
