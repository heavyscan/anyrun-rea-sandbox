#!/usr/bin/env python3
"""
ANY.RUN + REA Universal Malware & Binary Detonation Sandbox — Server & API
100% Open-Source, Self-Hosted, Unlimited File Uploads & Batch Submissions,
Live Session Video Recording (.mp4), REA Static/Dynamic Evidence Engine,
and Configurable AI Forensic Reporting (Local Ollama or External OpenAI/Anthropic/Groq/Gemini API).
"""

import os
import sys
import json
import uuid
import time
import shutil
import sqlite3
import datetime
import threading
from flask import Flask, request, jsonify, send_from_directory, send_file

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from engine.detonator import run_complete_submission, now_iso

DB_PATH = os.path.join(BASE_DIR, "data", "anyrun_rea.db")
SUBMISSIONS_DIR = os.path.join(BASE_DIR, "data", "submissions")
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
SAMPLES_DIR = os.path.join(BASE_DIR, "samples")

app = Flask(__name__, static_folder=STATIC_DIR)
# Unlimited upload size (no MAX_CONTENT_LENGTH limit)
app.config["MAX_CONTENT_LENGTH"] = None

db_lock = threading.Lock()


def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def init_db():
    os.makedirs(SUBMISSIONS_DIR, exist_ok=True)
    os.makedirs(SAMPLES_DIR, exist_ok=True)
    with db_lock:
        conn = get_db()
        cur = conn.cursor()

        cur.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS submissions (
            task_id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            target_os TEXT,
            artifact_family TEXT,
            sha256 TEXT,
            size_bytes INTEGER DEFAULT 0,
            status TEXT DEFAULT 'queued', -- 'queued', 'running', 'completed', 'failed'
            stage TEXT DEFAULT 'Na fila para análise...',
            progress INTEGER DEFAULT 0,
            verdict TEXT DEFAULT 'PENDING',
            threat_score INTEGER DEFAULT 0,
            has_video INTEGER DEFAULT 0,
            has_pdf INTEGER DEFAULT 0,
            created_at TEXT,
            completed_at TEXT,
            work_dir TEXT
        )
        """)

        # Default AI settings (Configurable via Web UI & Installer)
        defaults = {
            "ai_provider": os.environ.get("ANYRUN_AI_PROVIDER", "ollama"),
            "ai_model": os.environ.get("ANYRUN_AI_MODEL", "qwen3-hermes:latest"),
            "ai_base_url": os.environ.get("ANYRUN_AI_BASE_URL", "http://127.0.0.1:11434"),
            "ai_api_key": os.environ.get("ANYRUN_AI_API_KEY", ""),
            "sandbox_duration_sec": os.environ.get("ANYRUN_DURATION_SEC", "11")
        }
        for k, v in defaults.items():
            cur.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v))

        conn.commit()
        conn.close()


def get_ai_config():
    with db_lock:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT key, value FROM settings")
        cfg = {r["key"]: r["value"] for r in cur.fetchall()}
        conn.close()
    return {
        "provider": cfg.get("ai_provider", "ollama"),
        "model": cfg.get("ai_model", "qwen3-hermes:latest"),
        "base_url": cfg.get("ai_base_url", "http://127.0.0.1:11434"),
        "api_key": cfg.get("ai_api_key", ""),
        "duration_sec": int(cfg.get("sandbox_duration_sec", "11"))
    }


def update_task_status(task_id, stage, pct):
    with db_lock:
        conn = get_db()
        conn.execute(
            "UPDATE submissions SET status = 'running', stage = ?, progress = ? WHERE task_id = ?",
            (stage, pct, task_id)
        )
        conn.commit()
        conn.close()


def worker_process_submission(task_id, file_path, filename, work_dir):
    try:
        ai_cfg = get_ai_config()
        result = run_complete_submission(
            task_id=task_id,
            file_path=file_path,
            filename=filename,
            work_dir=work_dir,
            ai_config=ai_cfg,
            status_callback=update_task_status
        )
        with db_lock:
            conn = get_db()
            conn.execute("""
                UPDATE submissions SET
                    target_os = ?,
                    artifact_family = ?,
                    sha256 = ?,
                    size_bytes = ?,
                    status = 'completed',
                    stage = 'Análise concluída!',
                    progress = 100,
                    verdict = ?,
                    threat_score = ?,
                    has_video = ?,
                    has_pdf = ?,
                    completed_at = ?
                WHERE task_id = ?
            """, (
                result["file_meta"]["target_os"],
                result["file_meta"]["artifact_family"],
                result["hashes"]["sha256"],
                result["hashes"]["size_bytes"],
                result["scoring"]["verdict"],
                result["scoring"]["threat_score"],
                1 if result["dynamic"].get("video_recorded") else 0,
                1 if result.get("pdf_report") else 0,
                result["completed_at"],
                task_id
            ))
            conn.commit()
            conn.close()
    except Exception as e:
        with db_lock:
            conn = get_db()
            conn.execute(
                "UPDATE submissions SET status = 'failed', stage = ?, progress = 100 WHERE task_id = ?",
                (f"Erro na análise: {str(e)}", task_id)
            )
            conn.commit()
            conn.close()


# =====================================================================
# ROUTES
# =====================================================================

@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


@app.route("/api/submissions", methods=["GET"])
def api_list_submissions():
    with db_lock:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM submissions ORDER BY created_at DESC LIMIT 200")
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    return jsonify({"submissions": rows})


@app.route("/api/submit", methods=["POST"])
def api_submit_files():
    """
    Accepts unlimited single or multi-file uploads of ANY operating system or file format.
    Starts asynchronous REA + Dynamic Video Detonation + AI Reporting for each uploaded file.
    """
    uploaded_files = request.files.getlist("files")
    if not uploaded_files and "file" in request.files:
        uploaded_files = [request.files["file"]]

    if not uploaded_files:
        return jsonify({"error": "Nenhum arquivo enviado."}), 400

    created_tasks = []
    for f in uploaded_files:
        if not f.filename:
            continue
        safe_name = os.path.basename(f.filename)
        task_id = f"task-{ datetime.datetime.now().strftime('%Y%m%d-%H%M%S') }-{uuid.uuid4().hex[:6]}"
        work_dir = os.path.join(SUBMISSIONS_DIR, task_id)
        os.makedirs(work_dir, exist_ok=True)
        saved_path = os.path.join(work_dir, safe_name)
        f.save(saved_path)

        with db_lock:
            conn = get_db()
            conn.execute("""
                INSERT INTO submissions
                (task_id, filename, target_os, artifact_family, sha256, size_bytes, status, stage, progress, verdict, threat_score, has_video, has_pdf, created_at, work_dir)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                task_id, safe_name, "Detectando...", "Analisando cabeçalhos...", "",
                os.path.getsize(saved_path), "queued", "Iniciando pipeline REA + Sandbox...", 5,
                "ANALYZING", 0, 0, 0, now_iso(), work_dir
            ))
            conn.commit()
            conn.close()

        t = threading.Thread(target=worker_process_submission, args=(task_id, saved_path, safe_name, work_dir), daemon=True)
        t.start()
        created_tasks.append({"task_id": task_id, "filename": safe_name})

    return jsonify({"ok": True, "tasks": created_tasks})


@app.route("/api/submit-demo", methods=["POST"])
def api_submit_demo():
    """
    Creates and detonates a realistic, safe multi-OS demo artifact (Linux ELF, Windows PE, or Suspicious Dropper Script)
    so the user can immediately test the full ANY.RUN + REA + Video + AI Report pipeline in 1 click.
    """
    data = request.get_json(force=True) or {}
    demo_type = data.get("type", "linux_elf_agent")

    task_id = f"task-{ datetime.datetime.now().strftime('%Y%m%d-%H%M%S') }-{uuid.uuid4().hex[:6]}"
    work_dir = os.path.join(SUBMISSIONS_DIR, task_id)
    os.makedirs(work_dir, exist_ok=True)

    if demo_type == "suspicious_beacon_py":
        filename = "cobalt_beacon_simulator.py"
        saved_path = os.path.join(work_dir, filename)
        with open(saved_path, "w") as sf:
            sf.write("""#!/usr/bin/env python3
# Simulated C2 Beacon & Discovery Sample for ANY.RUN REA Sandbox Testing
import os, sys, time, socket, hashlib
C2_URL = "http://198.51.100.200:8443/stage2/beacon.bin"
REG_PERSIST = "HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\Updater"
print("[*] Starting Stage-1 Beacon Simulator...")
print("[*] Checking system identity: Linux sandbox-vm-01 6.12.0-generic x86_64")
print("[*] Probing target C2 endpoint:", C2_URL)
print("[*] Checking /etc/passwd and local environment variables...")
print(" -> Sandbox Host: anyrun-sandbox-node01 (Isolated Network Namespace)")
time.sleep(1)
print("[+] Simulation complete (Safe Canary Sample).")
""")
        os.chmod(saved_path, 0o755)
    elif demo_type == "linux_elf_binary":
        filename = "elf_recon_probe.elf"
        saved_path = os.path.join(work_dir, filename)
        shutil.copy2("/usr/bin/id", saved_path)
    else:
        filename = "suspicious_installer_dropper.sh"
        saved_path = os.path.join(work_dir, filename)
        with open(saved_path, "w") as sf:
            sf.write("""#!/usr/bin/env bash
echo "[*] Dropper Installer v2.4 initializing..."
echo "[*] Target C2: https://c2-telemetry.evil-simulation.example/gate.php"
echo "[*] Checking privilege level: uid=1000(sandbox-operator) gid=1000(sandbox-operator)"
echo "[*] Enumerating network interfaces: eth0 UP 10.240.0.10/24"
sleep 1
echo "[*] Attempting simulated persistence check in ~/.config/autostart..."
echo "[+] Installer execution finished."
""")
        os.chmod(saved_path, 0o755)

    with db_lock:
        conn = get_db()
        conn.execute("""
            INSERT INTO submissions
            (task_id, filename, target_os, artifact_family, sha256, size_bytes, status, stage, progress, verdict, threat_score, has_video, has_pdf, created_at, work_dir)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            task_id, filename, "Detectando...", "Analisando...", "",
            os.path.getsize(saved_path), "queued", "Iniciando detonação de demonstração...", 5,
            "ANALYZING", 0, 0, 0, now_iso(), work_dir
        ))
        conn.commit()
        conn.close()

    t = threading.Thread(target=worker_process_submission, args=(task_id, saved_path, filename, work_dir), daemon=True)
    t.start()
    return jsonify({"ok": True, "task_id": task_id, "filename": filename})


@app.route("/api/submission/<task_id>", methods=["GET"])
def api_get_submission(task_id):
    with db_lock:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM submissions WHERE task_id = ?", (task_id,))
        row = cur.fetchone()
        conn.close()

    if not row:
        return jsonify({"error": "Submissão não encontrada"}), 404

    meta = dict(row)
    report_path = os.path.join(meta["work_dir"], "report.json")
    report_data = None
    if os.path.isfile(report_path):
        try:
            with open(report_path, "r") as rf:
                report_data = json.load(rf)
        except Exception:
            pass

    return jsonify({"submission": meta, "report": report_data})


@app.route("/api/submission/<task_id>/video")
def api_get_video(task_id):
    video_path = os.path.join(SUBMISSIONS_DIR, task_id, "session_recording.mp4")
    if not os.path.isfile(video_path):
        return jsonify({"error": "Vídeo ainda não disponível"}), 404
    return send_file(video_path, mimetype="video/mp4", as_attachment=request.args.get("download") == "1", download_name=f"{task_id}_session.mp4")


@app.route("/api/submission/<task_id>/screenshot")
def api_get_screenshot(task_id):
    img_path = os.path.join(SUBMISSIONS_DIR, task_id, "session_keyframe.png")
    if not os.path.isfile(img_path):
        return jsonify({"error": "Screenshot não disponível"}), 404
    return send_file(img_path, mimetype="image/png")


@app.route("/api/submission/<task_id>/pdf")
def api_get_pdf(task_id):
    pdf_path = os.path.join(SUBMISSIONS_DIR, task_id, "forensic_report.pdf")
    if not os.path.isfile(pdf_path):
        return jsonify({"error": "PDF não disponível"}), 404
    return send_file(pdf_path, mimetype="application/pdf", as_attachment=True, download_name=f"{task_id}_forensic_report.pdf")


@app.route("/api/submission/<task_id>/markdown")
def api_get_markdown(task_id):
    md_path = os.path.join(SUBMISSIONS_DIR, task_id, "report.md")
    if not os.path.isfile(md_path):
        return jsonify({"error": "Relatório Markdown não disponível"}), 404
    return send_file(md_path, mimetype="text/markdown", as_attachment=True, download_name=f"{task_id}_report.md")


@app.route("/api/submission/<task_id>/json")
def api_get_json_bundle(task_id):
    json_path = os.path.join(SUBMISSIONS_DIR, task_id, "report.json")
    if not os.path.isfile(json_path):
        return jsonify({"error": "JSON não disponível"}), 404
    return send_file(json_path, mimetype="application/json", as_attachment=True, download_name=f"{task_id}_rea_evidence_report.json")


@app.route("/api/settings", methods=["GET", "POST"])
def api_settings():
    with db_lock:
        conn = get_db()
        cur = conn.cursor()
        if request.method == "POST":
            data = request.get_json(force=True)
            for k in ("ai_provider", "ai_model", "ai_base_url", "ai_api_key", "sandbox_duration_sec"):
                if k in data:
                    cur.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (k, str(data[k])))
            conn.commit()
        cur.execute("SELECT key, value FROM settings")
        cfg = {r["key"]: r["value"] for r in cur.fetchall()}
        conn.close()
    # Mask API key on read if set
    masked = dict(cfg)
    if masked.get("ai_api_key"):
        masked["ai_api_key_configured"] = True
        masked["ai_api_key"] = masked["ai_api_key"][:6] + "..." if len(masked["ai_api_key"]) > 6 else "***"
    else:
        masked["ai_api_key_configured"] = False
    return jsonify({"settings": masked})


init_db()

if __name__ == "__main__":
    port = int(os.environ.get("ANYRUN_PORT", "9550"))
    print(f"[*] ANY.RUN + REA Universal Detonation Sandbox listening on http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
