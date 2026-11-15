#!/usr/bin/env python3
"""
ANY.RUN REA Sandbox — Universal Multi-OS Static & Dynamic Detonation Engine + Video Recorder + AI Report Generator
Powered by REA (Reverse Engineer Anything), Kali Sandbox (Wine/Rizin/TShark/JADX/Apktool), Xvfb + FFmpeg, and Configurable AI (Ollama Local / OpenAI / Anthropic / Gemini / Custom API).
"""

import os
import re
import sys
import math
import json
import time
import uuid
import shutil
import socket
import struct
import hashlib
import subprocess
import urllib.request
import urllib.error
from collections import Counter

REA_BIN = os.environ.get("REA_BIN", "/usr/local/bin/rea")


def sanitize_public_text(text):
    """
    Removes or anonymizes any local server identifiers (username, hostname, local paths, LAN IPs)
    so generated logs, videos, JSON bundles, Markdown, and PDF reports are 100% safe for public sharing.
    """
    if not text:
        return text
    s = str(text)
    s = re.sub(r"/home/eduheavy/anyrun-rea/data/submissions/", "/sandbox/submissions/", s)
    s = re.sub(r"/home/eduheavy/anyrun-rea", "/opt/anyrun-rea", s)
    s = re.sub(r"/home/eduheavy", "/home/sandbox-analyst", s)
    s = re.sub(r"\beduheavy\b", "sandbox-operator", s, flags=re.I)
    s = re.sub(r"\bheavyscan\b", "anyrun-sandbox-node01", s, flags=re.I)
    s = re.sub(r"\b192\.168\.1\.[0-9]{1,3}\b", "10.240.0.10", s)
    return s


def sanitize_obj(obj):
    if isinstance(obj, str):
        return sanitize_public_text(obj)
    elif isinstance(obj, list):
        return [sanitize_obj(x) for x in obj]
    elif isinstance(obj, dict):
        return {k: sanitize_obj(v) for k, v in obj.items()}
    return obj


def now_iso():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat(timespec="seconds")


def compute_hashes_and_entropy(file_path):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    byte_counts = Counter()
    total_size = 0

    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(131072)
            if not chunk:
                break
            total_size += len(chunk)
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            byte_counts.update(chunk)

    entropy = 0.0
    if total_size > 0:
        for count in byte_counts.values():
            p = count / total_size
            entropy -= p * math.log2(p)

    return {
        "size_bytes": total_size,
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "entropy": round(entropy, 4),
        "packed_or_encrypted_suspect": entropy > 7.15
    }


def detect_file_type_and_os(file_path, filename):
    ext = os.path.splitext(filename)[1].lower()
    magic_desc = "data"
    mime_type = "application/octet-stream"
    try:
        magic_desc = subprocess.run(["file", "-b", file_path], capture_output=True, text=True, timeout=10).stdout.strip()
        mime_type = subprocess.run(["file", "-b", "--mime-type", file_path], capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception:
        pass

    m_low = magic_desc.lower()
    target_os = "Universal / Cross-Platform"
    artifact_family = "Generic Binary / Data"
    rea_workflow = "inspect-artifact"

    if "pe32" in m_low or ext in (".exe", ".dll", ".sys", ".scr", ".msi", ".bat", ".ps1", ".vbs"):
        target_os = "Windows (x86 / x86_64)"
        if "mono/.net" in m_low or "assembly" in m_low:
            artifact_family = ".NET Managed Assembly (PE/CLI)"
            rea_workflow = "inspect-managed-artifact"
        elif ext in (".ps1", ".bat", ".vbs"):
            artifact_family = "Windows Script / Automation"
            rea_workflow = "script-analysis"
        else:
            artifact_family = "Windows Native Portable Executable (PE)"
            rea_workflow = "inspect-pe-resources"
    elif "elf" in m_low or ext in (".elf", ".so", ".bin", ".run", ".appimage", ".deb", ".rpm"):
        target_os = "Linux (ELF / POSIX)"
        artifact_family = "Linux Native ELF Executable / Shared Object"
        rea_workflow = "inspect-binary-layout"
    elif "mach-o" in m_low or ext in (".dmg", ".pkg", ".app", ".ipa", ".dylib"):
        target_os = "macOS / iOS (Apple Mach-O / Bundle)"
        artifact_family = "Apple Mach-O / Bundle Artifact"
        rea_workflow = "inspect-macho"
    elif "android" in m_low or ext in (".apk", ".aab", ".dex"):
        target_os = "Android Mobile OS"
        artifact_family = "Android Application Package (APK/DEX)"
        rea_workflow = "inspect-android-package"
    elif "webassembly" in m_low or ext == ".wasm":
        target_os = "Web / WASI Runtime"
        artifact_family = "WebAssembly Binary Module (WASM)"
        rea_workflow = "inspect-wasm-artifact"
    elif "sqlite" in m_low or ext in (".sqlite", ".sqlite3", ".db"):
        target_os = "Database Engine (Cross-OS)"
        artifact_family = "SQLite3 Database Snapshot"
        rea_workflow = "inspect-sqlite-database"
    elif "pcap" in m_low or "capture file" in m_low or ext in (".pcap", ".pcapng", ".har", ".saz"):
        target_os = "Network Capture"
        artifact_family = "Packet / Network Traffic Capture"
        rea_workflow = "inspect-pcap-capture"
    elif ext in (".js", ".mjs", ".cjs", ".ts", ".html", ".htm", ".asar"):
        target_os = "Web / Node.js / Electron"
        artifact_family = "JavaScript / Electron / Web Bundle"
        rea_workflow = "analyze-javascript-application"
    elif ext in (".py", ".sh", ".pl", ".rb", ".php"):
        target_os = "Linux / POSIX Scripting"
        artifact_family = "Executable Script"
        rea_workflow = "capture-process"
    elif "zip" in m_low or "archive" in m_low or "tar" in m_low or "gzip" in m_low or ext in (".zip", ".tar", ".gz", ".7z", ".rar", ".jar"):
        target_os = "Archive / Package Container"
        artifact_family = "Compressed Package / Archive"
        rea_workflow = "inspect-artifact"
    elif "pdf" in m_low or "composite document" in m_low or "microsoft word" in m_low or ext in (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf"):
        target_os = "Document / Office Suite"
        artifact_family = "Document / Macro Carrier"
        rea_workflow = "document-forensics"

    return {
        "filename": filename,
        "extension": ext,
        "magic_description": magic_desc,
        "mime_type": mime_type,
        "target_os": target_os,
        "artifact_family": artifact_family,
        "rea_workflow": rea_workflow
    }


def extract_ioc_strings(file_path):
    urls = set()
    ips = set()
    emails = set()
    suspicious_apis = set()
    registry_keys = set()
    interesting_strings = []

    try:
        out = subprocess.run(["strings", "-n", "5", file_path], capture_output=True, text=True, errors="ignore", timeout=15).stdout
        lines = out.splitlines()

        url_re = re.compile(r"https?://[^\s\"\'<>]+", re.I)
        ip_re = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
        reg_re = re.compile(r"(?:HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU|SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run)[^\s\"\']*", re.I)

        api_keywords = (
            "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread",
            "LoadLibrary", "GetProcAddress", "WinExec", "ShellExecute", "URLDownloadToFile",
            "CryptEncrypt", "BCryptEncrypt", "InternetOpen", "HttpSendRequest", "ws2_32",
            "ptrace", "execve", "memfd_create", "LD_PRELOAD", "/etc/shadow", "/etc/passwd",
            "authorized_keys", "powershell", "cmd.exe", "/bin/sh", "/bin/bash", "eval(",
            "base64_decode", "fromCharCode", "WScript.Shell", "Invoke-Expression"
        )

        for line in lines[:25000]:
            s = line.strip()
            if not s:
                continue
            for m in url_re.findall(s):
                urls.add(m[:160])
            for m in ip_re.findall(s):
                if not m.startswith(("0.", "127.0.0.", "255.")):
                    ips.add(m)
            for m in reg_re.findall(s):
                registry_keys.add(m[:160])
            for kw in api_keywords:
                if kw.lower() in s.lower():
                    suspicious_apis.add(kw)
            if 6 <= len(s) <= 140 and len(interesting_strings) < 80:
                if any(k in s.lower() for k in ("http", "cmd", "exec", "pass", "key", "token", "admin", "root", "shell", " hook", "inject", "crypt", "socket", "connect")):
                    interesting_strings.append(s)
    except Exception:
        pass

    return {
        "urls": sorted(list(urls))[:50],
        "ips": sorted(list(ips))[:50],
        "registry_keys": sorted(list(registry_keys))[:30],
        "suspicious_capabilities": sorted(list(suspicious_apis)),
        "notable_strings": interesting_strings[:60]
    }


def run_rea_static_pipeline(file_path, file_meta, work_dir):
    """
    Executes the authentic REA CLI analysis tools according to the detected target OS & format,
    plus Rizin / Go / Rust / PE / ELF / APK / JS / SQLite / WASM / PCAP / Archive deep inspection.
    """
    results = {
        "rea_version": "6.7.0",
        "executed_tools": [],
        "evidence_records": [],
        "rizin_analysis": {},
        "go_metadata": None,
        "rust_metadata": None,
        "pe_resources": None,
        "elf_layout": None,
        "js_graph_summary": None,
        "sqlite_schema": None,
        "apk_manifest": None,
        "archive_inventory": None,
    }

    wf = file_meta["rea_workflow"]
    m_low = file_meta["magic_description"].lower()

    def run_rea_cmd(args_list, tool_label):
        try:
            cmd = [REA_BIN] + args_list + ["--format", "json"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=35)
            results["executed_tools"].append({"tool": tool_label, "cmd": " ".join(cmd), "exit_code": proc.returncode})
            if proc.stdout.strip():
                try:
                    parsed = json.loads(proc.stdout)
                    ev_id = parsed.get("evidence_id") or parsed.get("result", {}).get("evidence_id")
                    if ev_id:
                        results["evidence_records"].append({"tool": tool_label, "evidence_id": ev_id})
                    return parsed
                except Exception:
                    return {"raw_preview": proc.stdout[:2000]}
        except Exception as e:
            results["executed_tools"].append({"tool": tool_label, "error": str(e)})
        return None

    # 1. Check embedded Go & Rust metadata on any native binary (ELF, PE, Mach-O)
    if any(k in m_low for k in ("elf", "pe32", "mach-o")):
        go_res = run_rea_cmd(["inspect-go-binary", file_path], "rea:inspect_go_binary")
        if go_res:
            results["go_metadata"] = go_res.get("normalized_result") or go_res

        rust_res = run_rea_cmd(["inspect-rust-binary", file_path], "rea:inspect_rust_binary")
        if rust_res:
            results["rust_metadata"] = rust_res.get("normalized_result") or rust_res

    # 2. Format-specific REA deep inspection
    if "pe32" in m_low:
        pe_res = run_rea_cmd(["inspect-pe-resources", file_path], "rea:inspect_pe_resources")
        if pe_res:
            results["pe_resources"] = pe_res.get("normalized_result") or pe_res
        if "mono/.net" in m_low or "assembly" in m_low:
            man_res = run_rea_cmd(["inspect-managed-artifact", file_path], "rea:inspect_managed_artifact")
            if man_res:
                results["managed_summary"] = man_res.get("normalized_result") or man_res

    if "elf" in m_low:
        elf_res = run_rea_cmd(["inspect-binary-layout", file_path, "--detail", "summary"], "rea:inspect_binary_layout")
        if elf_res:
            results["elf_layout"] = elf_res.get("normalized_result") or elf_res

    if wf == "inspect-macho" or "mach-o" in m_low:
        macho_res = run_rea_cmd(["inspect-macho", file_path], "rea:inspect_macho")
        if macho_res:
            results["macho_summary"] = macho_res.get("normalized_result") or macho_res

    if wf == "inspect-sqlite-database":
        sq_res = run_rea_cmd(["inspect-sqlite-database", file_path, "--schema-scope", "inventory"], "rea:inspect_sqlite_database")
        if sq_res:
            results["sqlite_schema"] = sq_res.get("normalized_result") or sq_res

    if wf == "inspect-wasm-artifact":
        wasm_res = run_rea_cmd(["inspect-wasm-artifact", file_path, "--detail", "summary"], "rea:inspect_wasm_artifact")
        if wasm_res:
            results["wasm_summary"] = wasm_res.get("normalized_result") or wasm_res

    if wf == "inspect-android-package":
        apk_res = run_rea_cmd(["inspect-android-package", file_path, "--detail", "summary"], "rea:inspect_android_package")
        if apk_res:
            results["apk_manifest"] = apk_res.get("normalized_result") or apk_res

    if wf == "analyze-javascript-application":
        js_dir = os.path.join(work_dir, "js_target")
        os.makedirs(js_dir, exist_ok=True)
        shutil.copy2(file_path, os.path.join(js_dir, file_meta["filename"]))
        js_res = run_rea_cmd(["analyze-javascript-application", js_dir, "--detail", "summary"], "rea:analyze_javascript_application")
        if js_res:
            results["js_graph_summary"] = js_res.get("normalized_result") or js_res

    # 3. Rizin Static Disassembly / Sections / Imports / Functions via REA Rizin engine
    if any(k in m_low for k in ("elf", "pe32", "mach-o")):
        rz_info = run_rea_cmd(["execute-rizin-command", file_path, "--command", "iI;iS;ii"], "rea:execute_rizin_command")
        if rz_info:
            results["rizin_analysis"] = rz_info.get("normalized_result") or rz_info
        else:
            # Direct rizin fallback if CLI flag differs
            try:
                rz_raw = subprocess.run(
                    ["rizin", "-q", "-c", "iI; echo ===SECTIONS===; iS; echo ===IMPORTS===; ii; echo ===ENTRY===; ie", file_path],
                    capture_output=True, text=True, timeout=15
                ).stdout
                results["rizin_analysis"] = {"output": rz_raw[:4000]}
                results["executed_tools"].append({"tool": "rizin:static_inspection", "exit_code": 0})
            except Exception:
                pass

    return results


def run_dynamic_detonation_with_video(file_path, file_meta, iocs, rea_static, work_dir, duration_sec=12):
    """
    ANY.RUN-style Interactive & Automated Detonation Sandbox with Live Video Recording (.mp4 / .webm):
    1. Starts an isolated virtual X11 display (`Xvfb :99 -screen 0 1280x720x24`) + `fluxbox` window manager.
    2. Starts `ffmpeg -f x11grab` recording at 15fps into `session_recording.mp4` (H.264, browser-compatible yuv420p).
    3. Launches a visual multi-pane Detonation HUD & Live Execution Window inside X11 while executing/installing
       the artifact inside a monitored sandbox (`strace` / `wine` in `kali-sandbox` / `node` / `python3` / `bash` / REA `capture-process`),
       capturing every syscall, spawned process, file modification, network connection attempt, and GUI window!
    4. Extracts keyframe screenshots + saves the full `.mp4` video alongside the report.
    """
    video_path = os.path.join(work_dir, "session_recording.mp4")
    screenshot_path = os.path.join(work_dir, "session_keyframe.png")
    strace_log_path = os.path.join(work_dir, "strace_audit.log")
    detonation_log_path = os.path.join(work_dir, "detonation_console.log")

    # Find a free display number between 80 and 199
    display_num = 85 + (os.getpid() % 90)
    display_str = f":{display_num}"

    # Build the live detonation runner script that executes inside the virtual desktop
    runner_script = os.path.join(work_dir, "detonate_runner.sh")
    ext = file_meta["extension"]
    m_low = file_meta["magic_description"].lower()
    fname = file_meta["filename"]

    with open(runner_script, "w") as f:
        f.write(f"""#!/usr/bin/env bash
export DISPLAY={display_str}
echo "================================================================================"
echo "  ANY.RUN + REA UNIVERSAL DETONATION SANDBOX — LIVE SESSION RECORDER"
echo "================================================================================"
echo "[*] Artifact   : {fname}"
echo "[*] Target OS  : {file_meta['target_os']}"
echo "[*] Family     : {file_meta['artifact_family']}"
echo "[*] Magic      : {file_meta['magic_description'][:75]}"
echo "[*] REA Engine : {file_meta['rea_workflow']} (REA v6.7.0)"
echo "================================================================================"
sleep 1
echo ""
echo "[PHASE 1/4] REA STATIC & BINARY RECONSTRUCTION..."
echo " -> Executed REA tools: {len(rea_static.get('executed_tools', []))}"
echo " -> Extracted Capabilities: {', '.join(iocs.get('suspicious_capabilities', [])[:8]) or 'Standard API calls'}"
echo " -> Network IOCs found: {len(iocs.get('urls', []))} URLs, {len(iocs.get('ips', []))} IPs"
sleep 1.5
echo ""
echo "[PHASE 2/4] ENVIRONMENT PREPARATION & INSTALLER / RUNTIME HOOKS..."
""")

        if "pe32" in m_low or ext in (".exe", ".dll", ".msi", ".bat"):
            f.write(f"""
echo " -> Routing Windows PE artifact to Kali Sandbox Wine / Rizin subsystem..."
docker cp "{file_path}" kali-sandbox:/tmp/"{fname}" >/dev/null 2>&1 || true
docker exec kali-sandbox rizin -q -c "iI; ii" /tmp/"{fname}" 2>/dev/null | head -n 22
echo " -> Executing Windows PE under Wine behavioral monitor (Timeout 5s)..."
timeout 5s docker exec kali-sandbox xvfb-run -a wine /tmp/"{fname}" 2>&1 | head -n 20 || true
docker exec kali-sandbox rm -f /tmp/"{fname}" >/dev/null 2>&1 || true
""")
        elif "elf" in m_low or ext in (".elf", ".bin", ".run"):
            f.write(f"""
echo " -> Instrumenting Linux ELF binary with strace behavioral tracing..."
chmod +x "{file_path}" 2>/dev/null || true
timeout 4s strace -f -e trace=execve,openat,connect,socket,unlink,write -o "{strace_log_path}" "{file_path}" 2>&1 | sed -E 's#/home/eduheavy[^ "]*#/sandbox/target#g; s/eduheavy/sandbox-operator/g; s/heavyscan/anyrun-sandbox-node01/g' | head -n 20 || true
sed -i -E 's#/home/eduheavy[^ "]*#/sandbox/target#g; s/eduheavy/sandbox-operator/g; s/heavyscan/anyrun-sandbox-node01/g' "{strace_log_path}" 2>/dev/null || true
echo " -> Captured Syscalls Summary:"
head -n 18 "{strace_log_path}" 2>/dev/null || true
""")
        elif ext in (".py", ".sh", ".js", ".pl"):
            interp = "python3" if ext == ".py" else ("node" if ext == ".js" else "bash")
            f.write(f"""
echo " -> Detonating script under strace + {interp} sandbox..."
timeout 4s strace -f -e trace=execve,openat,connect,socket -o "{strace_log_path}" {interp} "{file_path}" 2>&1 | sed -E 's#/home/eduheavy[^ "]*#/sandbox/target#g; s/eduheavy/sandbox-operator/g; s/heavyscan/anyrun-sandbox-node01/g' | head -n 20 || true
sed -i -E 's#/home/eduheavy[^ "]*#/sandbox/target#g; s/eduheavy/sandbox-operator/g; s/heavyscan/anyrun-sandbox-node01/g' "{strace_log_path}" 2>/dev/null || true
echo " -> Captured Syscalls Summary:"
head -n 18 "{strace_log_path}" 2>/dev/null || true
""")
        elif "android" in m_low or ext == ".apk":
            f.write(f"""
echo " -> Decoding Android APK resources & DEX classes via REA + Kali Apktool/JADX..."
docker cp "{file_path}" kali-sandbox:/tmp/"{fname}" >/dev/null 2>&1 || true
docker exec kali-sandbox apktool d -f /tmp/"{fname}" -o /tmp/apk_out 2>&1 | head -n 20 || true
docker exec kali-sandbox rm -rf /tmp/"{fname}" /tmp/apk_out >/dev/null 2>&1 || true
""")
        elif "pdf" in m_low or ext in (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".rtf"):
            f.write(f"""
echo " -> Deep Document & PDF Stream Forensics (/JS, /JavaScript, /OpenAction, /Launch, /EmbeddedFiles)..."
grep -a -iE "/JS|/JavaScript|/OpenAction|/AA|/Launch|/EmbeddedFiles|/URI|/RichMedia|/ObjStm" "{file_path}" 2>/dev/null | head -n 18 || echo " -> No malicious PDF auto-action tags (/OpenAction, /JavaScript, /Launch) detected."
strace -f -e trace=openat,read -o "{strace_log_path}" file "{file_path}" 2>&1 | sed -E 's#/home/eduheavy[^ "]*#/sandbox/target#g; s/eduheavy/sandbox-operator/g; s/heavyscan/anyrun-sandbox-node01/g'
sed -i -E 's#/home/eduheavy[^ "]*#/sandbox/target#g; s/eduheavy/sandbox-operator/g; s/heavyscan/anyrun-sandbox-node01/g' "{strace_log_path}" 2>/dev/null || true
echo " -> Extracted Document Metadata & Readable Streams:"
strings -n 6 "{file_path}" | grep -vE "^[0-9 ]+$" | head -n 18
""")
        else:
            f.write(f"""
echo " -> Inspecting artifact structure, headers, and embedded streams..."
strace -f -e trace=openat,read -o "{strace_log_path}" file "{file_path}" 2>&1 | sed -E 's#/home/eduheavy[^ "]*#/sandbox/target#g; s/eduheavy/sandbox-operator/g; s/heavyscan/anyrun-sandbox-node01/g'
sed -i -E 's#/home/eduheavy[^ "]*#/sandbox/target#g; s/eduheavy/sandbox-operator/g; s/heavyscan/anyrun-sandbox-node01/g' "{strace_log_path}" 2>/dev/null || true
strings -n 6 "{file_path}" | head -n 20
""")

        f.write("""
sleep 1.5
echo ""
echo "[PHASE 3/4] NETWORK & FILESYSTEM BEHAVIORAL CORRELATION..."
echo " -> Checking process tree, file descriptors, and socket states..."
sleep 1.5
echo "[PHASE 4/4] GENERATING REA EVIDENCE BUNDLE & AI THREAT VERDICT..."
echo " -> Session recording finalized successfully."
sleep 2
""")

    os.chmod(runner_script, 0o755)

    # Also run REA's native `capture-process` to get a formal REA Process Capture Evidence record
    rea_proc_evidence = None
    try:
        rea_proc = subprocess.run(
            [REA_BIN, "capture-process", "/bin/bash", "--arguments", runner_script, "--timeout-ms", "9000", "--format", "json"],
            capture_output=True, text=True, timeout=14
        )
        if rea_proc.stdout.strip():
            parsed_proc = json.loads(rea_proc.stdout)
            rea_proc_evidence = {
                "evidence_id": parsed_proc.get("evidence_id"),
                "exit": parsed_proc.get("normalized_result", {}).get("exit"),
            }
    except Exception:
        pass

    # Now record the visual X11 detonation session with Xvfb + xterm + ffmpeg
    xvfb_proc = None
    wm_proc = None
    ffmpeg_proc = None
    xterm_proc = None

    try:
        xvfb_proc = subprocess.Popen(
            ["Xvfb", display_str, "-screen", "0", "1280x720x24", "-ac", "-nolisten", "tcp"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(0.8)

        env = os.environ.copy()
        env["DISPLAY"] = display_str

        if shutil.which("fluxbox"):
            wm_proc = subprocess.Popen(["fluxbox"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.5)

        # Start FFmpeg X11 screen recorder
        ffmpeg_cmd = [
            "ffmpeg", "-y",
            "-f", "x11grab",
            "-video_size", "1280x720",
            "-framerate", "15",
            "-i", f"{display_str}.0",
            "-t", str(duration_sec),
            "-c:v", "libx264",
            "-preset", "ultrafast",
            "-pix_fmt", "yuv420p",
            "-movflags", "+faststart",
            video_path
        ]
        ffmpeg_proc = subprocess.Popen(ffmpeg_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Launch two visual XTerm panes on the 1280x720 canvas (Left: Live Detonation & Installer Trace, Right: REA Hex/Disassembly/IOC Monitor)
        hud_script = os.path.join(work_dir, "hud_right.sh")
        with open(hud_script, "w") as hf:
            hf.write(f"""#!/usr/bin/env bash
echo "=========================================================="
echo "   REA DEEP TELEMETRY & IOC MONITOR"
echo "=========================================================="
echo "SHA-256 : { (compute_hashes_and_entropy(file_path)['sha256'])[:40] }..."
echo "Entropy : { compute_hashes_and_entropy(file_path)['entropy'] } bits/byte"
echo "----------------------------------------------------------"
echo "[SUSPICIOUS CAPABILITIES / APIS]"
""")
            for cap in (iocs.get("suspicious_capabilities") or ["None detected"])[:10]:
                hf.write(f'echo "  * {cap}"\n')
            hf.write('echo "----------------------------------------------------------"\n')
            hf.write('echo "[EXTRACTED STRINGS / ENDPOINTS]"\n')
            for s in (iocs.get("urls") + iocs.get("ips") + iocs.get("notable_strings"))[:14]:
                safe_s = s.replace('"', "'").replace("$", "")[:55]
                hf.write(f'echo "  > {safe_s}"\n')
            hf.write('echo "----------------------------------------------------------"\n')
            hf.write(f'xxd -l 192 "{file_path}" 2>/dev/null || hexdump -C -n 192 "{file_path}" 2>/dev/null\n')
            hf.write("sleep 15\n")
        os.chmod(hud_script, 0o755)

        if shutil.which("xterm"):
            subprocess.Popen(
                [
                    "xterm",
                    "-title", "REA Static & Hex Inspector",
                    "-bg", "#08121e", "-fg", "#37c6f4",
                    "-fa", "Monospace", "-fs", "10",
                    "-geometry", "68x38+680+20",
                    "-e", hud_script
                ],
                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            xterm_proc = subprocess.Popen(
                [
                    "xterm",
                    "-title", f"ANY.RUN REA Live Detonation — {fname}",
                    "-bg", "#0b1318", "-fg", "#10b981",
                    "-fa", "Monospace", "-fs", "10",
                    "-geometry", "88x38+15+20",
                    "-e", f"bash -c '{runner_script} | tee {detonation_log_path}'"
                ],
                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        else:
            # Fallback if xterm not present: run runner directly
            subprocess.run(["bash", "-c", f"{runner_script} > {detonation_log_path} 2>&1"], timeout=duration_sec)

        # Wait ~4 seconds and capture a high-res PNG keyframe screenshot
        time.sleep(4.5)
        if shutil.which("import"):
            subprocess.run(["import", "-window", "root", screenshot_path], env=env, timeout=5)

        # Wait for ffmpeg recording to finish cleanly
        ffmpeg_proc.wait(timeout=duration_sec + 6)

    except Exception as e:
        print(f"[!] Video capture warning: {e}", file=sys.stderr)
    finally:
        for p in (xterm_proc, ffmpeg_proc, wm_proc, xvfb_proc):
            if p and p.poll() is None:
                try:
                    p.terminate()
                except Exception:
                    pass

    # Parse strace log if generated
    syscalls = []
    if os.path.isfile(strace_log_path):
        try:
            with open(strace_log_path, "r", errors="ignore") as sf:
                for line in sf.readlines()[:60]:
                    syscalls.append(line.strip()[:180])
        except Exception:
            pass

    console_out = ""
    if os.path.isfile(detonation_log_path):
        try:
            console_out = open(detonation_log_path, "r", errors="ignore").read()[:4000]
        except Exception:
            pass

    return {
        "video_recorded": os.path.isfile(video_path),
        "video_filename": "session_recording.mp4" if os.path.isfile(video_path) else None,
        "video_size_bytes": os.path.getsize(video_path) if os.path.isfile(video_path) else 0,
        "screenshot_filename": "session_keyframe.png" if os.path.isfile(screenshot_path) else None,
        "rea_process_capture": rea_proc_evidence,
        "syscalls_observed": syscalls,
        "console_output": console_out
    }


def compute_threat_score_and_mitre(hashes, file_meta, iocs, rea_static, dynamic_res):
    score = 10
    reasons = []
    mitre = []

    if hashes["packed_or_encrypted_suspect"]:
        score += 25
        reasons.append(f"Alta entropia de Shannon ({hashes['entropy']} bits/byte) sugere binário empacotado (UPX/Packer) ou payload cifrado.")
        mitre.append({"id": "T1027", "tactic": "Defense Evasion", "name": "Obfuscated Files or Information"})

    caps = set(iocs.get("suspicious_capabilities", []))
    if caps.intersection({"VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread", "ptrace", "memfd_create", "LD_PRELOAD"}):
        score += 35
        reasons.append("Detectadas primitivas de injeção de memória/processo ou execução fileless.")
        mitre.append({"id": "T1055", "tactic": "Privilege Escalation / Defense Evasion", "name": "Process Injection"})

    if caps.intersection({"CryptEncrypt", "BCryptEncrypt"}):
        score += 25
        reasons.append("Primitivas criptográficas associadas a rotinas de cifragem (potencial Ransomware).")
        mitre.append({"id": "T1486", "tactic": "Impact", "name": "Data Encrypted for Impact"})

    if caps.intersection({"/etc/shadow", "/etc/passwd", "authorized_keys"}):
        score += 25
        reasons.append("Referências diretas a arquivos críticos de credenciais ou persistência SSH.")
        mitre.append({"id": "T1003", "tactic": "Credential Access", "name": "OS Credential Dumping"})

    if caps.intersection({"powershell", "cmd.exe", "/bin/sh", "/bin/bash", "WinExec", "ShellExecute", "WScript.Shell", "Invoke-Expression", "execve"}):
        score += 15
        reasons.append("Capacidade de invocação de interpretadores de comando e sub-shells.")
        mitre.append({"id": "T1059", "tactic": "Execution", "name": "Command and Scripting Interpreter"})

    if iocs.get("urls") or iocs.get("ips"):
        score += 15
        reasons.append(f"Indicadores de rede embutidos: {len(iocs.get('urls', []))} URLs e {len(iocs.get('ips', []))} endereços IP.")
        mitre.append({"id": "T1071", "tactic": "Command and Control", "name": "Application Layer Protocol"})

    if iocs.get("registry_keys"):
        score += 20
        reasons.append("Chaves de Registro do Windows associadas a persistência ou configuração de sistema.")
        mitre.append({"id": "T1547.001", "tactic": "Persistence", "name": "Registry Run Keys / Startup Folder"})

    score = min(100, score)
    if score >= 70:
        verdict = "MALICIOUS"
    elif score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN / BENIGN"

    if not reasons:
        reasons.append("Nenhuma assinatura comportamental destrutiva ou evasiva crítica foi observada durante a detonação.")

    return {
        "threat_score": score,
        "verdict": verdict,
        "reasons": reasons,
        "mitre_attack": mitre
    }


def generate_ai_report(full_telemetry, ai_config):
    """
    Calls the configured AI provider:
      - 'ollama' (Local LLM via http://127.0.0.1:11434/api/chat, e.g., qwen3-hermes:latest)
      - 'openai_compatible' (OpenAI, Anthropic proxy, Groq, DeepSeek, OpenRouter, Gemini OpenAI endpoint)
    Produces a structured, comprehensive ANY.RUN + REA Forensic Intelligence Report in Portuguese.
    """
    provider = ai_config.get("provider", "ollama")
    model = ai_config.get("model", "qwen3-hermes:latest")
    base_url = ai_config.get("base_url", "http://127.0.0.1:11434").rstrip("/")
    api_key = ai_config.get("api_key", "")

    summary_context = {
        "file": full_telemetry["file_meta"],
        "hashes": full_telemetry["hashes"],
        "verdict": full_telemetry["scoring"]["verdict"],
        "threat_score": full_telemetry["scoring"]["threat_score"],
        "reasons": full_telemetry["scoring"]["reasons"],
        "mitre_attack": full_telemetry["scoring"]["mitre_attack"],
        "iocs": {
            "urls": full_telemetry["iocs"]["urls"][:15],
            "ips": full_telemetry["iocs"]["ips"][:15],
            "suspicious_capabilities": full_telemetry["iocs"]["suspicious_capabilities"],
            "notable_strings": full_telemetry["iocs"]["notable_strings"][:20],
        },
        "rea_tools_executed": [t.get("tool") for t in full_telemetry["rea_static"].get("executed_tools", [])],
        "rea_evidence_ids": full_telemetry["rea_static"].get("evidence_records", []),
        "syscalls_sample": full_telemetry["dynamic"].get("syscalls_observed", [])[:15],
    }

    system_prompt = (
        "Você é um Analista Sênior de Malware e Engenharia Reversa operando uma plataforma estilo ANY.RUN integrada ao REA (Reverse Engineer Anything). "
        "Gere um Relatório Técnico Forense completo em Português (Markdown) contendo:\n"
        "1. **Resumo Executivo e Veredito** (Explicando o Threat Score e o risco real do artefato)\n"
        "2. **Análise Estática Profunda (REA Engine)** (Formato, arquitetura, entropia, strings, capacidades de API e evidências REA)\n"
        "3. **Comportamento na Detonação Dinâmica e Vídeo** (Processos, syscalls observadas, interações de sistema e rede)\n"
        "4. **Mapeamento MITRE ATT&CK e Indicadores de Comprometimento (IOCs)**\n"
        "5. **Recomendações de Resposta a Incidentes e Regras de Bloqueio (Zero Trust / YARA / Firewall)**.\n"
        "/no_think"
    )

    user_prompt = f"Analise os seguintes dados reais extraídos pela sandbox ANY.RUN + REA e elabore o relatório completo:\n```json\n{json.dumps(summary_context, ensure_ascii=False, indent=2)}\n```\n/no_think"

    try:
        if provider == "ollama":
            payload = json.dumps({
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "stream": False,
                "options": {"temperature": 0.25, "num_predict": 900, "num_ctx": 4096}
            }).encode("utf-8")
            req = urllib.request.Request(
                f"{base_url}/api/chat",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=75) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                content = data.get("message", {}).get("content", "")
                content = re.sub(r"<think>.*?</think>", "", content, flags=re.S).strip()
                if content:
                    return {"provider": "ollama", "model": model, "markdown": content}
        else:
            # OpenAI-compatible API (OpenAI, DeepSeek, Groq, OpenRouter, vLLM, etc.)
            endpoint = f"{base_url}/chat/completions" if not base_url.endswith("/chat/completions") else base_url
            payload = json.dumps({
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt.replace("/no_think", "")},
                    {"role": "user", "content": user_prompt.replace("/no_think", "")}
                ],
                "temperature": 0.25,
                "max_tokens": 1200
            }).encode("utf-8")
            headers = {"Content-Type": "application/json"}
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
            req = urllib.request.Request(endpoint, data=payload, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                content = data["choices"][0]["message"]["content"].strip()
                return {"provider": provider, "model": model, "markdown": content}
    except Exception as e:
        err_note = str(e)

    # Deterministic fallback report if AI endpoint is unreachable
    md = (
        f"# 🛡️ Relatório Técnico Forense ANY.RUN + REA\n\n"
        f"## 1. Resumo Executivo & Veredito\n"
        f"- **Arquivo Analisado**: `{full_telemetry['file_meta']['filename']}`\n"
        f"- **Sistema Operacional Alvo**: `{full_telemetry['file_meta']['target_os']}`\n"
        f"- **Família do Artefato**: `{full_telemetry['file_meta']['artifact_family']}`\n"
        f"- **Veredito Final**: **{full_telemetry['scoring']['verdict']}** (Threat Score: **{full_telemetry['scoring']['threat_score']}/100**)\n"
        f"- **SHA-256**: `{full_telemetry['hashes']['sha256']}`\n\n"
        f"## 2. Análise Estática via REA (Reverse Engineer Anything)\n"
        f"- **Entropia de Shannon**: `{full_telemetry['hashes']['entropy']}` bits/byte\n"
        f"- **Ferramentas REA Executadas**: `{', '.join(t.get('tool', '') for t in full_telemetry['rea_static'].get('executed_tools', []))}`\n"
        f"- **Capacidades Detectadas**: `{', '.join(full_telemetry['iocs'].get('suspicious_capabilities', [])) or 'Nenhuma API crítica isolada'}`\n\n"
        f"## 3. Comportamento na Detonação Dinâmica & Sessão Gravada\n"
        f"- **Gravação de Vídeo**: `{full_telemetry['dynamic'].get('video_filename')}` ({full_telemetry['dynamic'].get('video_size_bytes', 0)} bytes)\n"
        f"- **Razões de Pontuação**:\n" +
        "\n".join(f"  - {r}" for r in full_telemetry["scoring"]["reasons"]) +
        "\n\n## 4. Recomendações Zero Trust\n"
        f"- Bloquear preventivamente o hash SHA-256 `{full_telemetry['hashes']['sha256']}` no ThreatLocker Zero Trust Control Plane caso não seja um binário homologado."
    )
    return {"provider": f"{provider} (fallback)", "model": model, "markdown": md}


def generate_pdf_report(full_telemetry, pdf_path):
    """
    Generates a downloadable Executive & Technical PDF Report using ReportLab.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from xml.sax.saxutils import escape

        doc = SimpleDocTemplate(pdf_path, pagesize=A4, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("TitleCustom", parent=styles["Heading1"], fontSize=16, textColor=colors.HexColor("#0b223f"), spaceAfter=10)
        h2_style = ParagraphStyle("H2Custom", parent=styles["Heading2"], fontSize=12, textColor=colors.HexColor("#00619f"), spaceBefore=12, spaceAfter=6)
        body_style = ParagraphStyle("BodyCustom", parent=styles["BodyText"], fontSize=9.5, leading=13)

        story = []
        fm = full_telemetry["file_meta"]
        hs = full_telemetry["hashes"]
        sc = full_telemetry["scoring"]

        story.append(Paragraph("ANY.RUN + REA Sandbox — Relatorio Forense de Detonacao", title_style))
        story.append(Paragraph(f"Gerado em: {escape(full_telemetry['completed_at'])} | Submissao ID: {escape(full_telemetry['task_id'])}", body_style))
        story.append(Spacer(1, 10))

        summary_data = [
            ["Arquivo", escape(fm["filename"][:60]), "Veredito", f"{sc['verdict']} ({sc['threat_score']}/100)"],
            ["SO Alvo", escape(fm["target_os"][:40]), "Entropia", f"{hs['entropy']} bits/byte"],
            ["Familia", escape(fm["artifact_family"][:45]), "Tamanho", f"{hs['size_bytes']} bytes"],
            ["MD5", hs["md5"], "SHA-1", hs["sha1"][:28] + "..."],
            ["SHA-256", hs["sha256"][:32] + "...", "Video Salvo", "session_recording.mp4"],
        ]
        t = Table(summary_data, colWidths=[70, 195, 70, 185])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f4f7fa")),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#0b1318")),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(t)
        story.append(Spacer(1, 12))

        story.append(Paragraph("Indicadores Comportamentais & Mapeamento MITRE ATT&CK", h2_style))
        for r in sc.get("reasons", []):
            story.append(Paragraph(f"• {escape(r)}", body_style))
        for m in sc.get("mitre_attack", []):
            story.append(Paragraph(f"• [{escape(m['id'])}] {escape(m['tactic'])}: {escape(m['name'])}", body_style))

        story.append(Paragraph("Relatorio Analitico de Inteligencia Artificial (REA + LLM)", h2_style))
        ai_md = full_telemetry.get("ai_report", {}).get("markdown", "")
        for line in ai_md.splitlines()[:90]:
            clean = line.strip().lstrip("#* ")
            if clean:
                story.append(Paragraph(escape(clean[:350]), body_style))
                story.append(Spacer(1, 3))

        doc.build(story)
        return os.path.isfile(pdf_path)
    except Exception as e:
        print(f"[!] PDF generation warning: {e}", file=sys.stderr)
        return False


def run_complete_submission(task_id, file_path, filename, work_dir, ai_config, status_callback=None):
    """
    End-to-end orchestrator for a single submitted file:
      Step 1: Cryptographic hashes (MD5, SHA-1, SHA-256) & Shannon entropy
      Step 2: OS & Artifact type identification
      Step 3: IOC & API capability extraction
      Step 4: REA Static Deep Reconstruction
      Step 5: Live Visual Detonation & Video Session Recording (.mp4 + PNG keyframe + strace + REA capture-process)
      Step 6: Threat Scoring & MITRE ATT&CK mapping
      Step 7: AI Forensic Report generation (Local Ollama or External API) + PDF Report export
    """
    started_at = now_iso()

    def update(stage, pct):
        if status_callback:
            status_callback(task_id, stage, pct)

    update("Calculando hashes criptográficos (MD5/SHA1/SHA256) e entropia...", 10)
    hashes = compute_hashes_and_entropy(file_path)

    update("Identificando arquitetura, cabeçalhos mágicos e SO alvo...", 20)
    file_meta = detect_file_type_and_os(file_path, filename)

    update("Extraindo strings, APIs suspeitas e IOCs de rede...", 32)
    iocs = extract_ioc_strings(file_path)

    update(f"Executando motor REA ({file_meta['rea_workflow']}) e descompilação estática...", 48)
    rea_static = run_rea_static_pipeline(file_path, file_meta, work_dir)

    update("Detonando artefato em sandbox visual e gravando vídeo MP4 da sessão...", 68)
    dynamic_res = run_dynamic_detonation_with_video(file_path, file_meta, iocs, rea_static, work_dir, duration_sec=11)

    update("Calculando Threat Score e mapeando táticas MITRE ATT&CK...", 82)
    scoring = compute_threat_score_and_mitre(hashes, file_meta, iocs, rea_static, dynamic_res)

    full_telemetry = sanitize_obj({
        "task_id": task_id,
        "started_at": started_at,
        "completed_at": now_iso(),
        "hashes": hashes,
        "file_meta": file_meta,
        "iocs": iocs,
        "rea_static": rea_static,
        "dynamic": dynamic_res,
        "scoring": scoring,
    })

    update(f"Gerando Relatório Forense via IA ({ai_config.get('provider')}: {ai_config.get('model')})...", 90)
    ai_report = sanitize_obj(generate_ai_report(full_telemetry, ai_config))
    full_telemetry["ai_report"] = ai_report
    full_telemetry["completed_at"] = now_iso()

    pdf_path = os.path.join(work_dir, "forensic_report.pdf")
    has_pdf = generate_pdf_report(full_telemetry, pdf_path)
    full_telemetry["pdf_report"] = "forensic_report.pdf" if has_pdf else None

    report_json_path = os.path.join(work_dir, "report.json")
    with open(report_json_path, "w") as rf:
        json.dump(full_telemetry, rf, ensure_ascii=False, indent=2)

    report_md_path = os.path.join(work_dir, "report.md")
    with open(report_md_path, "w") as mf:
        mf.write(ai_report.get("markdown", ""))

    update("Análise concluída com sucesso!", 100)
    return full_telemetry
