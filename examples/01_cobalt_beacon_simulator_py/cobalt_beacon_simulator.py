#!/usr/bin/env python3
# Simulated C2 Beacon & Discovery Sample for ANY.RUN REA Sandbox Testing
import os, sys, time, socket, hashlib
C2_URL = "http://198.51.100.200:8443/stage2/beacon.bin"
REG_PERSIST = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"
print("[*] Starting Stage-1 Beacon Simulator...")
print("[*] Checking system identity: Linux sandbox-vm-01 6.12.0-generic x86_64")
print("[*] Probing target C2 endpoint:", C2_URL)
print("[*] Checking /etc/passwd and local environment variables...")
print(" -> Sandbox Host: anyrun-sandbox-node01 (Isolated Network Namespace)")
time.sleep(1)
print("[+] Simulation complete (Safe Canary Sample).")
