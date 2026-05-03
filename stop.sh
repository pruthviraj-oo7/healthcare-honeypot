#!/bin/bash
# Stop all honeypot processes
pkill -f "honeypot.py"   2>/dev/null && echo "[+] Honeypot stopped." || echo "[!] Honeypot was not running."
pkill -f "dashboard/app" 2>/dev/null && echo "[+] Dashboard stopped." || echo "[!] Dashboard was not running."
echo "[+] All stopped."
