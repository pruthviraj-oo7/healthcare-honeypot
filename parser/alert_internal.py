#!/usr/bin/env python3
"""
Internal Lateral Movement Detector
Alerts when internal RFC-1918 IPs connect to the honeypot.
Cron: */5 * * * * python3 /path/to/parser/alert_internal.py >> /path/to/logs/cron.log 2>&1
"""

import json, ipaddress, os, smtplib
from pathlib import Path
from datetime import datetime
from email.mime.text import MIMEText

BASE_DIR  = Path(__file__).resolve().parent.parent
LOG_FILE  = BASE_DIR / "logs" / "honeypot.json"
ALERT_LOG = BASE_DIR / "logs" / "internal_alerts.log"
SEEN_FILE = BASE_DIR / "logs" / ".seen_sessions"

NETS = [ipaddress.ip_network(n) for n in
        ["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8"]]

SMTP_HOST = os.getenv("SMTP_HOST","")
SMTP_PORT = int(os.getenv("SMTP_PORT","587"))
SMTP_USER = os.getenv("SMTP_USER","")
SMTP_PASS = os.getenv("SMTP_PASS","")
ALERT_TO  = os.getenv("ALERT_EMAIL","")

def is_internal(ip):
    try:
        a = ipaddress.ip_address(ip)
        return any(a in n for n in NETS)
    except ValueError:
        return False

def load_seen():
    return set(SEEN_FILE.read_text().splitlines()) if SEEN_FILE.exists() else set()

def save_seen(s):
    SEEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    SEEN_FILE.write_text("\n".join(s))

def send_email(alerts):
    if not all([SMTP_HOST, SMTP_USER, SMTP_PASS, ALERT_TO]):
        return
    try:
        msg = MIMEText("\n".join(alerts))
        msg["Subject"] = f"[HONEYPOT ALERT] {len(alerts)} Internal IP(s) Detected"
        msg["From"] = SMTP_USER; msg["To"] = ALERT_TO
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            s.starttls(); s.login(SMTP_USER, SMTP_PASS)
            s.sendmail(SMTP_USER, [ALERT_TO], msg.as_string())
        print(f"[+] Email sent to {ALERT_TO}")
    except Exception as ex:
        print(f"[!] Email failed: {ex}")

def main():
    if not LOG_FILE.exists():
        print(f"[!] Log not found: {LOG_FILE}"); return

    seen, new_seen, alerts = load_seen(), set(), []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(LOG_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                e  = json.loads(line)
                ip = e.get("src_ip","")
                ts = e.get("timestamp","")
                if not ip or not is_internal(ip): continue
                key = f"{ip}:{ts}"
                if key in seen: continue
                new_seen.add(key)
                alerts.append(
                    f"[{now}] *** INTERNAL PIVOT DETECTED ***\n"
                    f"  IP      : {ip}\n"
                    f"  Event   : {e.get('eventid','N/A')}\n"
                    f"  User    : {e.get('username','N/A')}\n"
                    f"  Pass    : {e.get('password','N/A')}\n"
                    f"  Detail  : {e.get('input') or e.get('path','N/A')}\n"
                    f"  Time    : {ts}\n"
                    f"{'-'*50}"
                )
            except json.JSONDecodeError:
                pass

    if alerts:
        print(f"\n{'!'*50}")
        print(f"  CRITICAL: {len(alerts)} INTERNAL IP ALERT(S)")
        print(f"{'!'*50}")
        for a in alerts: print(a)
        ALERT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(ALERT_LOG, "a") as f: f.write("\n".join(alerts)+"\n")
        print(f"[+] Alerts written → {ALERT_LOG}")
        send_email(alerts)
        seen.update(new_seen); save_seen(seen)
    else:
        print(f"[{now}] OK — No internal IPs detected. Network is clean.")

if __name__ == "__main__":
    main()
