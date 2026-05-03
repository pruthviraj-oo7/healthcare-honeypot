#!/usr/bin/env python3
"""
=============================================================================
  Log Parser & IoC Extractor
  Healthcare IoT Deception Honeypot Network
  Run: python3 parser/parse_logs.py
=============================================================================
"""

import json, csv, time, argparse, ipaddress
from pathlib import Path
from datetime import datetime
from collections import Counter

BASE_DIR   = Path(__file__).resolve().parent.parent
LOG_FILE   = BASE_DIR / "logs" / "honeypot.json"
CSV_OUT    = BASE_DIR / "logs" / "iocs.csv"
REPORT_OUT = BASE_DIR / "logs" / "threat_report.txt"

# Optional GeoIP — works without it
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

_geo_cache = {}

def geoip(ip):
    if not HAS_REQUESTS or not ip or ip in _geo_cache:
        return _geo_cache.get(ip, {})
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5,
                         params={"fields": "status,country,countryCode,city,lat,lon,isp"})
        d = r.json()
        _geo_cache[ip] = d if d.get("status") == "success" else {}
    except Exception:
        _geo_cache[ip] = {}
    time.sleep(0.1)
    return _geo_cache[ip]

INTERNAL_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]

def is_internal(ip):
    try:
        a = ipaddress.ip_address(ip)
        return any(a in n for n in INTERNAL_NETS)
    except ValueError:
        return False

def parse_log(path):
    if not path.exists():
        print(f"[ERROR] Log not found: {path}")
        print("        Start the honeypot first: python3 honeypot.py")
        print("        Then connect: ssh -p 2222 root@localhost")
        return []
    lines = open(path, encoding="utf-8").readlines()
    print(f"[*] Parsing {len(lines)} log lines from {path.name} ...")
    events, errors = [], 0
    for i, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        try:
            e  = json.loads(line)
            ip = e.get("src_ip", "")
            geo = geoip(ip) if ip and not is_internal(ip) else {}
            events.append({
                "timestamp":    e.get("timestamp", ""),
                "event_id":     e.get("eventid", ""),
                "src_ip":       ip,
                "country":      geo.get("country", "Internal" if is_internal(ip) else "Unknown"),
                "country_code": geo.get("countryCode", ""),
                "city":         geo.get("city", ""),
                "lat":          geo.get("lat", ""),
                "lon":          geo.get("lon", ""),
                "isp":          geo.get("isp", ""),
                "username":     e.get("username", ""),
                "password":     e.get("password", ""),
                "command":      e.get("input", ""),
                "path":         e.get("path", ""),
                "protocol":     e.get("protocol", ""),
                "is_internal":  is_internal(ip),
            })
            if i % 200 == 0:
                print(f"    ... {i}/{len(lines)}")
        except json.JSONDecodeError:
            errors += 1
    if errors:
        print(f"[!] Skipped {errors} malformed lines.")
    print(f"[+] Parsed {len(events)} events.")
    return events

def write_csv(events, path):
    if not events:
        return
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=events[0].keys())
        w.writeheader()
        w.writerows(events)
    print(f"[+] IoC CSV saved → {path}")

def build_report(events):
    if not events:
        return "No events to report."

    ips      = Counter(e["src_ip"]   for e in events if e["src_ip"])
    pws      = Counter(e["password"] for e in events if e["password"])
    users    = Counter(e["username"] for e in events if e["username"])
    cmds     = Counter(e["command"]  for e in events if e["command"])
    cntrs    = Counter(e["country"]  for e in events if e["country"])
    evts     = Counter(e["event_id"] for e in events if e["event_id"])
    internal = [e for e in events if e["is_internal"]]
    ssh_logins  = [e for e in events if e["event_id"] == "honeypot.login.attempt"]
    http_logins = [e for e in events if e["event_id"] == "honeypot.http.login"]
    exploits    = [e for e in events if e["event_id"] == "honeypot.exploit.attempt"]
    malware     = [e for e in events if e["event_id"] == "honeypot.download.attempt"]

    S = "=" * 62
    lines = [
        S,
        "  HEALTHCARE IoT DECEPTION HONEYPOT",
        "  THREAT INTELLIGENCE REPORT",
        f"  Generated : {datetime.now():%Y-%m-%d %H:%M:%S}",
        S, "",
        "  EXECUTIVE SUMMARY",
        f"    Total events captured    : {len(events)}",
        f"    Unique attacker IPs      : {len(ips)}",
        f"    Countries of origin      : {len(cntrs)}",
        f"    SSH login attempts       : {len(ssh_logins)}",
        f"    HTTP login attempts      : {len(http_logins)}",
        f"    Commands executed        : {sum(1 for e in events if e['command'])}",
        f"    Exploit attempts         : {len(exploits)}",
        f"    Malware download URLs    : {len(malware)}",
        f"    Internal IP alerts       : {len(internal)}",
        "", "  EVENT BREAKDOWN:",
    ]
    for ev, n in evts.most_common():
        lines.append(f"    {ev:45s}  x{n}")
    lines += ["", "  TOP ATTACKING COUNTRIES:"]
    for c, n in cntrs.most_common(10):
        lines.append(f"    {c:28s}  {'█'*min(n,35)} {n}")
    lines += ["", "  TOP ATTACKER IPs:"]
    for ip, n in ips.most_common(15):
        lines.append(f"    {ip:20s}  x{n}")
    lines += ["", "  TOP SSH PASSWORDS TRIED:"]
    for pw, n in pws.most_common(20):
        lines.append(f"    {str(pw):35s}  x{n}")
    lines += ["", "  TOP USERNAMES TRIED:"]
    for u, n in users.most_common(15):
        lines.append(f"    {str(u):30s}  x{n}")
    if cmds:
        lines += ["", "  TOP COMMANDS EXECUTED BY ATTACKERS:"]
        for cmd, n in cmds.most_common(15):
            lines.append(f"    {str(cmd)[:55]:57s}  x{n}")
    if exploits:
        lines += ["", "  EXPLOIT ATTEMPTS (paths probed):"]
        paths = Counter(e["path"] for e in exploits if e["path"])
        for p, n in paths.most_common(10):
            lines.append(f"    {p:55s}  x{n}")
    if internal:
        lines += ["", "  *** CRITICAL — INTERNAL IP ALERTS ***",
                  "  These internal IPs connected to the honeypot.",
                  "  A machine inside your network may be COMPROMISED:"]
        for e in internal:
            lines.append(f"    {e['src_ip']:20s}  {e['event_id']}")
    lines += ["", "  HIPAA COMPLIANCE NOTE:",
              "    This honeypot demonstrates proactive threat detection capability",
              "    as required for HIPAA Security Rule compliance (45 CFR §164.306).",
              "    The captured IoCs above can justify network segmentation policies.",
              S]
    return "\n".join(lines)

def main():
    ap = argparse.ArgumentParser(description="Honeypot Log Parser & IoC Extractor")
    ap.add_argument("--log", type=Path, default=LOG_FILE, help="Path to honeypot.json")
    args = ap.parse_args()

    events = parse_log(args.log)
    if not events:
        return

    write_csv(events, CSV_OUT)

    report = build_report(events)
    print("\n" + report)
    REPORT_OUT.write_text(report, encoding="utf-8")
    print(f"\n[+] Report saved → {REPORT_OUT}")
    print(f"[+] CSV saved    → {CSV_OUT}")

if __name__ == "__main__":
    main()
