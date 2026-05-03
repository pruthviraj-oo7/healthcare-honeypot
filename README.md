# Healthcare IoT Deception Honeypot Network

Proactive threat intelligence platform simulating a **GE Healthcare Patient Monitor** to lure, trap, and analyse attackers — with a live threat dashboard.

## Architecture

```
Attacker (Internet)
      │
      ├──→ Port 2222  (Fake SSH server)
      │       accepts any password, logs all commands
      │
      └──→ Port 8888  (Fake HTTP Admin Panel)
              logs all login attempts & exploit probes
                    │
                    ▼
           logs/honeypot.json
                    │
         ┌──────────┴──────────┐
         ▼                     ▼
  parse_logs.py         alert_internal.py
  (IoC extraction)      (lateral movement)
         │
         ▼
  Dashboard → http://localhost:8000
```

## Tech Stack

| Component | Technology |
|-----------|-----------|
| SSH Honeypot | Python + paramiko |
| HTTP Honeypot | Python sockets |
| Dashboard | Python Flask |
| Log Analysis | Python (built-in) |
| GeoIP | ip-api.com (free) |

## Quick Start

```bash
git clone https://git clone https://github.com/pruthviraj-oo7/honeypot-project.git
cd honeypot-project
sudo bash setup.sh
```

## Manual Start (after setup)

```bash
bash start.sh
```

## Ports

| Port | Purpose |
|------|---------|
| 2222 | Fake SSH honeypot |
| 8888 | Fake HTTP admin panel |
| 8000 | Threat intelligence dashboard |
| 2244 | Real SSH (your machine) |

## Weekly Roadmap

### Week 1 — Setup
```bash
sudo bash setup.sh
# Verify: ssh -p 2222 root@localhost  (any password)
# Open: http://localhost:8000
```

### Week 2 — Capture
```bash
# Watch live logs
tail -f logs/honeypot.json
# Fake web panel
curl http://localhost:8888
# Open dashboard
xdg-open http://localhost:8000
```

### Week 3 — Analysis
```bash
python3 parser/parse_logs.py        # full IoC report + CSV
python3 parser/alert_internal.py    # check for compromised machines
# Add cron for auto-alerts:
crontab -e
# Add: */5 * * * * python3 /path/to/parser/alert_internal.py >> /path/to/logs/cron.log 2>&1
```

### Week 4 — Dashboard + GitHub
```bash
# Dashboard already at http://localhost:8000
git add .
git commit -m "Week 4: Complete honeypot with dashboard"
git push origin main
```

## Daily Commands

```bash
bash start.sh                          # start everything
bash stop.sh                           # stop everything
tail -f logs/honeypot.json            # live attack stream
python3 parser/parse_logs.py          # threat report
python3 parser/alert_internal.py      # internal alert check
cat logs/threat_report.txt            # view saved report
```

## Security Notes

- Real attack logs are git-ignored — never commit them
- The honeypot runs on your machine, isolated by Python (no Docker needed)
- Tested on Ubuntu 20.04, 22.04, 24.04, 25.x
