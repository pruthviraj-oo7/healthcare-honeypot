#!/usr/bin/env python3
"""
=============================================================================
  Honeypot Threat Intelligence Dashboard
  Reads: logs/honeypot.json
  URL:   http://localhost:8000
  Run:   python3 dashboard/app.py
=============================================================================
"""

import json
import ipaddress
from pathlib import Path
from datetime import datetime
from collections import Counter
from flask import Flask, render_template_string, jsonify

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "logs" / "honeypot.json"

INTERNAL_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]

def is_internal(ip):
    try:
        return any(ipaddress.ip_address(ip) in n for n in INTERNAL_NETS)
    except Exception:
        return False

def parse_logs():
    if not LOG_FILE.exists():
        return [], False, str(LOG_FILE)
    if LOG_FILE.stat().st_size == 0:
        return [], True, str(LOG_FILE)
    events = []
    with open(LOG_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return events, True, str(LOG_FILE)

def get_stats():
    events, log_exists, log_path = parse_logs()

    empty = dict(
        total=0, unique_ips=0, ssh_logins=0, http_logins=0,
        commands_run=0, exploit_attempts=0, internal_alerts=0,
        malware_attempts=0, top_ips=[], top_ssh_passwords=[],
        top_http_passwords=[], top_usernames=[], top_commands=[],
        event_types=[], recent=[], internal_hits=[],
        log_path=log_path, log_exists=log_exists, has_events=False,
    )
    if not events:
        return empty

    ips           = Counter(e.get("src_ip","")   for e in events if e.get("src_ip"))
    ssh_pws       = Counter(e.get("password","") for e in events
                            if e.get("eventid") == "honeypot.login.attempt" and e.get("password"))
    http_pws      = Counter(e.get("password","") for e in events
                            if e.get("eventid") == "honeypot.http.login" and e.get("password"))
    usernames     = Counter(e.get("username","") for e in events if e.get("username"))
    commands      = Counter(e.get("input","")    for e in events if e.get("input"))
    evt_types     = Counter(e.get("eventid","")  for e in events if e.get("eventid"))
    ssh_logins    = [e for e in events if e.get("eventid") == "honeypot.login.attempt"]
    http_logins   = [e for e in events if e.get("eventid") == "honeypot.http.login"]
    exploits      = [e for e in events if e.get("eventid") == "honeypot.exploit.attempt"]
    malware       = [e for e in events if e.get("eventid") == "honeypot.download.attempt"]
    internal      = [e for e in events if is_internal(e.get("src_ip",""))]
    cmd_events    = [e for e in events if e.get("input")]

    recent = []
    for e in list(reversed(events))[:100]:
        eid = e.get("eventid","")
        recent.append({
            "time":     e.get("timestamp","")[:19].replace("T"," "),
            "ip":       e.get("src_ip","—"),
            "proto":    "SSH" if "login.attempt" in eid or "command" in eid or "session" in eid
                        else "HTTP" if "http" in eid
                        else "?",
            "event":    eid.replace("honeypot.",""),
            "user":     e.get("username","—"),
            "password": e.get("password","—"),
            "detail":   e.get("input") or e.get("path") or e.get("error") or "—",
        })

    return dict(
        total=len(events),
        unique_ips=len(ips),
        ssh_logins=len(ssh_logins),
        http_logins=len(http_logins),
        commands_run=len(cmd_events),
        exploit_attempts=len(exploits),
        internal_alerts=len(internal),
        malware_attempts=len(malware),
        top_ips=ips.most_common(12),
        top_ssh_passwords=ssh_pws.most_common(15),
        top_http_passwords=http_pws.most_common(10),
        top_usernames=usernames.most_common(12),
        top_commands=[(c[:60],n) for c,n in commands.most_common(12)],
        event_types=evt_types.most_common(),
        recent=recent[:60],
        internal_hits=[{"ip":e.get("src_ip"),"event":e.get("eventid")} for e in internal[:5]],
        log_path=log_path,
        log_exists=log_exists,
        has_events=True,
    )

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Honeypot Dashboard</title>
<style>
:root{--bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--border:#30363d;--text:#e6edf3;
--muted:#8b949e;--blue:#58a6ff;--green:#3fb950;--red:#f85149;--orange:#d29922;
--purple:#bc8cff;--teal:#39d353;--cyan:#79c0ff;}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:14px}
a{color:var(--blue)}
code{background:var(--bg3);padding:2px 8px;border-radius:4px;font-size:12px;font-family:monospace;color:var(--cyan)}

/* top bar */
.topbar{background:var(--bg2);border-bottom:1px solid var(--border);padding:14px 24px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px}
.topbar h1{font-size:15px;font-weight:600;color:var(--blue)}
.topbar .sub{font-size:11px;color:var(--muted);margin-top:3px}
.tr{display:flex;align-items:center;gap:10px}
.live{display:flex;align-items:center;gap:6px;background:var(--bg3);border:1px solid var(--border);border-radius:20px;padding:5px 12px;font-size:12px;color:var(--green)}
.dot{width:7px;height:7px;border-radius:50%;background:var(--green);animation:blink 2s infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.2}}
.rbtn{background:var(--blue);color:#000;border:none;border-radius:6px;padding:7px 16px;font-size:12px;font-weight:700;cursor:pointer}
.rbtn:hover{opacity:.85}
#cd{font-size:11px;color:var(--muted)}

/* info bar */
.info{background:#0d1f33;border:1px solid #2a5a8a;border-radius:8px;padding:12px 16px;margin:14px 24px 0;font-size:13px;color:#8ab8e0;display:flex;gap:10px;align-items:flex-start}

/* alert */
.alert{background:#2d1a1a;border:1px solid var(--red);border-radius:8px;padding:14px 16px;margin:10px 24px 0;font-size:13px;color:var(--red)}

/* empty state */
.empty-state{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:40px;margin:20px 24px;text-align:center}
.empty-state .icon{font-size:40px;margin-bottom:12px}
.empty-state p{color:var(--muted);margin-bottom:8px;line-height:1.6}

/* content */
.content{padding:16px 24px;max-width:1400px;margin:0 auto}

/* stat cards */
.sgrid{display:grid;grid-template-columns:repeat(8,1fr);gap:10px;margin-bottom:16px}
.scard{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:12px}
.scard .lbl{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.07em;margin-bottom:6px}
.scard .val{font-size:22px;font-weight:700}
.cb{color:var(--blue)}.cg{color:var(--green)}.cr{color:var(--red)}
.co{color:var(--orange)}.cp{color:var(--purple)}.ct{color:var(--teal)}.cc{color:var(--cyan)}

/* grid layouts */
.g2{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px}
.g3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:12px}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:16px}
.card h2{font-size:10px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:14px}

/* bar rows */
.br{display:flex;align-items:center;gap:8px;margin-bottom:8px}
.bl{width:140px;font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex-shrink:0}
.bk{flex:1;height:5px;background:var(--bg3);border-radius:3px;overflow:hidden}
.bf{height:100%;border-radius:3px}
.bb{background:var(--blue)}.bo{background:var(--orange)}.bg{background:var(--green)}
.bpp{background:var(--purple)}.bc{background:var(--cyan)}
.bn{font-size:11px;color:var(--muted);width:30px;text-align:right;flex-shrink:0}
.no-data{color:var(--muted);font-size:12px;text-align:center;padding:20px 0}

/* table */
.tw{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;color:var(--muted);font-weight:500;padding:6px 8px;border-bottom:1px solid var(--border);font-size:10px;text-transform:uppercase;letter-spacing:.04em;white-space:nowrap}
td{padding:7px 8px;border-bottom:1px solid var(--border);max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
tr:last-child td{border-bottom:none}
tr:hover td{background:var(--bg3)}

/* badges */
.badge{display:inline-block;padding:2px 8px;border-radius:20px;font-size:10px;font-weight:600}
.bssh{background:#1a2a3a;color:var(--cyan)}
.bhttp{background:#2a1a3a;color:var(--purple)}
.bok{background:#1a3a1a;color:var(--green)}
.bfail{background:#3a1a1a;color:var(--red)}
.bcmd{background:#1a2a2a;color:var(--blue)}
.bexp{background:#3a2a1a;color:var(--orange)}
.bother{background:var(--bg3);color:var(--muted)}

/* proto tag */
.proto-ssh{background:#1a2a3a;color:var(--cyan);padding:2px 6px;border-radius:4px;font-size:10px;font-weight:600}
.proto-http{background:#2a1a3a;color:var(--purple);padding:2px 6px;border-radius:4px;font-size:10px;font-weight:600}
.proto-q{background:var(--bg3);color:var(--muted);padding:2px 6px;border-radius:4px;font-size:10px}

.footer{text-align:center;color:var(--muted);font-size:11px;padding:24px}
@media(max-width:1100px){.sgrid{grid-template-columns:repeat(4,1fr)}.g2,.g3{grid-template-columns:1fr}}
</style>
</head>
<body>

<div class="topbar">
  <div>
    <h1>🛡 Healthcare IoT Honeypot — Threat Intelligence Dashboard</h1>
    <div class="sub">Device: <strong>GE-VitalMonitor-ICU-01</strong> &nbsp;·&nbsp; Updated: {{ now }}</div>
  </div>
  <div class="tr">
    <span id="cd"></span>
    <div class="live"><div class="dot"></div>LIVE</div>
    <button class="rbtn" onclick="location.reload()">↻ Refresh</button>
  </div>
</div>

<div class="info">
  <span>ℹ️</span>
  <div>
    <strong>How this works:</strong>
    The honeypot accepts <strong>any username and password</strong> on purpose — this traps attackers inside a fake medical device shell so we can record every command, download attempt, and exploit technique they use. All activity is logged and shown below in real time.
  </div>
</div>

{% if s.internal_alerts > 0 %}
<div class="alert">
  🚨 <strong>CRITICAL — INTERNAL IP ALERT:</strong>
  {{ s.internal_alerts }} internal IP(s) connected to the honeypot — possible compromised machine inside your network.<br>
  {% for h in s.internal_hits %}&nbsp;&nbsp;IP: <strong>{{ h.ip }}</strong> &nbsp;→&nbsp; {{ h.event }}<br>{% endfor %}
</div>
{% endif %}

{% if not s.has_events %}
<div class="empty-state">
  <div class="icon">{% if not s.log_exists %}📂{% else %}⏳{% endif %}</div>
  <p style="font-size:16px;font-weight:600;color:var(--text);margin-bottom:12px">
    {% if not s.log_exists %}Log file not found yet{% else %}No events captured yet{% endif %}
  </p>
  <p>The honeypot is running. Generate your first event by opening a new terminal and running:</p>
  <p style="margin:12px 0"><code>ssh -p 2222 root@localhost</code></p>
  <p>Type <strong>any password</strong> when prompted, then press Enter.</p>
  <p style="margin-top:8px">Or open the fake web panel: <a href="http://localhost:8888" target="_blank">http://localhost:8888</a></p>
  <p style="margin-top:16px;font-size:11px;color:var(--muted)">Log file: {{ s.log_path }}</p>
  <p style="margin-top:8px"><button class="rbtn" onclick="location.reload()">↻ Check for events</button></p>
</div>
{% endif %}

{% if s.has_events %}
<div class="content">

<!-- Stat cards -->
<div class="sgrid">
  <div class="scard"><div class="lbl">Total Events</div><div class="val cb">{{ s.total }}</div></div>
  <div class="scard"><div class="lbl">Unique IPs</div><div class="val co">{{ s.unique_ips }}</div></div>
  <div class="scard"><div class="lbl">SSH Logins</div><div class="val cc">{{ s.ssh_logins }}</div></div>
  <div class="scard"><div class="lbl">HTTP Logins</div><div class="val cp">{{ s.http_logins }}</div></div>
  <div class="scard"><div class="lbl">Commands Run</div><div class="val cb">{{ s.commands_run }}</div></div>
  <div class="scard"><div class="lbl">Exploit Attempts</div><div class="val co">{{ s.exploit_attempts }}</div></div>
  <div class="scard"><div class="lbl">Malware DLs</div><div class="val cp">{{ s.malware_attempts }}</div></div>
  <div class="scard"><div class="lbl">Internal Alerts</div>
    <div class="val {% if s.internal_alerts > 0 %}cr{% else %}ct{% endif %}">{{ s.internal_alerts }}</div></div>
</div>

<!-- Top IPs + SSH Passwords -->
<div class="g2">
  <div class="card">
    <h2>Top Attacking IPs</h2>
    {% if s.top_ips %}{% set mx=s.top_ips[0][1] %}
    {% for ip,n in s.top_ips %}
    <div class="br"><span class="bl">{{ ip }}</span>
    <div class="bk"><div class="bf bb" style="width:{{ (n/mx*100)|int }}%"></div></div>
    <span class="bn">{{ n }}</span></div>
    {% endfor %}
    {% else %}<div class="no-data">No data yet</div>{% endif %}
  </div>
  <div class="card">
    <h2>Top SSH Passwords Tried &nbsp;<span style="font-weight:400;font-size:9px">(all accepted — logged for intel)</span></h2>
    {% if s.top_ssh_passwords %}{% set mx=s.top_ssh_passwords[0][1] %}
    {% for pw,n in s.top_ssh_passwords %}
    <div class="br"><span class="bl">{{ pw if pw else '(empty)' }}</span>
    <div class="bk"><div class="bf bo" style="width:{{ (n/mx*100)|int }}%"></div></div>
    <span class="bn">{{ n }}</span></div>
    {% endfor %}
    {% else %}<div class="no-data">No SSH attempts yet</div>{% endif %}
  </div>
</div>

<!-- Usernames + Commands + Event types -->
<div class="g3">
  <div class="card">
    <h2>Top Usernames Tried</h2>
    {% if s.top_usernames %}{% set mx=s.top_usernames[0][1] %}
    {% for u,n in s.top_usernames %}
    <div class="br"><span class="bl">{{ u if u else '(empty)' }}</span>
    <div class="bk"><div class="bf bg" style="width:{{ (n/mx*100)|int }}%"></div></div>
    <span class="bn">{{ n }}</span></div>
    {% endfor %}
    {% else %}<div class="no-data">No data yet</div>{% endif %}
  </div>
  <div class="card">
    <h2>Commands Run by Attackers</h2>
    {% if s.top_commands %}{% set mx=s.top_commands[0][1] %}
    {% for cmd,n in s.top_commands %}
    <div class="br"><span class="bl" title="{{ cmd }}">{{ cmd }}</span>
    <div class="bk"><div class="bf bpp" style="width:{{ (n/mx*100)|int }}%"></div></div>
    <span class="bn">{{ n }}</span></div>
    {% endfor %}
    {% else %}<div class="no-data">No commands yet<br><small>Login via SSH and run: ls, whoami, ps aux</small></div>{% endif %}
  </div>
  <div class="card">
    <h2>Event Breakdown</h2>
    {% if s.event_types %}{% set mx=s.event_types[0][1] %}
    {% for ev,n in s.event_types %}
    <div class="br"><span class="bl">{{ ev.replace('honeypot.','') }}</span>
    <div class="bk"><div class="bf bc" style="width:{{ (n/mx*100)|int }}%"></div></div>
    <span class="bn">{{ n }}</span></div>
    {% endfor %}
    {% else %}<div class="no-data">No events</div>{% endif %}
  </div>
</div>

{% if s.top_http_passwords %}
<div class="g2" style="margin-bottom:12px">
  <div class="card">
    <h2>HTTP Web Panel Passwords Tried</h2>
    {% set mx=s.top_http_passwords[0][1] %}
    {% for pw,n in s.top_http_passwords %}
    <div class="br"><span class="bl">{{ pw if pw else '(empty)' }}</span>
    <div class="bk"><div class="bf bpp" style="width:{{ (n/mx*100)|int }}%"></div></div>
    <span class="bn">{{ n }}</span></div>
    {% endfor %}
  </div>
  <div class="card">
    <h2>Quick Actions</h2>
    <p style="color:var(--muted);font-size:12px;margin-bottom:12px">Useful commands for deeper analysis:</p>
    <p style="margin-bottom:8px;font-size:12px">Generate threat report:</p>
    <p style="margin-bottom:12px"><code>python3 parser/parse_logs.py</code></p>
    <p style="margin-bottom:8px;font-size:12px">Watch live log:</p>
    <p style="margin-bottom:12px"><code>tail -f logs/honeypot.json</code></p>
    <p style="margin-bottom:8px;font-size:12px">Check internal alerts:</p>
    <p><code>python3 parser/alert_internal.py</code></p>
  </div>
</div>
{% endif %}

<!-- Live feed table -->
<div class="card" style="margin-bottom:24px">
  <h2>Live Attack Feed — Recent Events</h2>
  <div class="tw"><table>
    <thead><tr>
      <th>Time</th><th>Attacker IP</th><th>Proto</th><th>Event</th>
      <th>Username</th><th>Password</th><th>Detail</th>
    </tr></thead>
    <tbody>
    {% for e in s.recent %}
    <tr>
      <td style="color:var(--muted);white-space:nowrap">{{ e.time }}</td>
      <td><strong style="color:var(--text)">{{ e.ip }}</strong></td>
      <td>
        {% if e.proto == 'SSH' %}<span class="proto-ssh">SSH</span>
        {% elif e.proto == 'HTTP' %}<span class="proto-http">HTTP</span>
        {% else %}<span class="proto-q">?</span>{% endif %}
      </td>
      <td>
        {% set ev = e.event %}
        {% if 'login.attempt' in ev or 'login.success' in ev %}<span class="badge bok">✓ login</span>
        {% elif 'login' in ev and 'http' in ev %}<span class="badge bok">✓ http login</span>
        {% elif 'command' in ev %}<span class="badge bcmd">$ cmd</span>
        {% elif 'exploit' in ev %}<span class="badge bexp">⚡ exploit</span>
        {% elif 'download' in ev %}<span class="badge bexp">↓ download</span>
        {% elif 'connect' in ev %}<span class="badge bother">→ connect</span>
        {% elif 'closed' in ev %}<span class="badge bother">✗ closed</span>
        {% else %}<span class="badge bother">{{ ev }}</span>{% endif %}
      </td>
      <td>{{ e.user }}</td>
      <td style="color:var(--orange)">{{ e.password }}</td>
      <td style="font-family:monospace;font-size:11px;color:var(--blue)">{{ e.detail }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table></div>
</div>

</div>
{% endif %}

<div class="footer">
  Healthcare IoT Deception Honeypot &nbsp;·&nbsp; GE-VitalMonitor-ICU-01 &nbsp;·&nbsp;
  Log: <code>{{ s.log_path }}</code>
</div>

<script>
let s=30;const el=document.getElementById('cd');
setInterval(()=>{s--;if(s<=0)location.reload();el.textContent='Refreshing in '+s+'s  ';},1000);
</script>
</body></html>"""

@app.route("/")
def index():
    return render_template_string(HTML, s=get_stats(),
                                  now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

@app.route("/api/stats")
def api_stats():
    stats = get_stats()
    for k in ["top_ips","top_ssh_passwords","top_http_passwords",
              "top_usernames","top_commands","event_types"]:
        stats[k] = [list(x) for x in stats[k]]
    return jsonify(stats)

@app.route("/health")
def health():
    return jsonify({"status":"ok","log":str(LOG_FILE),"exists":LOG_FILE.exists()})

if __name__ == "__main__":
    print(f"\n{'='*55}")
    print(f"  Honeypot Dashboard")
    print(f"  Log file : {LOG_FILE}")
    print(f"  Exists   : {LOG_FILE.exists()}")
    if LOG_FILE.exists():
        print(f"  Size     : {LOG_FILE.stat().st_size} bytes")
    print(f"  URL      : http://localhost:8000")
    print(f"{'='*55}\n")
    app.run(host="0.0.0.0", port=8000, debug=False)
