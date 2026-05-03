#!/usr/bin/env python3
"""
=============================================================================
  Healthcare IoT Deception Honeypot
  Simulates: GE Healthcare Patient Monitor (SSH + HTTP web panel)

  Listens on:
    - Port 2222  -> Fake SSH server (logs all login attempts + commands)
    - Port 8888  -> Fake HTTP admin panel (logs all requests)

  Logs everything to: logs/honeypot.json
  Run: python3 honeypot.py
=============================================================================
"""

import socket
import threading
import json
import os
import sys
import time
import logging
import subprocess
import ipaddress
from pathlib import Path
from datetime import datetime, timezone

# ── Install paramiko automatically if missing ─────────────────────────────────
def install_paramiko():
    print("[*] paramiko not found — installing automatically...")
    cmds = [
        [sys.executable, "-m", "pip", "install", "paramiko", "--break-system-packages", "-q"],
        [sys.executable, "-m", "pip", "install", "paramiko", "-q"],
        ["pip3", "install", "paramiko", "--break-system-packages", "-q"],
        ["pip3", "install", "paramiko", "-q"],
    ]
    for cmd in cmds:
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=60)
            if result.returncode == 0:
                print("[+] paramiko installed successfully.")
                return True
        except Exception:
            continue
    print("[!] paramiko auto-install failed. Run manually: pip3 install paramiko")
    return False

try:
    import paramiko
except ImportError:
    if install_paramiko():
        try:
            import paramiko
        except ImportError:
            paramiko = None
    else:
        paramiko = None

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent
LOG_DIR  = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / "honeypot.json"
LOG_DIR.mkdir(exist_ok=True)

# ── Logger ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("honeypot")

# ── Device identity ───────────────────────────────────────────────────────────
DEVICE_NAME   = "GE-VitalMonitor-ICU-01"
SSH_BANNER    = "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"
FAKE_HOSTNAME = "ge-patient-monitor"
FAKE_MOTD     = (
    "\r\n"
    "GE Healthcare Dash 3000+ Patient Monitor\r\n"
    "Firmware v2.1.4 | ICU Unit 01\r\n"
    "WARNING: Authorized access only\r\n\r\n"
)

# ── Fake command responses ────────────────────────────────────────────────────
FAKE_COMMANDS = {
    "ls":               "bin  dev  etc  home  lib  proc  root  sys  tmp  usr  var",
    "ls -la":           "total 64\r\ndrwxr-xr-x  2 root root 4096 .\r\ndrwxr-xr-x 18 root root 4096 ..\r\n-rw-r--r--  1 root root  220 .bash_logout",
    "whoami":           "root",
    "id":               "uid=0(root) gid=0(root) groups=0(root)",
    "uname -a":         "Linux ge-patient-monitor 3.10.0-1127.el7.x86_64 #1 SMP x86_64 GNU/Linux",
    "uname":            "Linux",
    "pwd":              "/root",
    "cat /etc/passwd":  "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nge-monitor:x:1000:1000::/home/ge-monitor:/bin/bash",
    "cat /etc/shadow":  "cat: /etc/shadow: Permission denied",
    "ps":               "  PID TTY          TIME CMD\r\n    1 ?        00:00:01 systemd\r\n  412 ?        00:00:00 ge-monitord",
    "ps aux":           "USER  PID %CPU %MEM COMMAND\r\nroot    1  0.0  0.1 /sbin/init\r\nroot  412  0.0  0.0 ge-monitord",
    "netstat -an":      "tcp  0  0 0.0.0.0:22   0.0.0.0:*  LISTEN\r\ntcp  0  0 0.0.0.0:80   0.0.0.0:*  LISTEN",
    "ifconfig":         "eth0  inet 192.168.1.50  netmask 255.255.255.0",
    "ip addr":          "2: eth0: inet 192.168.1.50/24",
    "df -h":            "Filesystem  Size  Used  Avail  Use%\r\n/dev/sda1    30G   4.2G   24G   15%  /",
    "free -m":          "       total  used  free\r\nMem:   1024   412   612",
    "env":              "PATH=/usr/local/sbin:/usr/bin:/sbin:/bin\r\nHOME=/root\r\nSHELL=/bin/bash",
    "history":          "    1  ls\r\n    2  cat /etc/passwd\r\n    3  uname -a",
    "uptime":           " 00:00:01 up 42 days,  3:22,  1 user,  load average: 0.00",
    "date":             datetime.now().strftime("%a %b %d %H:%M:%S UTC %Y"),
    "w":                "USER  TTY  FROM  LOGIN@  IDLE  WHAT\r\nroot  pts/0  attacker  00:00  0.00s  w",
    "exit":             "__EXIT__",
    "logout":           "__EXIT__",
    "quit":             "__EXIT__",
}

# ── Write event to log ────────────────────────────────────────────────────────
_log_lock = threading.Lock()

def write_event(event_type, src_ip, src_port, **kwargs):
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "eventid":   event_type,
        "src_ip":    src_ip,
        "src_port":  src_port,
        "sensor":    DEVICE_NAME,
    }
    event.update(kwargs)
    with _log_lock:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
    log.info(f"[{event_type}] {src_ip}:{src_port}  {kwargs}")

# =============================================================================
#  SSH HONEYPOT — only defined if paramiko is available
# =============================================================================

if paramiko is not None:

    class FakeSSHServer(paramiko.ServerInterface):
        """Accept every login, log every credential."""

        def __init__(self, src_ip, src_port):
            self.src_ip   = src_ip
            self.src_port = src_port
            self.username = ""
            self.password = ""
            self.event    = threading.Event()

        def check_channel_request(self, kind, chanid):
            if kind == "session":
                return paramiko.OPEN_SUCCEEDED
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

        def check_auth_password(self, username, password):
            self.username = username
            self.password = password
            write_event("honeypot.login.attempt", self.src_ip, self.src_port,
                        username=username, password=password)
            return paramiko.AUTH_SUCCESSFUL   # accept everything

        def check_auth_publickey(self, username, key):
            return paramiko.AUTH_FAILED

        def get_allowed_auths(self, username):
            return "password"

        def check_channel_shell_request(self, channel):
            self.event.set()
            return True

        def check_channel_pty_request(self, channel, term, width, height,
                                      pixelwidth, pixelheight, modes):
            return True

        def check_channel_exec_request(self, channel, command):
            return True

    def _get_host_key():
        key_path = LOG_DIR / ".host_key"
        if key_path.exists():
            return paramiko.RSAKey(filename=str(key_path))
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(str(key_path))
        return key

    def _run_fake_shell(channel, src_ip, src_port, username, password):
        write_event("honeypot.login.success", src_ip, src_port,
                    username=username, password=password)
        channel.send(FAKE_MOTD.encode())
        channel.send(f"{FAKE_HOSTNAME}:~# ".encode())
        buf = ""
        try:
            while True:
                channel.settimeout(60.0)
                try:
                    data = channel.recv(1024)
                except socket.timeout:
                    break
                if not data:
                    break
                for byte in data.decode("utf-8", errors="ignore"):
                    if byte in ("\r", "\n"):
                        cmd = buf.strip()
                        buf = ""
                        channel.send(b"\r\n")
                        if not cmd:
                            channel.send(f"{FAKE_HOSTNAME}:~# ".encode())
                            continue
                        write_event("honeypot.command.input", src_ip, src_port,
                                    username=username, input=cmd)
                        if any(x in cmd for x in ["wget", "curl", "tftp", "ftp", "chmod", "bash -i"]):
                            write_event("honeypot.download.attempt", src_ip, src_port,
                                        username=username, input=cmd)
                        response = FAKE_COMMANDS.get(cmd, f"bash: {cmd}: command not found")
                        if response == "__EXIT__":
                            channel.send(b"logout\r\n")
                            break
                        channel.send((response + "\r\n").encode())
                        channel.send(f"{FAKE_HOSTNAME}:~# ".encode())
                    elif byte == "\x7f":
                        if buf:
                            buf = buf[:-1]
                            channel.send(b"\x08 \x08")
                    else:
                        buf += byte
                        channel.send(byte.encode())
        except Exception:
            pass
        finally:
            write_event("honeypot.session.closed", src_ip, src_port, username=username)
            try:
                channel.close()
            except Exception:
                pass

    def _handle_ssh_conn(client_socket, src_ip, src_port, host_key):
        write_event("honeypot.connect", src_ip, src_port, protocol="ssh")
        try:
            transport = paramiko.Transport(client_socket)
            transport.local_version = SSH_BANNER
            transport.add_server_key(host_key)
            server = FakeSSHServer(src_ip, src_port)
            transport.start_server(server=server)
            channel = transport.accept(20)
            if channel is None:
                return
            server.event.wait(10)
            _run_fake_shell(channel, src_ip, src_port, server.username, server.password)
        except Exception as e:
            write_event("honeypot.error", src_ip, src_port, error=str(e), protocol="ssh")
        finally:
            try:
                client_socket.close()
            except Exception:
                pass

    def start_ssh_honeypot(port=2222):
        host_key   = _get_host_key()
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server_sock.bind(("0.0.0.0", port))
        except OSError as e:
            log.error(f"Cannot bind SSH on port {port}: {e}")
            log.error("Try: sudo fuser -k 2222/tcp")
            return
        server_sock.listen(10)
        log.info(f"[SSH Honeypot] Listening on port {port}")
        while True:
            try:
                client, addr = server_sock.accept()
                t = threading.Thread(
                    target=_handle_ssh_conn,
                    args=(client, addr[0], addr[1], host_key),
                    daemon=True,
                )
                t.start()
            except Exception as e:
                log.error(f"SSH accept error: {e}")

else:
    def start_ssh_honeypot(port=2222):
        log.error("SSH honeypot disabled — paramiko not available.")
        log.error("Run: pip3 install paramiko")

# =============================================================================
#  HTTP HONEYPOT
# =============================================================================

_HTTP_HEADER_OK = (
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html\r\n"
    "Server: GE-WebServer/1.0\r\n"
    "Connection: close\r\n\r\n"
)

_HTTP_BODY = (
    "<!DOCTYPE html><html><head><title>GE Healthcare Patient Monitor - Admin</title>"
    "<style>body{font-family:Arial,sans-serif;background:#1a1a2e;color:#eee;margin:0}"
    ".header{background:#16213e;padding:20px;border-bottom:2px solid #e94560}"
    "h1{color:#e94560;margin:0}.content{padding:30px;max-width:600px;margin:auto}"
    ".fg{margin:15px 0}label{display:block;margin-bottom:5px;color:#a8a8b3}"
    "input{width:100%;padding:10px;background:#16213e;border:1px solid #444;color:#eee;border-radius:4px}"
    "button{background:#e94560;color:#fff;border:none;padding:12px 30px;border-radius:4px;cursor:pointer;font-size:16px;margin-top:10px}"
    ".warn{background:#2d1a1a;border:1px solid #e94560;padding:15px;border-radius:4px;margin-bottom:20px;font-size:13px}"
    "</style></head><body>"
    "<div class='header'><h1>GE Healthcare -- Dash 3000+ Patient Monitor</h1>"
    "<small>ICU Unit 01 | Firmware v2.1.4 | Remote Administration</small></div>"
    "<div class='content'>"
    "<div class='warn'>WARNING: Authorized personnel only. All access is logged.</div>"
    "<h2>Administrator Login</h2>"
    "<form method='POST' action='/login'>"
    "<div class='fg'><label>Username</label><input type='text' name='username' placeholder='admin'></div>"
    "<div class='fg'><label>Password</label><input type='password' name='password'></div>"
    "<button type='submit'>Login</button></form></div></body></html>"
)

HTTP_INDEX = (_HTTP_HEADER_OK + _HTTP_BODY).encode("utf-8")

HTTP_LOGIN_RESP = (
    "HTTP/1.1 401 Unauthorized\r\n"
    "Content-Type: text/html\r\n"
    "Server: GE-WebServer/1.0\r\n"
    "Connection: close\r\n\r\n"
    "<html><body style='font-family:Arial;background:#1a1a2e;color:#eee;padding:40px'>"
    "<h2 style='color:#e94560'>Authentication Failed</h2>"
    "<p>Invalid credentials. This attempt has been logged.</p>"
    "<a href='/' style='color:#58a6ff'>Try again</a>"
    "</body></html>"
).encode("utf-8")

HTTP_404 = (
    "HTTP/1.1 404 Not Found\r\n"
    "Content-Type: text/plain\r\n"
    "Server: GE-WebServer/1.0\r\n"
    "Connection: close\r\n\r\n"
    "404 Not Found"
).encode("utf-8")


def _parse_http(raw):
    try:
        end   = raw.find(b"\r\n\r\n")
        head  = raw[:end].decode("utf-8", errors="ignore")
        body  = raw[end + 4:].decode("utf-8", errors="ignore")
        lines = head.split("\r\n")
        parts = lines[0].split(" ")
        method  = parts[0] if len(parts) > 0 else "UNKNOWN"
        path    = parts[1] if len(parts) > 1 else "/"
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
        return method, path, headers, body
    except Exception:
        return "UNKNOWN", "/", {}, ""


def _handle_http_conn(client_socket, src_ip, src_port):
    write_event("honeypot.connect", src_ip, src_port, protocol="http")
    try:
        client_socket.settimeout(10)
        raw = b""
        while True:
            chunk = client_socket.recv(4096)
            if not chunk:
                break
            raw += chunk
            if b"\r\n\r\n" in raw:
                break
        method, path, headers, body = _parse_http(raw)
        ua = headers.get("User-Agent", "")
        write_event("honeypot.http.request", src_ip, src_port,
                    method=method, path=path, user_agent=ua)
        if method == "POST" and "/login" in path:
            creds = {}
            for part in body.split("&"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    creds[k.strip()] = v.strip()
            write_event("honeypot.http.login", src_ip, src_port,
                        username=creds.get("username",""),
                        password=creds.get("password",""), path=path)
            client_socket.send(HTTP_LOGIN_RESP)
        elif path in ("/", "/index.html", "/admin", "/admin/", "/login"):
            client_socket.send(HTTP_INDEX)
        else:
            if any(x in path for x in ["../", "%2e", "etc/passwd", "cmd=", "exec", "shell"]):
                write_event("honeypot.exploit.attempt", src_ip, src_port,
                            path=path, method=method)
            client_socket.send(HTTP_404)
    except Exception:
        pass
    finally:
        try:
            client_socket.close()
        except Exception:
            pass


def start_http_honeypot(port=8888):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_sock.bind(("0.0.0.0", port))
    except OSError as e:
        log.error(f"Cannot bind HTTP on port {port}: {e}")
        return
    server_sock.listen(10)
    log.info(f"[HTTP Honeypot] Listening on port {port}")
    while True:
        try:
            client, addr = server_sock.accept()
            t = threading.Thread(
                target=_handle_http_conn,
                args=(client, addr[0], addr[1]),
                daemon=True,
            )
            t.start()
        except Exception as e:
            log.error(f"HTTP accept error: {e}")

# =============================================================================
#  MAIN
# =============================================================================

if __name__ == "__main__":
    log.info("=" * 55)
    log.info(f"  Healthcare IoT Deception Honeypot")
    log.info(f"  Device : {DEVICE_NAME}")
    log.info(f"  SSH    : port 2222")
    log.info(f"  HTTP   : port 8888")
    log.info(f"  Log    : {LOG_FILE}")
    log.info("=" * 55)

    # Start HTTP honeypot thread
    http_thread = threading.Thread(target=start_http_honeypot, args=(8888,), daemon=True)
    http_thread.start()

    # Start SSH honeypot thread
    ssh_thread = threading.Thread(target=start_ssh_honeypot, args=(2222,), daemon=True)
    ssh_thread.start()

    log.info("Honeypot active. Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("Honeypot stopped.")
