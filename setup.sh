#!/bin/bash
# =============================================================================
#  Healthcare IoT Deception Honeypot Network
#  One-command setup — run with: sudo bash setup.sh
# =============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

echo -e "${BLUE}
╔══════════════════════════════════════════════════════════╗
║   Healthcare IoT Deception Honeypot Network              ║
║   Setup Script — Ubuntu 20.04 / 22.04 / 24.04 / 25.x    ║
╚══════════════════════════════════════════════════════════╝
${NC}"

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*"; }
step()  { echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; \
          echo -e "${BLUE}  $*${NC}"; \
          echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }

# Detect real user
if [ -n "$SUDO_USER" ]; then
    REAL_USER="$SUDO_USER"
    REAL_HOME="/home/$SUDO_USER"
else
    REAL_USER="$(whoami)"
    REAL_HOME="$HOME"
fi

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="$PROJECT_DIR/logs"
info "User    : $REAL_USER"
info "Project : $PROJECT_DIR"

# ── Release apt lock ──────────────────────────────────────────────────────────
release_apt() {
    systemctl stop unattended-upgrades 2>/dev/null || true
    systemctl stop apt-daily.service apt-daily-upgrade.service 2>/dev/null || true
    killall unattended-upgr apt apt-get dpkg 2>/dev/null || true
    sleep 3
    rm -f /var/lib/dpkg/lock-frontend \
          /var/lib/dpkg/lock \
          /var/cache/apt/archives/lock \
          /var/lib/apt/lists/lock 2>/dev/null || true
    dpkg --configure -a 2>/dev/null || true
    info "apt lock released."
}

safe_apt() {
    local PACKAGES="$*"
    for attempt in 1 2 3; do
        if apt-get install -y $PACKAGES; then
            return 0
        fi
        warn "apt failed (attempt $attempt/3) — releasing lock and retrying in 10s..."
        release_apt
        sleep 10
    done
    err "apt install failed for: $PACKAGES"
    return 1
}

# =============================================================================
step "Step 1 — Release apt lock & update"
# =============================================================================
release_apt
apt-get update -qq 2>/dev/null || { release_apt; apt-get update; }
info "apt updated."

# =============================================================================
step "Step 2 — Install system packages"
# =============================================================================
safe_apt python3 python3-pip git curl ufw net-tools
info "System packages installed."

# =============================================================================
step "Step 3 — Install Python packages"
# =============================================================================
# Try multiple methods for different Ubuntu versions
pip3 install --break-system-packages flask requests 2>/dev/null || \
pip3 install flask requests 2>/dev/null || \
python3 -m pip install flask requests 2>/dev/null || true

python3 -c "import flask, requests" 2>/dev/null && \
    info "Flask and requests installed." || \
    { err "Python packages failed. Trying once more..."; \
      apt-get install -y python3-flask python3-requests 2>/dev/null || true; }
info "Python packages ready."

# =============================================================================
step "Step 4 — Create directories"
# =============================================================================
mkdir -p "$LOG_DIR"
chmod 777 "$LOG_DIR"
chown -R "$REAL_USER":"$REAL_USER" "$PROJECT_DIR"
info "Directories ready."

# =============================================================================
step "Step 5 — Install & configure SSH server"
# =============================================================================
if [ ! -f /etc/ssh/sshd_config ]; then
    warn "openssh-server not found — installing..."
    release_apt
    safe_apt openssh-server
    sleep 3
fi

if [ -f /etc/ssh/sshd_config ]; then
    CURRENT_PORT=$(grep -E "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    if [ -z "$CURRENT_PORT" ] || [ "$CURRENT_PORT" = "22" ]; then
        warn "Moving real SSH from port 22 → 2244..."
        sed -i '/^#*Port /d' /etc/ssh/sshd_config
        echo "Port 2244" >> /etc/ssh/sshd_config
        for SVC in ssh sshd; do
            if systemctl list-unit-files 2>/dev/null | grep -q "^${SVC}.service"; then
                systemctl enable "$SVC" --now 2>/dev/null || true
                systemctl restart "$SVC" 2>/dev/null && \
                    info "SSH restarted on port 2244." && break
            fi
        done
    else
        info "SSH already on port $CURRENT_PORT — no change."
    fi
else
    warn "No sshd_config found — skipping SSH config."
fi

# =============================================================================
step "Step 6 — Firewall rules"
# =============================================================================
ufw --force enable 2>/dev/null || true
ufw allow 2244/tcp  comment "Real SSH"           2>/dev/null || true
ufw allow 2222/tcp  comment "Honeypot fake SSH"  2>/dev/null || true
ufw allow 8888/tcp  comment "Honeypot web panel" 2>/dev/null || true
ufw allow 8000/tcp  comment "Dashboard"          2>/dev/null || true
ufw status
info "Firewall configured."

# =============================================================================
step "Step 7 — Kill any old honeypot processes"
# =============================================================================
pkill -f "honeypot.py"    2>/dev/null || true
pkill -f "dashboard/app"  2>/dev/null || true
pkill -f "app.py"         2>/dev/null || true
sleep 2
info "Old processes cleared."

# =============================================================================
step "Step 8 — Start the honeypot"
# =============================================================================
sudo -u "$REAL_USER" nohup python3 "$PROJECT_DIR/honeypot.py" \
    > "$LOG_DIR/honeypot_service.log" 2>&1 &
HON_PID=$!
sleep 4

if kill -0 "$HON_PID" 2>/dev/null; then
    info "Honeypot running (PID $HON_PID) — listening on ports 2222 (SSH) and 8888 (HTTP)"
else
    err "Honeypot failed to start. Log:"
    cat "$LOG_DIR/honeypot_service.log" 2>/dev/null | tail -20
fi

# =============================================================================
step "Step 9 — Start the dashboard"
# =============================================================================
sudo -u "$REAL_USER" nohup python3 "$PROJECT_DIR/dashboard/app.py" \
    > "$LOG_DIR/dashboard_service.log" 2>&1 &
DASH_PID=$!
sleep 4

if kill -0 "$DASH_PID" 2>/dev/null; then
    info "Dashboard running (PID $DASH_PID)"
else
    err "Dashboard failed to start. Log:"
    cat "$LOG_DIR/dashboard_service.log" 2>/dev/null | tail -20
fi

# =============================================================================
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  SETUP COMPLETE — Everything is running!                 ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BLUE}Honeypot fake SSH${NC}  → port 2222  (connect with any password)"
echo -e "  ${BLUE}Honeypot fake HTTP${NC} → port 8888  (open in browser)"
echo -e "  ${BLUE}Dashboard${NC}          → ${GREEN}http://localhost:8000${NC}"
echo -e "  ${BLUE}Real SSH${NC}           → port 2244"
echo ""
echo -e "  ${YELLOW}▶ Test the honeypot:${NC}"
echo -e "    ssh -p 2222 root@localhost   (any password works)"
echo -e "    curl http://localhost:8888"
echo ""
echo -e "  ${YELLOW}▶ Open dashboard:${NC}"
echo -e "    http://localhost:8000"
echo ""
echo -e "  ${YELLOW}▶ Generate threat report:${NC}"
echo -e "    python3 parser/parse_logs.py"
echo ""
echo -e "  ${YELLOW}▶ To restart everything:${NC}"
echo -e "    bash start.sh"
echo ""
echo -e "  ${YELLOW}▶ To stop everything:${NC}"
echo -e "    bash stop.sh"
echo ""
