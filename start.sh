#!/bin/bash
# Quick start — run after setup.sh has been run once
# Usage: bash start.sh

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="$PROJECT_DIR/logs"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info() { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }

# Kill existing processes
pkill -f "honeypot.py" 2>/dev/null || true
pkill -f "dashboard/app.py" 2>/dev/null || true
sleep 2

# Check flask is installed
python3 -c "import flask" 2>/dev/null || {
    warn "Flask not found — installing..."
    pip3 install --break-system-packages flask requests 2>/dev/null || pip3 install flask requests
}

# Check paramiko
python3 -c "import paramiko" 2>/dev/null || {
    warn "paramiko not found — installing..."
    pip3 install --break-system-packages paramiko 2>/dev/null || pip3 install paramiko
}

# Start honeypot
nohup python3 "$PROJECT_DIR/honeypot.py" > "$LOG_DIR/honeypot_service.log" 2>&1 &
HON_PID=$!
sleep 3
kill -0 "$HON_PID" 2>/dev/null && info "Honeypot running (PID $HON_PID)" || warn "Honeypot failed — check $LOG_DIR/honeypot_service.log"

# Start dashboard
nohup python3 "$PROJECT_DIR/dashboard/app.py" > "$LOG_DIR/dashboard_service.log" 2>&1 &
DASH_PID=$!
sleep 3
kill -0 "$DASH_PID" 2>/dev/null && info "Dashboard running (PID $DASH_PID)" || warn "Dashboard failed — check $LOG_DIR/dashboard_service.log"

echo ""
echo -e "  ${GREEN}Honeypot SSH${NC}  → ssh -p 2222 root@localhost  (any password)"
echo -e "  ${GREEN}Honeypot HTTP${NC} → http://localhost:8888"
echo -e "  ${GREEN}Dashboard${NC}     → http://localhost:8000"
echo ""
