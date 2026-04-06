#!/usr/bin/env bash
# ============================================================
# run.sh — Red Team Framework — Start Services
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/backend"
FRONTEND_DIR="$SCRIPT_DIR/frontend"
VENV_DIR="$BACKEND_DIR/.venv"
PID_DIR="$SCRIPT_DIR/.pids"
LOG_DIR="$SCRIPT_DIR/.logs"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[X]${NC} $1"; exit 1; }
info() { echo -e "${CYAN}[*]${NC} $1"; }

# ─── Directories ─────────────────────────────────────────
mkdir -p "$PID_DIR" "$LOG_DIR"

# ─── Pre-checks ─────────────────────────────────────────
if [ ! -d "$VENV_DIR" ]; then
    err ".venv not found. Run ./install.sh first."
fi

# ─── Kill stale processes on our ports ───────────────────
kill_port() {
    local port=$1
    local pids
    pids=$(lsof -ti :$port 2>/dev/null || true)
    if [ -n "$pids" ]; then
        warn "Killing stale process on port $port (PIDs: $pids)"
        echo "$pids" | xargs kill -9 2>/dev/null || true
        sleep 1
    fi
}

# Check for stale PID files
for pidfile in "$PID_DIR"/*.pid; do
    [ -f "$pidfile" ] || continue
    pid=$(cat "$pidfile")
    if ! kill -0 "$pid" 2>/dev/null; then
        rm -f "$pidfile"
    else
        warn "Service already running (PID $pid). Run ./stop.sh first."
        exit 1
    fi
done

kill_port 8001
kill_port 3000

# ─── Start Backend ───────────────────────────────────────
info "Starting backend (FastAPI on :8001)..."
source "$VENV_DIR/bin/activate"
cd "$BACKEND_DIR"
uvicorn server:app --host 0.0.0.0 --port 8001 --reload \
    > "$LOG_DIR/backend.log" 2>&1 &
BACKEND_PID=$!
echo "$BACKEND_PID" > "$PID_DIR/backend.pid"
cd "$SCRIPT_DIR"
ok "Backend started (PID: $BACKEND_PID)"

# ─── Start Frontend ──────────────────────────────────────
info "Starting frontend (React on :3000)..."
cd "$FRONTEND_DIR"
PORT=3000 BROWSER=none npx react-scripts start \
    > "$LOG_DIR/frontend.log" 2>&1 &
FRONTEND_PID=$!
echo "$FRONTEND_PID" > "$PID_DIR/frontend.pid"
cd "$SCRIPT_DIR"
ok "Frontend started (PID: $FRONTEND_PID)"

# ─── Wait for services ──────────────────────────────────
info "Waiting for services to be ready..."
READY=false
for i in $(seq 1 30); do
    if curl -sf http://localhost:8001/api/ >/dev/null 2>&1; then
        READY=true
        break
    fi
    sleep 1
done

if $READY; then
    echo ""
    echo -e "${GREEN}============================================${NC}"
    echo -e "${GREEN}  RED TEAM FRAMEWORK RUNNING${NC}"
    echo -e "${GREEN}============================================${NC}"
    echo ""
    echo -e "  Backend:  ${CYAN}http://localhost:8001${NC}"
    echo -e "  Frontend: ${CYAN}http://localhost:3000${NC}"
    echo -e "  Health:   ${CYAN}http://localhost:8001/api/health${NC}"
    echo -e "  Doctor:   ${CYAN}http://localhost:8001/api/doctor${NC}"
    echo ""
    echo -e "  Logs:     ${CYAN}$LOG_DIR/${NC}"
    echo -e "  Stop:     ${CYAN}./stop.sh${NC}"
    echo ""
else
    warn "Backend didn't respond in 30s. Check logs: $LOG_DIR/backend.log"
fi
