#!/usr/bin/env bash
# ============================================================
# stop.sh — Red Team Framework — Clean Shutdown (No Orphans)
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_DIR="$SCRIPT_DIR/.pids"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
info() { echo -e "\033[0;36m[*]\033[0m $1"; }

KILLED=0

# ─── Phase 1: Kill by PID files ─────────────────────────
info "Stopping services via PID files..."
for pidfile in "$PID_DIR"/*.pid; do
    [ -f "$pidfile" ] || continue
    pid=$(cat "$pidfile")
    name=$(basename "$pidfile" .pid)
    if kill -0 "$pid" 2>/dev/null; then
        pkill -P "$pid" 2>/dev/null || true
        kill "$pid" 2>/dev/null || true
        sleep 0.5
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
        ok "Stopped $name (PID: $pid)"
        KILLED=$((KILLED + 1))
    else
        warn "$name (PID: $pid) was not running"
    fi
    rm -f "$pidfile"
done

# ─── Phase 2: Kill by port (catch orphans) ──────────────
info "Checking for orphan processes on ports 8001 and 3000..."
for port in 8001 3000; do
    pids=$(lsof -ti :$port 2>/dev/null || true)
    if [ -n "$pids" ]; then
        warn "Orphan on port $port (PIDs: $pids) — killing"
        echo "$pids" | xargs kill -9 2>/dev/null || true
        KILLED=$((KILLED + 1))
    fi
done

# ─── Phase 3: Kill by process name (last resort) ────────
info "Checking for remaining uvicorn/react-scripts processes..."
UVICORN_PIDS=$(pgrep -f "uvicorn server:app" 2>/dev/null || true)
if [ -n "$UVICORN_PIDS" ]; then
    warn "Found lingering uvicorn: $UVICORN_PIDS"
    echo "$UVICORN_PIDS" | xargs kill -9 2>/dev/null || true
    KILLED=$((KILLED + 1))
fi

REACT_PIDS=$(pgrep -f "react-scripts start" 2>/dev/null || true)
if [ -n "$REACT_PIDS" ]; then
    warn "Found lingering react-scripts: $REACT_PIDS"
    echo "$REACT_PIDS" | xargs kill -9 2>/dev/null || true
    KILLED=$((KILLED + 1))
fi

# ─── Summary ─────────────────────────────────────────────
echo ""
if [ "$KILLED" -gt 0 ]; then
    echo -e "${GREEN}Stopped $KILLED service(s). Clean shutdown.${NC}"
else
    echo -e "${YELLOW}No running services found.${NC}"
fi

sleep 0.5
for port in 8001 3000; do
    if lsof -ti :$port >/dev/null 2>&1; then
        echo -e "${RED}WARNING: Port $port still in use!${NC}"
    fi
done
