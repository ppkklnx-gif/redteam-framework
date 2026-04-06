#!/usr/bin/env bash
# ============================================================
# doctor.sh — Red Team Framework — Deep Health Check
# ============================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/backend"
FRONTEND_DIR="$SCRIPT_DIR/frontend"
VENV_DIR="$BACKEND_DIR/.venv"
DATA_DIR="$BACKEND_DIR/data"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
pass() { echo -e "  ${GREEN}PASS${NC}  $1"; }
fail() { echo -e "  ${RED}FAIL${NC}  $1"; ERRORS=$((ERRORS + 1)); }
warn() { echo -e "  ${YELLOW}WARN${NC}  $1"; WARNINGS=$((WARNINGS + 1)); }
info() { echo -e "  ${CYAN}INFO${NC}  $1"; }

ERRORS=0
WARNINGS=0
HINTS=()

echo -e "${CYAN}"
echo "  ╔═══════════════════════════════════════╗"
echo "  ║      RED TEAM FRAMEWORK — DOCTOR      ║"
echo "  ║         Deep Health Diagnostic         ║"
echo "  ╚═══════════════════════════════════════╝"
echo -e "${NC}"

# ─── 1. Python & Venv ───────────────────────────────────
echo -e "${CYAN}[1/7] Python Environment${NC}"
if command -v python3 &>/dev/null; then
    PY_VER=$(python3 --version 2>&1)
    pass "Python: $PY_VER"
else
    fail "python3 not found"
    HINTS+=("Install: sudo apt install python3 python3-venv")
fi

if [ -d "$VENV_DIR" ]; then
    pass ".venv exists at $VENV_DIR"
    if [ -f "$VENV_DIR/bin/activate" ]; then
        source "$VENV_DIR/bin/activate"
        pass ".venv activates OK"
        # Check key packages
        for pkg in fastapi uvicorn aiosqlite httpx; do
            if python3 -c "import $pkg" 2>/dev/null; then
                pass "  $pkg installed"
            else
                fail "  $pkg NOT installed"
                HINTS+=("Run: source $VENV_DIR/bin/activate && pip install $pkg")
            fi
        done
    else
        fail ".venv/bin/activate missing (corrupt venv)"
        HINTS+=("Recreate: rm -rf $VENV_DIR && python3 -m venv $VENV_DIR")
    fi
else
    fail ".venv not found"
    HINTS+=("Run: ./install.sh")
fi

# ─── 2. Node & Frontend ─────────────────────────────────
echo ""
echo -e "${CYAN}[2/7] Frontend Environment${NC}"
if command -v node &>/dev/null; then
    NODE_VER=$(node --version)
    pass "Node: $NODE_VER"
else
    fail "Node.js not found"
    HINTS+=("Install: sudo apt install nodejs npm")
fi

if [ -d "$FRONTEND_DIR/node_modules" ]; then
    pass "node_modules present"
else
    fail "node_modules missing"
    HINTS+=("Run: cd $FRONTEND_DIR && npm install")
fi

# ─── 3. Configuration ───────────────────────────────────
echo ""
echo -e "${CYAN}[3/7] Configuration${NC}"
ENV_FILE="$BACKEND_DIR/.env"
if [ -f "$ENV_FILE" ]; then
    pass ".env exists"
    # Check critical vars
    source <(grep -v '^#' "$ENV_FILE" | sed 's/^/export /' 2>/dev/null) 2>/dev/null || true
    
    if [ -n "${DB_PATH:-}" ]; then
        pass "DB_PATH set: $DB_PATH"
    else
        warn "DB_PATH not set (will use default)"
    fi
    
    if [ -n "${KIMI_API_KEY:-}" ] && [ "${KIMI_API_KEY}" != '""' ] && [ "${KIMI_API_KEY}" != "" ]; then
        pass "KIMI_API_KEY configured"
    else
        warn "KIMI_API_KEY not set (AI analysis disabled)"
    fi
    
    if [ -n "${MSF_RPC_TOKEN:-}" ] && [ "${MSF_RPC_TOKEN}" != '""' ] && [ "${MSF_RPC_TOKEN}" != "" ]; then
        pass "MSF_RPC_TOKEN configured"
    else
        warn "MSF_RPC_TOKEN not set (Metasploit integration disabled)"
    fi
    
    if [ -n "${SLIVER_CONFIG_PATH:-}" ] && [ "${SLIVER_CONFIG_PATH}" != '""' ] && [ "${SLIVER_CONFIG_PATH}" != "" ]; then
        if [ -f "${SLIVER_CONFIG_PATH}" ]; then
            pass "SLIVER_CONFIG_PATH valid: $SLIVER_CONFIG_PATH"
        else
            fail "SLIVER_CONFIG_PATH file not found: $SLIVER_CONFIG_PATH"
        fi
    else
        warn "SLIVER_CONFIG_PATH not set (Sliver integration disabled)"
    fi
else
    fail ".env not found"
    HINTS+=("Run: ./install.sh to create default .env")
fi

# ─── 4. Database ─────────────────────────────────────────
echo ""
echo -e "${CYAN}[4/7] Database (SQLite)${NC}"
DB_FILE="${DB_PATH:-$DATA_DIR/redteam.db}"
if [ -d "$(dirname "$DB_FILE")" ]; then
    pass "Data directory exists: $(dirname "$DB_FILE")"
else
    fail "Data directory missing: $(dirname "$DB_FILE")"
    HINTS+=("mkdir -p $(dirname "$DB_FILE")")
fi
if [ -f "$DB_FILE" ]; then
    DB_SIZE=$(du -h "$DB_FILE" | cut -f1)
    pass "Database exists: $DB_FILE ($DB_SIZE)"
    TABLE_COUNT=$(sqlite3 "$DB_FILE" "SELECT count(*) FROM sqlite_master WHERE type='table';" 2>/dev/null || echo "?")
    pass "Tables: $TABLE_COUNT"
else
    warn "Database file not yet created (will be created on first start)"
fi

# ─── 5. Ports ────────────────────────────────────────────
echo ""
echo -e "${CYAN}[5/7] Service Ports${NC}"
for port in 8001 3000; do
    pid=$(lsof -ti :$port 2>/dev/null || true)
    if [ -n "$pid" ]; then
        cmd=$(ps -p $pid -o comm= 2>/dev/null || echo "unknown")
        pass "Port $port in use (PID: $pid, CMD: $cmd)"
    else
        info "Port $port free (service not running)"
    fi
done

# ─── 6. Security Tools ──────────────────────────────────
echo ""
echo -e "${CYAN}[6/7] Security Tools${NC}"
TOOLS=("nmap" "nikto" "sqlmap" "hydra" "msfvenom" "msfconsole" "gobuster" "whatweb" "wafw00f" "subfinder")
INSTALLED=0
for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        pass "$tool"
        INSTALLED=$((INSTALLED + 1))
    else
        warn "$tool not found"
    fi
done
info "Security tools: $INSTALLED/${#TOOLS[@]} installed"

# ─── 7. Integrations ────────────────────────────────────
echo ""
echo -e "${CYAN}[7/7] Integration Connectivity${NC}"

# MSF RPC
MSF_HOST="${MSF_RPC_HOST:-127.0.0.1}"
MSF_PORT="${MSF_RPC_PORT:-55553}"
if nc -z "$MSF_HOST" "$MSF_PORT" 2>/dev/null; then
    pass "MSF RPC reachable at $MSF_HOST:$MSF_PORT"
else
    if [ -n "${MSF_RPC_TOKEN:-}" ] && [ "${MSF_RPC_TOKEN}" != '""' ]; then
        warn "MSF RPC not reachable at $MSF_HOST:$MSF_PORT"
        HINTS+=("Start msfrpcd: msfrpcd -P <token> -S -a $MSF_HOST -p $MSF_PORT")
    else
        info "MSF RPC not configured (optional)"
    fi
fi

# Backend API (if running)
if curl -sf http://localhost:8001/api/health >/dev/null 2>&1; then
    pass "Backend API responding"
    HEALTH=$(curl -sf http://localhost:8001/api/health)
    DB_STATUS=$(echo "$HEALTH" | python3 -c "import sys,json; print(json.load(sys.stdin)['checks']['database']['status'])" 2>/dev/null || echo "unknown")
    pass "Database status: $DB_STATUS"
else
    info "Backend not running (start with ./run.sh)"
fi

# ─── Summary ─────────────────────────────────────────────
echo ""
echo "  ─────────────────────────────────────────"
if [ "$ERRORS" -eq 0 ] && [ "$WARNINGS" -eq 0 ]; then
    echo -e "  ${GREEN}ALL CHECKS PASSED${NC}"
elif [ "$ERRORS" -eq 0 ]; then
    echo -e "  ${YELLOW}$WARNINGS WARNING(S) — Framework functional${NC}"
else
    echo -e "  ${RED}$ERRORS ERROR(S), $WARNINGS WARNING(S)${NC}"
fi
echo "  ─────────────────────────────────────────"

if [ ${#HINTS[@]} -gt 0 ]; then
    echo ""
    echo -e "  ${CYAN}Hints:${NC}"
    for hint in "${HINTS[@]}"; do
        echo -e "    ${YELLOW}→${NC} $hint"
    done
fi
echo ""
