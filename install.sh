#!/usr/bin/env bash
# ============================================================
# install.sh — Red Team Framework — Idempotent Installer
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/backend"
FRONTEND_DIR="$SCRIPT_DIR/frontend"
VENV_DIR="$BACKEND_DIR/.venv"
DATA_DIR="$BACKEND_DIR/data"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[X]${NC} $1"; }
info() { echo -e "${CYAN}[*]${NC} $1"; }

echo -e "${RED}"
echo "  ██████╗ ███████╗██████╗  ████████╗███████╗ █████╗ ███╗   ███╗"
echo "  ██╔══██╗██╔════╝██╔══██╗ ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║"
echo "  ██████╔╝█████╗  ██║  ██║    ██║   █████╗  ███████║██╔████╔██║"
echo "  ██╔══██╗██╔══╝  ██║  ██║    ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║"
echo "  ██║  ██║███████╗██████╔╝    ██║   ███████╗██║  ██║██║ ╚═╝ ██║"
echo "  ╚═╝  ╚═╝╚══════╝╚═════╝     ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝"
echo -e "${NC}"
echo "  INSTALLER v7.0 — AI-Driven Architecture"
echo ""

# ─── System Dependencies ─────────────────────────────────
info "Checking system dependencies..."

REQUIRED_SYS=("python3" "pip3" "node" "npm")
MISSING_SYS=()
for dep in "${REQUIRED_SYS[@]}"; do
    if ! command -v "$dep" &>/dev/null; then
        MISSING_SYS+=("$dep")
    fi
done

if [ ${#MISSING_SYS[@]} -gt 0 ]; then
    err "Missing: ${MISSING_SYS[*]}"
    info "On Kali/Debian: sudo apt update && sudo apt install -y python3 python3-pip python3-venv nodejs npm"
    exit 1
fi
ok "System dependencies present"

# ─── Python Virtual Environment ──────────────────────────
info "Setting up Python virtual environment..."
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
    ok "Created .venv at $VENV_DIR"
else
    ok ".venv already exists"
fi

source "$VENV_DIR/bin/activate"

info "Installing Python dependencies..."
pip install --quiet --upgrade pip
pip install --quiet -r "$BACKEND_DIR/requirements.txt"
ok "Python packages installed"

# ─── Data Directory ──────────────────────────────────────
mkdir -p "$DATA_DIR"
ok "Data directory: $DATA_DIR"

# ─── Backend .env ────────────────────────────────────────
ENV_FILE="$BACKEND_DIR/.env"
if [ ! -f "$ENV_FILE" ]; then
    info "Creating default .env..."
    cat > "$ENV_FILE" <<'ENVEOF'
KIMI_API_KEY=""
DB_PATH=""
APP_MODE="local"
LOG_LEVEL="INFO"
ENVEOF
    warn "Created .env — Edit $ENV_FILE to set your KIMI_API_KEY (Moonshot AI)"
else
    ok ".env already exists"
fi

# ─── Frontend Dependencies ───────────────────────────────
info "Installing frontend dependencies..."
cd "$FRONTEND_DIR"

# Always nuke old node_modules to prevent stale cache issues
if [ -d "node_modules" ]; then
    warn "Removing old node_modules (prevents cache bugs)..."
    rm -rf node_modules package-lock.json
fi

info "Running npm install (this may take 2-3 minutes)..."
if npm install 2>&1; then
    ok "Frontend packages installed"
else
    warn "npm install had issues, retrying with --legacy-peer-deps..."
    npm install --legacy-peer-deps 2>&1
    if [ $? -eq 0 ]; then
        ok "Frontend packages installed (legacy mode)"
    else
        err "Frontend install failed. Run manually: cd frontend && npm install --legacy-peer-deps"
    fi
fi
cd "$SCRIPT_DIR"

# ─── Frontend .env ───────────────────────────────────────
FE_ENV="$FRONTEND_DIR/.env"
if [ ! -f "$FE_ENV" ]; then
    echo 'REACT_APP_BACKEND_URL=http://localhost:8001' > "$FE_ENV"
    warn "Created frontend .env pointing to localhost:8001"
else
    ok "Frontend .env exists"
fi

# ─── Verify ──────────────────────────────────────────────
echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  INSTALLATION COMPLETE${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "  Next steps:"
echo -e "    1. Edit ${CYAN}$ENV_FILE${NC} with your API keys"
echo -e "    2. Run ${CYAN}./run.sh${NC} to start the framework"
echo -e "    3. Run ${CYAN}./doctor.sh${NC} to verify everything"
echo ""
