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
echo "  INSTALLER v6.0 — Local-First Architecture"
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
MONGO_URL="mongodb://localhost:27017"
DB_NAME="redteam"
KIMI_API_KEY=""
MSF_RPC_TOKEN=""
MSF_RPC_HOST="127.0.0.1"
MSF_RPC_PORT="55553"
SLIVER_CONFIG_PATH=""
DB_PATH="/app/backend/data/redteam.db"
APP_MODE="local"
LOG_LEVEL="INFO"
ENVEOF
    warn "Created .env with defaults. Edit $ENV_FILE to set KIMI_API_KEY, MSF_RPC_TOKEN, etc."
else
    ok ".env already exists"
fi

# ─── Frontend Dependencies ───────────────────────────────
info "Installing frontend dependencies..."
if [ ! -d "$FRONTEND_DIR/node_modules" ]; then
    cd "$FRONTEND_DIR"
    if command -v yarn &>/dev/null; then
        yarn install --silent 2>/dev/null
    else
        npm install --silent 2>/dev/null
    fi
    cd "$SCRIPT_DIR"
    ok "Frontend packages installed"
else
    ok "Frontend node_modules already present"
fi

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
