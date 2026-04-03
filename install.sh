#!/bin/bash
# ============================================
# RED TEAM FRAMEWORK - INSTALADOR AUTOMATICO
# Solo corre: bash install.sh
# ============================================

set -e
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${RED}"
echo "  ██████╗ ███████╗██████╗     ████████╗███████╗ █████╗ ███╗   ███╗"
echo "  ██╔══██╗██╔════╝██╔══██╗    ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║"
echo "  ██████╔╝█████╗  ██║  ██║       ██║   █████╗  ███████║██╔████╔██║"
echo "  ██╔══██╗██╔══╝  ██║  ██║       ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║"
echo "  ██║  ██║███████╗██████╔╝       ██║   ███████╗██║  ██║██║ ╚═╝ ██║"
echo "  ╚═╝  ╚═╝╚══════╝╚═════╝        ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝"
echo -e "${NC}"
echo -e "${CYAN}  Instalador Automatico v5.0${NC}"
echo ""

DIR="$(cd "$(dirname "$0")" && pwd)"

# ============ DETECTAR SISTEMA ============
echo -e "${YELLOW}[1/7] Detectando sistema...${NC}"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo -e "  ${GREEN}OS: $PRETTY_NAME${NC}"
else
    echo -e "  ${GREEN}OS: Linux${NC}"
fi

# ============ MONGODB ============
echo -e "${YELLOW}[2/7] Verificando MongoDB...${NC}"
if command -v mongod &> /dev/null; then
    echo -e "  ${GREEN}MongoDB ya instalado${NC}"
else
    echo -e "  ${CYAN}Instalando MongoDB...${NC}"
    if command -v apt &> /dev/null; then
        sudo apt update -qq
        sudo apt install -y mongodb 2>/dev/null || {
            # Si falla, intentar con mongosh/mongod directo
            curl -fsSL https://www.mongodb.org/static/pgp/server-7.0.asc | sudo gpg --dearmor -o /usr/share/keyrings/mongodb-server-7.0.gpg 2>/dev/null
            echo "deb [ signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] http://repo.mongodb.org/apt/debian bookworm/mongodb-org/7.0 main" | sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list
            sudo apt update -qq
            sudo apt install -y mongodb-org
        }
    fi
fi

# Arrancar MongoDB
if command -v systemctl &> /dev/null; then
    sudo systemctl start mongod 2>/dev/null || sudo systemctl start mongodb 2>/dev/null || true
    sudo systemctl enable mongod 2>/dev/null || sudo systemctl enable mongodb 2>/dev/null || true
fi

# Verificar que MongoDB responde
sleep 2
if command -v mongosh &> /dev/null; then
    mongosh --quiet --eval "db.runCommand({ping:1})" > /dev/null 2>&1 && echo -e "  ${GREEN}MongoDB corriendo${NC}" || echo -e "  ${RED}MongoDB no responde - verificar manualmente${NC}"
elif command -v mongo &> /dev/null; then
    mongo --quiet --eval "db.runCommand({ping:1})" > /dev/null 2>&1 && echo -e "  ${GREEN}MongoDB corriendo${NC}" || echo -e "  ${RED}MongoDB no responde - verificar manualmente${NC}"
else
    echo -e "  ${YELLOW}No se pudo verificar MongoDB - asegurate que este corriendo${NC}"
fi

# ============ NODE.JS & YARN ============
echo -e "${YELLOW}[3/7] Verificando Node.js y Yarn...${NC}"
if command -v node &> /dev/null; then
    NODE_VER=$(node --version)
    echo -e "  ${GREEN}Node.js $NODE_VER ya instalado${NC}"
else
    echo -e "  ${CYAN}Instalando Node.js 18...${NC}"
    curl -fsSL https://deb.nodesource.com/setup_18.x | sudo bash -
    sudo apt install -y nodejs
    echo -e "  ${GREEN}Node.js $(node --version) instalado${NC}"
fi

if command -v yarn &> /dev/null; then
    echo -e "  ${GREEN}Yarn ya instalado${NC}"
else
    echo -e "  ${CYAN}Instalando Yarn...${NC}"
    sudo npm install -g yarn
    echo -e "  ${GREEN}Yarn instalado${NC}"
fi

# ============ PYTHON BACKEND ============
echo -e "${YELLOW}[4/7] Configurando backend Python...${NC}"
cd "$DIR/backend"

if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "  ${GREEN}Entorno virtual creado${NC}"
fi

source venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet fastapi uvicorn motor python-dotenv httpx pydantic fpdf2 pymetasploit3 sliver-py websockets
echo -e "  ${GREEN}Dependencias Python instaladas${NC}"

# ============ CONFIGURAR .ENV ============
echo -e "${YELLOW}[5/7] Configurando archivos .env...${NC}"

# Backend .env
if [ ! -f "$DIR/backend/.env" ]; then
    cat > "$DIR/backend/.env" << 'ENVFILE'
MONGO_URL="mongodb://localhost:27017"
DB_NAME="redteam_db"
CORS_ORIGINS="http://localhost:3000"
KIMI_API_KEY=""
MSF_RPC_TOKEN=""
MSF_RPC_HOST="127.0.0.1"
MSF_RPC_PORT="55553"
SLIVER_CONFIG_PATH=""
ENVFILE
    echo -e "  ${GREEN}backend/.env creado${NC}"
else
    # Solo actualizar CORS y MONGO para local si vienen de la nube
    sed -i 's|REACT_APP_BACKEND_URL=https://.*|REACT_APP_BACKEND_URL=http://localhost:8001|' "$DIR/backend/.env" 2>/dev/null || true
    if ! grep -q "CORS_ORIGINS" "$DIR/backend/.env"; then
        echo 'CORS_ORIGINS="http://localhost:3000"' >> "$DIR/backend/.env"
    else
        sed -i 's|CORS_ORIGINS=.*|CORS_ORIGINS="http://localhost:3000"|' "$DIR/backend/.env"
    fi
    if ! grep -q "MSF_RPC_TOKEN" "$DIR/backend/.env"; then
        echo 'MSF_RPC_TOKEN=""' >> "$DIR/backend/.env"
        echo 'MSF_RPC_HOST="127.0.0.1"' >> "$DIR/backend/.env"
        echo 'MSF_RPC_PORT="55553"' >> "$DIR/backend/.env"
        echo 'SLIVER_CONFIG_PATH=""' >> "$DIR/backend/.env"
    fi
    echo -e "  ${GREEN}backend/.env actualizado para local${NC}"
fi

# Frontend .env
if [ ! -f "$DIR/frontend/.env" ]; then
    echo 'REACT_APP_BACKEND_URL=http://localhost:8001' > "$DIR/frontend/.env"
    echo -e "  ${GREEN}frontend/.env creado${NC}"
else
    sed -i 's|REACT_APP_BACKEND_URL=.*|REACT_APP_BACKEND_URL=http://localhost:8001|' "$DIR/frontend/.env"
    # Eliminar config de nube
    sed -i '/WDS_SOCKET_PORT/d' "$DIR/frontend/.env" 2>/dev/null || true
    sed -i '/ENABLE_HEALTH_CHECK/d' "$DIR/frontend/.env" 2>/dev/null || true
    echo -e "  ${GREEN}frontend/.env actualizado para local${NC}"
fi

# ============ FRONTEND ============
echo -e "${YELLOW}[6/7] Instalando frontend...${NC}"
cd "$DIR/frontend"
yarn install --silent 2>/dev/null
echo -e "  ${GREEN}Dependencias frontend instaladas${NC}"

# ============ CREAR SCRIPT DE ARRANQUE ============
echo -e "${YELLOW}[7/7] Creando script de arranque...${NC}"

cat > "$DIR/start.sh" << 'STARTFILE'
#!/bin/bash
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'
DIR="$(cd "$(dirname "$0")" && pwd)"

echo -e "${RED}"
echo "  RED TEAM FRAMEWORK v5.0"
echo -e "${NC}"

# Arrancar MongoDB si no esta corriendo
sudo systemctl start mongod 2>/dev/null || sudo systemctl start mongodb 2>/dev/null || echo -e "${CYAN}MongoDB: arrancalo manualmente si no esta corriendo${NC}"

# Backend
echo -e "${GREEN}Arrancando backend en puerto 8001...${NC}"
cd "$DIR/backend"
source venv/bin/activate
uvicorn server:app --host 0.0.0.0 --port 8001 --reload &
BACKEND_PID=$!

# Esperar a que el backend responda
sleep 3

# Frontend
echo -e "${GREEN}Arrancando frontend en puerto 3000...${NC}"
cd "$DIR/frontend"
PORT=3000 yarn start &
FRONTEND_PID=$!

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Framework listo en:${NC}"
echo -e "${CYAN}  http://localhost:3000${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${CYAN}Para activar msfrpcd (en otra terminal):${NC}"
echo -e "  msfrpcd -P TU_TOKEN -S -a 127.0.0.1"
echo ""
echo -e "${RED}Presiona Ctrl+C para detener todo${NC}"

# Capturar Ctrl+C y matar ambos procesos
trap "echo ''; echo 'Deteniendo...'; kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit 0" INT TERM

# Esperar
wait
STARTFILE

chmod +x "$DIR/start.sh"

# ============ LISTO ============
echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  INSTALACION COMPLETA${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "  Para arrancar la herramienta:"
echo -e "  ${CYAN}bash start.sh${NC}"
echo ""
echo -e "  Se abrira en: ${CYAN}http://localhost:3000${NC}"
echo ""
echo -e "  ${YELLOW}NOTA: Edita backend/.env para poner tus keys:${NC}"
echo -e "  ${YELLOW}  - KIMI_API_KEY (Moonshot AI)${NC}"
echo -e "  ${YELLOW}  - MSF_RPC_TOKEN (Metasploit RPC)${NC}"
echo ""
