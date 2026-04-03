# Red Team Framework - Guia de Instalacion en Kali Linux

## Paso 1: Obtener el codigo

### Opcion A: Desde GitHub
Usa el boton **"Save to Github"** en el chat de Emergent para hacer push.
Luego en tu Kali:
```bash
git clone https://github.com/TU_USUARIO/TU_REPO.git
cd TU_REPO
```

### Opcion B: ZIP
Usa el boton **"Download"** en el chat de Emergent para descargar el ZIP.
```bash
unzip redteam-framework.zip
cd redteam-framework
```

---

## Paso 2: Instalar MongoDB

```bash
# Importar clave GPG de MongoDB
curl -fsSL https://www.mongodb.org/static/pgp/server-7.0.asc | sudo gpg -o /usr/share/keyrings/mongodb-server-7.0.gpg --dearmor

# Agregar repositorio (Kali basado en Debian)
echo "deb [ signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] http://repo.mongodb.org/apt/debian bookworm/mongodb-org/7.0 main" | sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list

# Instalar
sudo apt update
sudo apt install -y mongodb-org

# Iniciar MongoDB
sudo systemctl start mongod
sudo systemctl enable mongod

# Verificar que esta corriendo
mongosh --eval "db.runCommand({ping:1})"
```

**Si tienes problemas con el repo**, alternativa rapida:
```bash
sudo apt install -y mongodb
sudo systemctl start mongodb
```

---

## Paso 3: Instalar Node.js y Yarn

```bash
# Node.js 18+ (si no lo tienes)
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo bash -
sudo apt install -y nodejs

# Yarn
sudo npm install -g yarn

# Verificar
node --version   # debe ser 18+
yarn --version
```

---

## Paso 4: Configurar el Backend

```bash
cd backend

# Crear entorno virtual
python3 -m venv venv
source venv/bin/activate

# Instalar dependencias (solo las necesarias, no todo el freeze)
pip install fastapi uvicorn motor python-dotenv httpx pydantic fpdf2 pymetasploit3 sliver-py websockets

# Configurar .env (ya viene configurado, solo verificar)
cat .env
```

Tu archivo `backend/.env` debe tener:
```
MONGO_URL="mongodb://localhost:27017"
DB_NAME="redteam_db"
CORS_ORIGINS="http://localhost:3000"
KIMI_API_KEY="sk-4zTj5qtLiyJTrzGPmf7DQYsFMplk2B5QvvP69EPJb3N3fwDQ"
MSF_RPC_TOKEN="13nHJ54CoGYr5jCeI0iXXU4YsAnkItfv"
MSF_RPC_HOST="127.0.0.1"
MSF_RPC_PORT="55553"
SLIVER_CONFIG_PATH=""
```

**Iniciar el backend:**
```bash
cd backend
source venv/bin/activate
uvicorn server:app --host 0.0.0.0 --port 8001 --reload
```

---

## Paso 5: Configurar el Frontend

```bash
cd frontend

# Cambiar la URL del backend para local
# Edita frontend/.env y cambia:
```

Tu archivo `frontend/.env` debe quedar asi:
```
REACT_APP_BACKEND_URL=http://localhost:8001
```

```bash
# Instalar dependencias
yarn install

# Iniciar el frontend
yarn start
```

---

## Paso 6: Abrir la App

Abre tu navegador en: **http://localhost:3000**

---

## Ejecucion Rapida (2 terminales)

**Terminal 1 - Backend:**
```bash
cd backend
source venv/bin/activate
uvicorn server:app --host 0.0.0.0 --port 8001 --reload
```

**Terminal 2 - Frontend:**
```bash
cd frontend
yarn start
```

---

## BONUS: Herramientas Red Team reales

El framework simula las herramientas si no estan instaladas. Para resultados reales, instala:

```bash
# Ya vienen en Kali normalmente:
sudo apt install -y nmap nikto whatweb wafw00f gobuster hydra

# SQLmap
sudo apt install -y sqlmap

# Metasploit (ya viene en Kali)
# Si no: sudo apt install -y metasploit-framework

# CrackMapExec
sudo apt install -y crackmapexec

# Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

Con estas herramientas instaladas, el framework ejecutara los comandos reales en vez de simular.

---

## Troubleshooting

| Problema | Solucion |
|----------|----------|
| MongoDB no arranca | `sudo systemctl status mongod` y revisar logs |
| Puerto 8001 ocupado | `lsof -i :8001` y matar el proceso |
| Puerto 3000 ocupado | `lsof -i :3000` y matar el proceso |
| Error CORS | Verificar que `CORS_ORIGINS` en backend/.env incluya `http://localhost:3000` |
| Frontend no conecta al backend | Verificar `REACT_APP_BACKEND_URL=http://localhost:8001` en frontend/.env |
