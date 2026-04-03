# REPORTE COMPLETO PARA GEMINI - RED TEAM AUTOMATION FRAMEWORK
# Instructivo de Instalacion, Configuracion y Funcionamiento

---

## 1. QUE ES ESTA HERRAMIENTA

Es un framework de automatizacion de Red Team basado en web (React + FastAPI + MongoDB).
Permite ejecutar escaneos automatizados contra targets, analizar vulnerabilidades con IA (Moonshot Kimi K2),
y ejecutar cadenas de ataque automatizadas, todo mapeado al framework MITRE ATT&CK.

Tiene una interfaz estilo Matrix/Cyberpunk (colores #FF003C rojo, #00FF41 verde, fondo negro).

---

## 2. ESTRUCTURA DE ARCHIVOS

```
/
├── backend/
│   ├── server.py          ← TODO el backend (FastAPI, endpoints, logica, IA)
│   ├── requirements.txt   ← Dependencias Python
│   ├── .env               ← Variables de entorno (MODIFICAR ANTES DE ARRANCAR)
│   └── tests/             ← Tests automatizados
├── frontend/
│   ├── src/
│   │   ├── App.js         ← TODO el frontend (React, componentes, logica UI)
│   │   ├── App.css        ← Estilos Matrix
│   │   └── components/ui/ ← Componentes Shadcn UI
│   ├── package.json       ← Dependencias Node
│   └── .env               ← Variables de entorno (MODIFICAR ANTES DE ARRANCAR)
├── INSTALL_KALI.md        ← Guia de instalacion en Kali
└── memory/
    └── PRD.md             ← Requerimientos del producto
```

---

## 3. QUE MODIFICAR ANTES DE ARRANCAR EN KALI LINUX

### 3.1 Archivo: backend/.env

CAMBIAR estas lineas:
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

NOTAS:
- MONGO_URL: Solo cambiar si MongoDB corre en otro host/puerto
- DB_NAME: Puedes poner el nombre que quieras para la base de datos
- CORS_ORIGINS: DEBE ser "http://localhost:3000" para desarrollo local
- KIMI_API_KEY: Ya viene configurada. API key de Moonshot AI (Kimi K2)
- MSF_RPC_TOKEN: Tu token para msfrpcd (ya configurado)
- MSF_RPC_HOST/PORT: Host y puerto del msfrpcd (default 127.0.0.1:55553)
- SLIVER_CONFIG_PATH: Ruta al config de operador Sliver (dejar vacio si no lo usas)

### 3.2 Archivo: frontend/.env

CAMBIAR esta linea:
```
REACT_APP_BACKEND_URL=http://localhost:8001
```

IMPORTANTE: En la nube tenia la URL de preview de Emergent. Para local DEBE apuntar al backend local.

ELIMINAR o ignorar estas lineas (son para la nube):
```
WDS_SOCKET_PORT=443
ENABLE_HEALTH_CHECK=false
```

### 3.3 Instalar dependencias

Backend:
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install fastapi uvicorn motor python-dotenv httpx pydantic fpdf2 pymetasploit3 sliver-py websockets
```

Frontend:
```bash
cd frontend
yarn install
```

### 3.4 Asegurar que MongoDB esta corriendo

```bash
sudo systemctl start mongod
# o
sudo systemctl start mongodb
```

### 3.5 Arrancar servicios

Terminal 1 (Backend):
```bash
cd backend
source venv/bin/activate
uvicorn server:app --host 0.0.0.0 --port 8001 --reload
```

Terminal 2 (Frontend):
```bash
cd frontend
yarn start
```

Abrir: http://localhost:3000

---

## 4. COMO FUNCIONA LA HERRAMIENTA - FLUJO COMPLETO

### 4.1 Flujo Principal

1. Pones un TARGET (IP, dominio, rango CIDR)
2. Seleccionas las FASES del Kill Chain que quieres ejecutar (RECON, INITIAL ACCESS, etc.)
3. Das click en ENGAGE
4. El framework ejecuta herramientas automaticamente segun las fases seleccionadas
5. Despues de cada herramienta, el TACTICAL ENGINE analiza resultados y adapta el plan
6. Cuando termina, la IA (Kimi K2) analiza todo y recomienda exploits
7. Se genera un ATTACK TREE con nodos de accion priorizados
8. Se sugieren CADENAS DE ATAQUE automaticas basadas en hallazgos
9. Se muestran MODULOS MSF RECOMENDADOS segun servicios/vulnerabilidades encontradas

### 4.2 Tabs de la Interfaz

| Tab | Funcion |
|-----|---------|
| KILL CHAIN | Seleccionar fases MITRE ATT&CK para el escaneo |
| ATTACK TREE | Arbol interactivo de nodos de ataque generados |
| EXPLOIT | Modulos Metasploit - primero los recomendados, despues todos |
| AI | Analisis de IA, exploits recomendados, boton PDF y JSON, cadenas sugeridas |
| OPS | Historial de operaciones pasadas, descargar/eliminar |
| CHAINS | Cadenas de ataque automatizadas (6 predefinidas) |

### 4.3 MITRE ATT&CK Kill Chain (14 fases seleccionables)

- TA0043 Reconnaissance (RECON)
- TA0042 Resource Development (RESOURCE)
- TA0001 Initial Access (INITIAL ACCESS)
- TA0002 Execution (EXECUTION)
- TA0003 Persistence (PERSISTENCE)
- TA0004 Privilege Escalation (PRIV ESC)
- TA0005 Defense Evasion (EVASION)
- TA0006 Credential Access (CREDS)
- TA0007 Discovery (DISCOVERY)
- TA0008 Lateral Movement (LATERAL)
- TA0009 Collection (COLLECT)
- TA0011 Command and Control (C2)
- TA0010 Exfiltration (EXFIL)
- TA0040 Impact (IMPACT)

Las fases que selecciones determinan que herramientas se ejecutan automaticamente.
Ejemplo: Si seleccionas RECON + INITIAL ACCESS, correra nmap, wafw00f, whatweb, nikto, sqlmap, etc.

---

## 5. VARIANTES DE CONFIGURACION

### 5.1 Herramientas de Escaneo (backend/server.py - RED_TEAM_TOOLS)

El framework tiene 10 herramientas configuradas:

| Herramienta | Fase | Comando |
|------------|------|---------|
| nmap | reconnaissance | nmap -sV -sC -A {target} |
| masscan | reconnaissance | masscan -p1-65535 {target} --rate=1000 |
| subfinder | reconnaissance | subfinder -d {target} |
| wafw00f | reconnaissance | wafw00f {target} |
| whatweb | reconnaissance | whatweb {target} |
| gobuster | reconnaissance | gobuster dir -u {target} -w wordlist.txt |
| nikto | initial_access | nikto -h {target} |
| sqlmap | initial_access | sqlmap -u '{target}' --batch |
| hydra | initial_access | hydra -L users.txt -P pass.txt {target} ssh |
| crackmapexec | initial_access | crackmapexec smb {target} |

**COMPORTAMIENTO:**
- Si la herramienta ESTA INSTALADA en Kali: ejecuta el comando REAL
- Si NO esta instalada: retorna resultado SIMULADO (marcado con "simulated: true")

### 5.2 Cadenas de Ataque (6 predefinidas)

| ID | Nombre | Descripcion | Triggers |
|----|--------|-------------|----------|
| web_to_shell | Web App to Shell | SQLi/RCE -> Credential Dump -> Persistence | sql injection, rce, command injection |
| smb_to_domain | SMB to Domain Admin | EternalBlue -> Hashdump -> Lateral -> DC | smb, 445, ms17-010 |
| kerberos_attack | Kerberos Attack Chain | User Enum -> AS-REP -> Kerberoast -> Golden Ticket | kerberos, 88, active directory |
| linux_privesc | Linux Privilege Escalation | Shell -> Enum -> Exploit -> Root | linux, shell, ssh |
| windows_privesc | Windows Privilege Escalation | Shell -> Enum -> Exploit -> SYSTEM | windows, shell, rdp, winrm |
| phishing_to_shell | Phishing to Internal Access | Phish -> Macro -> Beacon -> Pivot | phishing, email, social |

Modos de ejecucion:
- PREPARE (MANUAL): Genera la cadena y te deja ejecutar paso a paso con boton [RUN]
- AUTO-EXECUTE: Ejecuta toda la cadena automaticamente en secuencia con tracking en tiempo real

### 5.3 WAF Bypass Strategies (5 WAFs + generico)

Si el escaneo detecta un WAF, el Tactical Engine adapta automaticamente:
- Cloudflare: Origin IP discovery via DNS history/SSL certificates
- Akamai: Edge bypass, request smuggling
- AWS WAF: Unicode normalization, regional bypass
- Imperva: MX/SPF records, payload fragmentation
- ModSecurity: Rule bypass, anomaly score gaming
- Generico: Encoding, origin discovery, protocol switch

### 5.4 Modulos Metasploit (11 precargados)

Exploits: Shellshock, Log4Shell, EternalBlue, PwnKit, Dirty Pipe, BlueKeep
Auxiliary: EternalBlue Scanner, SSH Brute Force, Dir Scanner
Post: Hash Dump, Exploit Suggester

**DESPUES de un escaneo**, el tab EXPLOIT muestra primero los modulos RECOMENDADOS
segun los servicios/vulnerabilidades encontrados (con score de relevancia).
Los demas modulos aparecen abajo como referencia.

---

## 6. REPORTES

### 6.1 Reporte JSON
- Tab AI > Boton "JSON" 
- Tab OPS > Icono de descarga por cada operacion
- Contiene toda la data cruda del escaneo

### 6.2 Reporte PDF (NUEVO)
- Tab AI > Boton "PDF REPORT"
- Estilo informal entre colegas
- Contenido:
  * Resumen de lo que se encontro
  * Resultados por herramienta
  * Analisis tactico (WAF, servicios, vulnerabilidades)
  * Analisis de IA (Kimi K2)
  * Cadenas de ataque sugeridas
  * Modulos MSF recomendados

### 6.3 Donde se almacenan
- MongoDB, coleccion "scans"
- Se pueden consultar via API: GET /api/scan/history
- Se pueden descargar individualmente

---

## 7. QUE SE PUEDE Y NO SE PUEDE MODIFICAR/AGREGAR

### 7.1 SE PUEDE agregar facilmente:

**Nuevas herramientas de escaneo:**
En server.py, agregar al diccionario RED_TEAM_TOOLS:
```python
"nueva_herramienta": {
    "phase": "reconnaissance",      # Fase del Kill Chain
    "mitre": "T1595",              # Tecnica MITRE
    "cmd": "herramienta {target}",  # Comando (usa {target} como placeholder)
    "desc": "Descripcion"
}
```
El framework la ejecutara automaticamente si esta instalada.

**Nuevos modulos Metasploit:**
En server.py, agregar a la lista METASPLOIT_MODULES:
```python
{"name": "exploit/windows/smb/nuevo_exploit", "desc": "Mi exploit", "rank": "excellent", "category": "exploit", "mitre": "T1210"}
```

**Nuevas cadenas de ataque:**
En server.py, agregar al diccionario AttackChainEngine.ATTACK_CHAINS:
```python
"mi_cadena": {
    "name": "Mi Cadena Custom",
    "description": "Paso 1 -> Paso 2 -> ...",
    "trigger": ["palabra_clave1", "palabra_clave2"],
    "steps": [
        {"id": 1, "name": "Nombre del paso", "actions": [
            {"tool": "herramienta", "cmd": "comando {target}", "condition": "condicion"}
        ]}
    ]
}
```

**Nuevas estrategias WAF:**
En server.py, agregar al diccionario TacticalDecisionEngine.WAF_BYPASS_STRATEGIES

**Nuevos mapeos servicio->ataque:**
En server.py, agregar a TacticalDecisionEngine.SERVICE_ATTACK_MAP

### 7.2 NO se puede hacer sin modificacion significativa:

- **Ejecutar herramientas en maquinas remotas** (actualmente todo corre local en Kali)
- **Integracion real con Metasploit via RPC** (usa subprocess, no msfrpcd)
- **Integracion con C2 frameworks** (Sliver, Havoc, Cobalt Strike - no implementado)
- **Sesiones persistentes de Meterpreter** (el exploit runner es fire-and-forget)
- **Autenticacion de usuarios** (no hay login, cualquiera con acceso a la URL puede usarla)
- **Multi-target simultaneo** (un scan a la vez)

---

## 8. CAMBIOS REALIZADOS EN ESTA SESION (Feb 2026)

### Cambio 1: Motor de Ejecucion de Attack Chains (P1)
- Antes: Las cadenas solo se mostraban
- Ahora: Se ejecutan paso a paso con tracking en tiempo real
- Dos modos: PREPARE (manual, botones [RUN] por paso) y AUTO-EXECUTE (automatico)
- Pipeline visual de progreso (S1 > S2 > S3 > S4) con colores de estado
- Polling cada 1.5 segundos durante ejecucion automatica

### Cambio 2: Modulos MSF Recomendados segun Escaneo
- Antes: El tab EXPLOIT mostraba todos los modulos sin filtrar
- Ahora: Despues de un escaneo, los modulos relevantes aparecen primero con:
  * Score de relevancia (basado en servicios/vulns detectados)
  * Razones de por que se recomienda (ej: "SMB service detected")
  * Los demas modulos siguen disponibles abajo

### Cambio 3: Generacion de Reportes PDF
- Nuevo endpoint: GET /api/scan/{id}/report/pdf
- Estilo informal "entre colegas" en espanol
- Incluye: resultados por herramienta, analisis tactico, analisis IA, cadenas sugeridas, modulos recomendados
- Boton "PDF REPORT" en el tab AI

### Cambio 4: Auto-sugerencia de Cadenas de Ataque
- Antes: El usuario tenia que elegir manualmente que cadena aplicar
- Ahora: Despues de un escaneo, el sistema detecta automaticamente que cadenas aplican
  basandose en los hallazgos (ej: si detecta SMB -> sugiere "SMB to Domain Admin")
- Se muestran en el tab AI como tarjetas clickeables
- Se anuncian en el terminal

### Cambio 5: Integracion con Metasploit RPC (msfrpcd) - NUEVO
- Se conecto al daemon RPC de Metasploit para control real
- En tu Kali ejecuta: msfrpcd -P 13nHJ54CoGYr5jCeI0iXXU4YsAnkItfv -S -a 127.0.0.1
- Permite:
  * Buscar modulos directamente del MSF instalado (no solo los precargados)
  * Ejecutar exploits via RPC (con job tracking)
  * Ver y controlar sesiones activas (Meterpreter, shell)
  * Ejecutar comandos en sesiones abiertas
  * Ver y matar jobs activos
- Tab C2 > Seccion METASPLOIT RPC

### Cambio 6: WebSocket para Actualizaciones en Tiempo Real - NUEVO
- Antes: Frontend preguntaba "ya terminaste?" cada 2 segundos (polling)
- Ahora: Backend avisa instantaneamente cuando algo pasa (WebSocket)
- Endpoints WS: /api/ws/scan/{id} y /api/ws/chain/{id}
- Fallback automatico a polling si WebSocket falla
- Los resultados del escaneo aparecen en tiempo real sin delay

### Cambio 7: Integracion con Sliver C2 - NUEVO
- Framework de Command & Control open source para post-explotacion
- Para activar en tu Kali:
  1. curl https://sliver.sh/install|sudo bash
  2. sliver-server
  3. new-operator --name redteam --lhost 127.0.0.1
  4. Pon la ruta del config en SLIVER_CONFIG_PATH en backend/.env
- Permite:
  * Ver sesiones y beacons activos
  * Generar implants (Session o Beacon) para Linux/Windows/macOS
  * Ejecutar comandos en sesiones de Sliver
  * Iniciar listeners (mTLS, HTTPS, HTTP, DNS)
  * Ver implants generados
- Tab C2 > Seccion SLIVER C2

### Cambio 8: Tab C2 Unificado - NUEVO
- Nuevo tab "C2" en la interfaz con dashboard unificado
- Muestra status de MSF RPC y Sliver en un solo lugar
- Busqueda de modulos MSF via RPC
- Shell interactiva para sesiones (MSF y Sliver)
- Generador de implants Sliver con config visual
- Botones de Quick Start Listeners
- Indicadores MSF:ON y SLIVER:ON en la barra de status

---

## 9. API ENDPOINTS COMPLETOS

| Metodo | Endpoint | Descripcion |
|--------|----------|-------------|
| GET | /api/ | Health check |
| GET | /api/mitre/tactics | 14 tacticas MITRE ATT&CK |
| GET | /api/tools | Herramientas disponibles (filtrable por fase) |
| POST | /api/scan/start | Iniciar escaneo {target, scan_phases, tools} |
| GET | /api/scan/{id}/status | Status del escaneo (incluye suggested_chains, recommended_modules) |
| GET | /api/scan/{id}/tree | Attack tree del escaneo |
| PUT | /api/scan/{id}/tree/node/{node_id} | Actualizar status de nodo |
| GET | /api/scan/{id}/report | Reporte JSON completo |
| GET | /api/scan/{id}/report/pdf | Descargar reporte PDF |
| GET | /api/scan/history | Historial de escaneos |
| DELETE | /api/scan/{id} | Eliminar escaneo |
| GET | /api/chains | Listar 6 cadenas de ataque |
| GET | /api/chains/{id} | Detalles de una cadena |
| POST | /api/chains/execute | Ejecutar cadena (manual o auto) |
| GET | /api/chains/execution/{id} | Status de ejecucion de cadena |
| POST | /api/chains/execution/{id}/step/{step_id} | Ejecutar paso individual |
| POST | /api/chains/detect | Detectar chains aplicables segun hallazgos |
| POST | /api/chains/{id}/generate | Generar comandos con variables de contexto |
| GET | /api/metasploit/modules | Listar modulos MSF estaticos (filtrable) |
| POST | /api/metasploit/execute | Ejecutar modulo MSF via subprocess |
| GET | /api/tactical/waf-bypass/{waf} | Estrategias de bypass para WAF especifico |
| GET | /api/tactical/service-attacks | Mapeo servicio -> ataque |
| GET | /api/tactical/vuln-exploits | Mapeo vulnerabilidad -> exploit |
| **WS** | **/api/ws/scan/{id}** | **WebSocket tiempo real para escaneos** |
| **WS** | **/api/ws/chain/{id}** | **WebSocket tiempo real para cadenas** |
| **GET** | **/api/msf/status** | **Status conexion msfrpcd** |
| **POST** | **/api/msf/connect** | **Reconectar a msfrpcd** |
| **GET** | **/api/msf/search?query=** | **Buscar modulos via RPC** |
| **GET** | **/api/msf/module/info** | **Info detallada de modulo via RPC** |
| **POST** | **/api/msf/module/execute** | **Ejecutar modulo via RPC** |
| **GET** | **/api/msf/sessions** | **Listar sesiones MSF activas** |
| **POST** | **/api/msf/session/command** | **Ejecutar comando en sesion MSF** |
| **GET** | **/api/msf/jobs** | **Listar jobs MSF activos** |
| **POST** | **/api/msf/job/kill** | **Matar job MSF** |
| **GET** | **/api/sliver/status** | **Status conexion Sliver** |
| **GET** | **/api/sliver/sessions** | **Listar sesiones Sliver** |
| **GET** | **/api/sliver/beacons** | **Listar beacons Sliver** |
| **GET** | **/api/sliver/implants** | **Listar implants generados** |
| **POST** | **/api/sliver/implant/generate** | **Generar implant Sliver** |
| **POST** | **/api/sliver/session/exec** | **Ejecutar comando en sesion Sliver** |
| **POST** | **/api/sliver/listener/start** | **Iniciar listener Sliver** |
| **GET** | **/api/c2/dashboard** | **Dashboard unificado MSF + Sliver** |

---

## 10. INTEGRACION CON IA - MOONSHOT KIMI K2

- API Base URL: https://api.moonshot.ai/v1/chat/completions
- Modelo: kimi-k2-0711-preview
- La IA actua como Red Team Advisor
- Recibe los resultados del escaneo + analisis tactico
- Responde en espanol con: validacion del analisis, ajustes al plan, secuencia optima, comandos especificos, contingencias
- API Key actual: sk-4zTj5qtLiyJTrzGPmf7DQYsFMplk2B5QvvP69EPJb3N3fwDQ

---

## 11. RESUMEN DE TECNOLOGIAS

- Frontend: React 19, TailwindCSS, Shadcn UI, Lucide icons, Axios
- Backend: FastAPI, Motor (MongoDB async), httpx, fpdf2 (PDF), pydantic
- Database: MongoDB
- IA: Moonshot AI (Kimi K2) via REST API
- Tema visual: Matrix/Cyberpunk (fuente VT323/Courier, colores #FF003C #00FF41 #00F0FF #FFB000)

---

FIN DEL REPORTE
