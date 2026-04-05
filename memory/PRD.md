# Red Team Automation Framework v5.0 - PRD

## Problem Statement
Framework Red Team con orquestacion adaptativa, boveda de credenciales, cadenas condicionales, msfrpcd, Sliver C2, WebSocket, timeline de ataque, catalogo dinamico de herramientas, generador de payloads con LHOST global, y UI estilo APT/Cyberpunk.

## What's Implemented

### UI Overhaul - APT Style (Apr 2026)
- [x] Dashboard: 4 metricas, MITRE Kill Chain fases, Recent Operations
- [x] Targets: Add/Remove/Scan targets
- [x] Attack Graph: Visual tree of scan results
- [x] Chains: 6 cadenas de ataque con context inputs y ejecucion manual/auto
- [x] C2: MSF + Sliver status panels, session shell interactivo
- [x] Payloads: 11 templates, filtros por plataforma/tipo, generacion con LHOST auto-inyectado
- [x] AI: Kimi K2 analysis, recommended exploits, suggested chains, PDF download
- [x] Config: Global listener IP/Port, C2 protocol, auto-inject LHOST, stealth mode, quick payload commands
- [x] Logs: Terminal output con 6 filtros
- [x] Autonomous Mode toggle
- [x] Cyberpunk dark theme (JetBrains Mono, green/red/cyan accents)

### Payload Generator (Apr 2026)
- [x] 11 payload templates: Windows Meterpreter TCP/HTTPS, Windows Shell, Linux Shell/Meterpreter, PHP, Bash/Python/PowerShell oneliners, Sliver Session/Beacon
- [x] GET /api/payloads/templates - lista todos con LHOST pre-inyectado
- [x] POST /api/payloads/generate - genera payload real con comando exacto
- [x] Oneliners retornan payload_content listo para copiar/pegar
- [x] Binarios retornan generator_cmd (msfvenom) + handler_cmd
- [x] Implants retornan comandos Sliver console
- [x] Validacion: retorna 400 si LHOST no configurado

### Global Listener Config (Apr 2026)
- [x] Backend: GET/PUT /api/config - persistent in MongoDB
- [x] Auto-inject LHOST into all: payloads, MSF rc_command, chain commands, Sliver implants
- [x] Quick Payload Commands: MSFvenom, Bash, Python reverse shells, NC listener, MSF handler
- [x] Sidebar LHOST indicator (green when configured, red when not)

### Core Backend
- [x] Orquestacion Dinamica Adaptativa
- [x] Cadenas integradas al Motor Tactico con auto-trigger
- [x] Boveda de Credenciales
- [x] Ejecucion Condicional en Cadenas
- [x] Session Manager (MSF/Sliver)
- [x] Catalogo Dinamico de Herramientas
- [x] Reportes con Timeline + PDF export
- [x] Abort Scan + safeguards (timeouts, tool limits, stealth mode)

### Integrations
- [x] Moonshot AI (Kimi K2) - analisis tactico
- [x] msfrpcd - Metasploit RPC
- [x] Sliver C2 - gRPC
- [x] WebSocket - real-time scan updates

## Architecture
```
/app/backend/server.py - FastAPI (adaptive orchestration, 50+ endpoints, payload generator)
/app/backend/modules/credential_vault.py
/app/backend/modules/session_manager.py
/app/backend/modules/sliver_c2.py
/app/frontend/src/App.js - React (9 sections)
/app/frontend/src/App.css - Cyberpunk theme
```

## Key API Endpoints
- POST /api/scan/start - Inicia escaneo
- GET /api/scan/{id}/status - Estado del escaneo
- WS /api/ws/scan/{id} - WebSocket live updates
- GET/PUT /api/config - Configuracion global (LHOST/LPORT)
- GET /api/payloads/templates - 11 templates de payloads
- POST /api/payloads/generate - Genera payload con LHOST
- POST /api/chains/execute - Ejecuta cadena de ataque
- POST /api/chains/{id}/generate - Genera comandos de cadena
- POST /api/metasploit/execute - Ejecuta modulo MSF
- GET /api/c2/dashboard - Estado MSF/Sliver
- GET /api/vault - Boveda de credenciales

## Backlog

### P1
- [ ] Refactorizar App.js en componentes separados (~950 lineas)

### P2
- [ ] OpSec/Evasion (ofuscacion, limpieza, tunneling)
- [ ] BloodHound AD paths
- [ ] Multi-target campaigns
- [ ] Expandir credential_vault para inyeccion automatica en MSF/Sliver
