# Red Team Automation Framework v4.0 - PRD

## Problem Statement
Framework Red Team profesional con MITRE ATT&CK, Tactical Decision Engine, Moonshot AI (Kimi K2), Attack Chains automatizadas, integracion real con msfrpcd, Sliver C2, WebSocket real-time, y reportes PDF.

## What's Implemented (Feb 2026)

### Core Features
- [x] 14 tacticas MITRE ATT&CK seleccionables
- [x] 10 herramientas Red Team
- [x] 11+ modulos Metasploit precargados
- [x] Tema Matrix/Cyberpunk
- [x] Moonshot AI (Kimi K2) Red Team Advisor
- [x] Scan system con background tasks

### Tactical Decision Engine
- [x] WAF bypass strategies (5 WAFs + generico)
- [x] Service-to-attack, Vulnerability-to-exploit mapping
- [x] Adaptive planning

### Attack Chains
- [x] 6 cadenas predefinidas con motor de ejecucion
- [x] Modo manual (paso a paso) y AUTO-EXECUTE
- [x] Pipeline visual, auto-sugerencia post-scan

### Smart Exploits & Reports
- [x] Modulos MSF recomendados por relevancia del escaneo
- [x] JSON y PDF report downloads
- [x] PDF estilo informal entre colegas

### msfrpcd Integration (NEW)
- [x] Conexion real al daemon RPC de Metasploit
- [x] Busqueda de modulos via RPC
- [x] Ejecucion de exploits via RPC con job tracking
- [x] Session management (shell commands)
- [x] Job listing y kill

### WebSocket Real-time (NEW)
- [x] WS para scan progress (/ws/scan/{id})
- [x] WS para chain execution (/ws/chain/{id})
- [x] Fallback automatico a polling

### Sliver C2 Integration (NEW)
- [x] Session y beacon management
- [x] Implant generation (Linux/Windows/macOS)
- [x] Listener management (mTLS, HTTPS, HTTP, DNS)
- [x] Command execution on sessions

### C2 Unified Dashboard (NEW)
- [x] Tab C2 con MSF + Sliver status
- [x] Interactive session shell
- [x] Quick Start Listeners

## Architecture
- Frontend: React + TailwindCSS + Shadcn UI + WebSocket
- Backend: FastAPI + Motor + pymetasploit3 + sliver-py
- Database: MongoDB
- AI: Moonshot AI (Kimi K2)
- C2: Metasploit RPC + Sliver gRPC

## Prioritized Backlog

### P2
- [ ] BloodHound AD attack paths
- [ ] Real nmap/nikto output parsing (not simulated)
- [ ] Multi-target campaign management

### P3
- [ ] User authentication
- [ ] Cobalt Strike Beacon simulation
- [ ] Deploy-ready Docker compose
