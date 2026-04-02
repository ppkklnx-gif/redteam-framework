# Red Team Automation Framework v3.1 - PRD

## Problem Statement
Framework Red Team profesional con MITRE ATT&CK y **Tactical Decision Engine** que adapta el plan de ataque en tiempo real basado en los hallazgos.

## Key Feature: Tactical Decision Engine

### ¿Qué hace?
Analiza resultados DESPUÉS de cada herramienta y adapta la estrategia:

1. **WAF Detection → Bypass Strategies**
   - Cloudflare: Origin IP discovery, DNS history
   - Akamai: Edge bypass, request smuggling
   - AWS WAF: Unicode normalization
   - Imperva: MX/SPF records analysis

2. **Service Discovery → Attack Mapping**
   - SSH (22) → Credential brute force, key auth
   - HTTP (80/443) → Nikto, SQLmap, directory enum
   - SMB (445) → EternalBlue, null sessions
   - RDP (3389) → BlueKeep, credential spray
   - Kerberos (88) → AS-REP roasting, Kerberoasting

3. **Vulnerability → Exploit Mapping**
   - SQL Injection → sqlmap + credential dump
   - XSS → Session hijacking, phishing
   - LFI/RFI → Log poisoning, RCE
   - Shellshock → Direct RCE
   - Log4Shell → JNDI callback

## Architecture
- **TacticalDecisionEngine**: Motor de decisión adaptativo
- **Kimi K2 AI**: Red Team Advisor con contexto táctico
- **Attack Tree**: Nodos con prioridades basadas en análisis
- **Real-time Updates**: Decisiones mostradas en terminal

## What's Implemented (Jan 2026)
- [x] 14 tácticas MITRE ATT&CK seleccionables
- [x] 34 herramientas Red Team categorizadas
- [x] 35+ módulos Metasploit con MITRE mapping
- [x] Tactical Decision Engine con adaptación en tiempo real
- [x] WAF bypass strategies para 5+ WAFs
- [x] Service-to-attack mapping para 10+ servicios
- [x] Vulnerability-to-exploit mapping
- [x] Attack tree con nodos de prioridad
- [x] AI advisor con contexto táctico

## API Endpoints
- GET /api/tactical/waf-bypass/{waf} - Estrategias bypass
- GET /api/tactical/service-attacks - Mapeo servicio→ataque
- GET /api/tactical/vuln-exploits - Mapeo vuln→exploit
- POST /api/scan/start - Inicia con tactical_decisions
- GET /api/scan/{id}/status - Incluye final_tactical

## Prioritized Backlog

### P0 - Completado
- ✅ Tactical Decision Engine
- ✅ WAF bypass strategies
- ✅ Adaptive planning

### P1 (High)
- [ ] Cobalt Strike Beacon simulation
- [ ] C2 Framework integration (Sliver/Havoc)
- [ ] BloodHound AD attack paths
- [ ] Real Metasploit integration

### P2 (Medium)
- [ ] WebSocket real-time updates
- [ ] Automated exploitation chains
- [ ] Report generation PDF

## Next Tasks
1. Desplegar en Kali Linux real
2. Integrar msfrpcd para MSF real
3. Agregar C2 framework support
