# Red Team Automation Framework — PRD v7.2

## Problem Statement
Automated Red Team / pentesting framework with **AI-driven** OFFENSIVE scanning. Local-First on Kali Linux.

## Architecture
- **Backend**: FastAPI + SQLite + Async Jobs + AI Engine (Kimi K2)
- **Frontend**: React 19 + TailwindCSS (CRA native)
- **Database**: SQLite (repository pattern)
- **Deployment**: Local-First. NO Docker.

## v7.2 Changes (Apr 7, 2026) — EXPLOITATION ENGINE
- [x] AI prompt rewritten: OFFENSIVE focus, max 3 recon tools then MUST exploit
- [x] Auto-exploit engine: maps open ports → attack tools automatically
- [x] New tools: hydra_mysql, hydra_http, nmap_smb_vuln, enum4linux
- [x] Fallback decision: recon(2-3) → nuclei → EXPLOIT based on findings
- [x] POST-AI forced exploitation: if AI only did recon, system forces attacks
- [x] SQLMap upgraded: --forms --crawl=2 --risk 2 for deeper exploitation
- [x] AI final analysis prompt: includes exploitation results and credentials
- [x] Scan limits: 15 tools, 1200s (up from 12/900)
- [x] Chain auto-execute: runs all steps with real tool execution
- [x] Frontend log dedup (no spam)

## Attack Flow
1. Recon (max 3): nmap → whatweb → wafw00f
2. Vuln Scan: nuclei
3. AUTO-EXPLOIT based on findings:
   - FTP(21) → hydra_ftp
   - SSH(22) → hydra_ssh
   - MySQL(3306) → hydra_mysql
   - HTTP(80/443) → sqlmap
   - SMB(445) → nmap_smb_vuln + enum4linux
4. AI decides additional exploits (msfconsole, custom commands)
5. POST-AI: Force exploits if AI chickened out

## Backlog
- P1: Modularize App.js
- P2: PostgreSQL support
- P2: BloodHound AD
