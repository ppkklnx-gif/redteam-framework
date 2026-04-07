# Red Team Automation Framework — PRD v7.0

## Problem Statement
Automated Red Team / pentesting framework with **AI-driven** adaptive scanning. The AI (Kimi K2) decides which tool to run next based on results. Local-First: SQLite, async Jobs, no Docker, no msfrpcd/Sliver RPC dependencies.

## Architecture (v7.0 — AI-Driven)
- **Backend**: FastAPI + SQLite (aiosqlite) + Async Job System + AI Decision Engine
- **Frontend**: React 19 + TailwindCSS + Craco (webpack alias `@/` -> `src/`)
- **Database**: SQLite (repository pattern via `db.py`)
- **AI Engine**: Kimi K2 (Moonshot) decides next tool after each step, with rule-based fallback
- **Tools**: All CLI-based (nmap, nuclei, nikto, sqlmap, hydra, msfconsole, etc.)
- **Metasploit**: Direct CLI (`msfconsole -q -x`) — no msfrpcd needed
- **Deployment**: Local-First on Kali Linux. NO Docker needed.

## Key Changes in v7.0
- REMOVED: MSF RPC (msfrpcd), Sliver C2, all RPC-dependent modules
- ADDED: AI-driven scan loop (AI decides each step)
- ADDED: Nuclei integration (8000+ vulnerability templates)
- ADDED: `/api/msf/run` (direct CLI commands)

## Completed
- [x] MongoDB -> SQLite migration
- [x] Async Job system
- [x] Local-first operational scripts (install/run/stop/doctor)
- [x] AI-driven scan engine (Kimi K2)
- [x] Nuclei integration + MSF CLI only
- [x] Fixed NPM peer dependency conflicts (date-fns, eslint@9, react-day-picker, react-flow-renderer)
- [x] Fixed `@/` alias resolution — simplified craco.config.js, removed Emergent-only deps
- [x] Removed unused deps: react-flow-renderer, react-force-graph-2d, react-router-dom, recharts, eslint plugins
- [x] Updated install.sh with robust npm handling

## Backlog
- P1: Modularize App.js into components
- P1: Add real-time AI decision log panel
- P2: PostgreSQL support via repository pattern
- P2: BloodHound AD integration
