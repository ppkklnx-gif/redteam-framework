# Red Team Automation Framework — PRD v7.0

## Problem Statement
Automated Red Team / pentesting framework with **AI-driven** adaptive scanning. The AI (Kimi K2) decides which tool to run next based on results. Local-First: SQLite, async Jobs, no Docker, no msfrpcd/Sliver RPC dependencies.

## Architecture (v7.0 — AI-Driven)
- **Backend**: FastAPI + SQLite (aiosqlite) + Async Job System + AI Decision Engine
- **Frontend**: React 19 + TailwindCSS (CRA native, `baseUrl: "src"` in jsconfig.json)
- **Database**: SQLite (repository pattern via `db.py`)
- **AI Engine**: Kimi K2 (Moonshot) decides next tool after each step, with rule-based fallback
- **Tools**: All CLI-based (nmap, nuclei, nikto, sqlmap, hydra, msfconsole, etc.)
- **Metasploit**: Direct CLI (`msfconsole -q -x`) — no msfrpcd needed
- **Deployment**: Local-First on Kali Linux. NO Docker needed. NO craco.

## Completed
- [x] MongoDB -> SQLite migration
- [x] Async Job system
- [x] Local-first operational scripts (install/run/stop/doctor)
- [x] AI-driven scan engine (Kimi K2)
- [x] Nuclei integration + MSF CLI only
- [x] Fixed NPM peer dependency conflicts (date-fns, eslint@9, react-day-picker, react-flow-renderer)
- [x] Eliminated craco dependency — all `@/` aliases replaced with CRA native `baseUrl: "src"` resolution
- [x] Removed: @emergentbase/visual-edits, @craco/craco, eslint plugins, react-flow-renderer, react-force-graph-2d, react-router-dom, recharts
- [x] Updated install.sh with robust npm handling

## Backlog
- P1: Modularize App.js into components
- P1: Add real-time AI decision log panel
- P2: PostgreSQL support via repository pattern
- P2: BloodHound AD integration
