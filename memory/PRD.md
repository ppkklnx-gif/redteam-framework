# Red Team Automation Framework — PRD v7.1

## Problem Statement
Automated Red Team / pentesting framework with **AI-driven** adaptive scanning. Local-First on Kali Linux.

## Architecture
- **Backend**: FastAPI + SQLite + Async Jobs + AI Engine (Kimi K2)
- **Frontend**: React 19 + TailwindCSS (CRA native, no craco)
- **Database**: SQLite (repository pattern)
- **Deployment**: Local-First. NO Docker.

## Completed (v7.1)
- [x] MongoDB -> SQLite migration + Repository Pattern
- [x] Async Job system (prevents 504 timeouts)
- [x] Local scripts (install/run/stop/doctor)
- [x] AI-driven scan engine (Kimi K2) with anti-loop
- [x] Nuclei + MSF CLI (no msfrpcd)
- [x] NPM dependency fixes, craco removed
- [x] AI anti-loop: no repeat tools, nmap variant detection, fallback
- [x] Targets: no duplicates, clickable detail view + Continue Audit
- [x] Chains: fixed 404, full step details, real commands
- [x] **Chains AUTO-EXECUTE**: runs all steps sequentially with real tool execution
- [x] **Chains MANUAL mode**: step-by-step RUN buttons
- [x] Chain execution polling with real-time progress
- [x] Network Map (target → services → subdomains → vulns)
- [x] Smart Payload recommendations (AI-based)
- [x] AI Chain Suggestions post-scan
- [x] Frontend log spam fix (only logs on change)
- [x] MITRE phase tooltips

## Backlog
- P1: Modularize App.js into components
- P2: PostgreSQL support via repository pattern
- P2: BloodHound AD integration
