# Red Team Automation Framework — PRD v7.1

## Problem Statement
Automated Red Team / pentesting framework with **AI-driven** adaptive scanning. Local-First on Kali Linux.

## Architecture
- **Backend**: FastAPI + SQLite + Async Jobs + AI Engine (Kimi K2)
- **Frontend**: React 19 + TailwindCSS (CRA native, no craco)
- **Database**: SQLite (repository pattern)
- **Deployment**: Local-First. NO Docker.

## v7.1 Changes (Apr 7, 2026)
### P0 — Fixed
- [x] AI Engine anti-loop: enforces tool uniqueness, skips nmap variants, fallback on repeat
- [x] AI prompt rewritten: strict rules (no repeat, logical sequence, available tools only)
- [x] Targets: no duplicates allowed, clickable with full report view + "Continue Audit" button
- [x] Chains: fixed 404 (added /chains/{id}, /chains/execute, /chains/execution endpoints)
- [x] Chains: full step details with real commands per chain type (6 chains)

### P1 — Implemented
- [x] Network Map: /scan/{id}/network_map endpoint builds topology (services, subdomains, vulns, WAF, tech)
- [x] Network Map: Frontend shows hierarchical map (target → services → subdomains → vulnerabilities)
- [x] Smart Payloads: /payloads/recommend endpoint analyzes scan results and suggests best payloads
- [x] AI Chain Suggestions: /chains/{scan_id}/suggest recommends chains based on scan findings
- [x] AI Decision Log panel in AI Engine section

### P2 — Implemented
- [x] Dashboard: "Completed" instead of misleading "Compromised"
- [x] Dashboard: Tooltips on MITRE phases explaining what each does
- [x] Removed mTLS option (no Sliver)

## Completed (All)
- MongoDB -> SQLite, Async Jobs, Local scripts
- AI-driven engine (Kimi K2), Nuclei, MSF CLI
- NPM dependency fixes, craco removal
- v7.1 improvements (above)

## Backlog
- P1: Modularize App.js into components (currently ~500 lines, improved from 904)
- P2: PostgreSQL support via repository pattern
- P2: BloodHound AD integration
- P2: Real chain execution (currently prepare-only, needs tool orchestration)
