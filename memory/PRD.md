# Red Team Automation Framework — PRD

## Problem Statement
Automated Red Team / pentesting framework with adaptive scanning, AI-driven tactical analysis, attack chain execution, and C2 integration (Metasploit RPC + Sliver). The framework uses a Local-First architecture: SQLite database, async Job system, and robust operational scripts. No Docker required for core operations.

## Architecture (v6.0 — Local-First)
- **Backend**: FastAPI (Python) + SQLite (aiosqlite) + Async Job System
- **Frontend**: React 19 + TailwindCSS
- **Database**: SQLite at `/app/backend/data/redteam.db` (repository pattern via `db.py` for future PostgreSQL migration)
- **Job System**: `jobs.py` — wraps long operations (scans, payloads) into async jobs with progress tracking and log streaming
- **Config**: Strict `.env` validation via `config.py`
- **Integrations** (all optional): Metasploit RPC (msfrpcd), Sliver C2, Kimi AI (Moonshot K2)

## Key Files
- `/app/backend/server.py` — Main FastAPI app, all API routes
- `/app/backend/db.py` — SQLite repository layer (tables: jobs, scans, credentials, events, config, chain_executions, custom_tools, custom_modules)
- `/app/backend/jobs.py` — Async job submission, tracking, cancellation
- `/app/backend/config.py` — Env validation (APP_MODE, DB_PATH, KIMI_API_KEY, MSF_RPC_*, SLIVER_CONFIG_PATH)
- `/app/backend/modules/` — Metasploit RPC, Sliver C2, Credential Vault, Session Manager
- `/app/frontend/src/App.js` — React UI with polling-based scan tracking
- `/app/install.sh`, `/app/run.sh`, `/app/stop.sh`, `/app/doctor.sh` — Operational scripts

## API Endpoints
- `GET /api/` — Root info (version, architecture)
- `GET /api/health` — Fast health check (DB, MSF, Sliver, Listener, active jobs)
- `GET /api/doctor` — Deep diagnostic (tools, integrations, config warnings, hints)
- `POST /api/scan/start` — Start adaptive scan (returns scan_id + job_id)
- `GET /api/scan/{id}/status` — Poll scan progress (in-memory if active, SQLite if completed)
- `GET /api/scan/{id}/tree` — Attack tree
- `GET /api/scan/history` — All scans from SQLite
- `GET /api/scan/{id}/report/pdf` — PDF export
- `POST /api/jobs/{type}/start` — Generic job start
- `GET /api/jobs/{id}` — Job status
- `GET /api/jobs/{id}/logs` — Job log stream
- `POST /api/jobs/{id}/cancel` — Cancel running job
- `GET /api/jobs` — List all jobs
- `GET/PUT /api/config` — Global config (listener_ip, listener_port, etc.)
- `GET /api/chains` — Attack chain catalog
- `POST /api/chains/execute` — Execute chain
- `GET /api/tools` — Tool catalog (expandable)
- `GET /api/payloads/templates` — Payload generation templates
- `GET /api/mitre/tactics` — MITRE ATT&CK mapping
- MSF RPC: `/api/msf/*`
- Sliver: `/api/sliver/*`
- C2 Dashboard: `/api/c2/dashboard`

## Completed (April 2026)
- [x] Full MongoDB → SQLite migration (db.py repository pattern)
- [x] Async Job system (jobs.py) — scans create jobs, frontend polls status
- [x] Health/Doctor endpoints
- [x] Backend rewrite (server.py) — all Motor/pymongo removed
- [x] Credential vault updated for SQLite
- [x] Frontend polling with job_id tracking and live job logs
- [x] Operational scripts: install.sh, run.sh, stop.sh, doctor.sh
- [x] Docker files cleaned up (docker-compose.yml, DOCKER_DEPLOY.md removed)
- [x] Testing: 19/19 backend, 9/9 frontend tabs — 100% pass

## Backlog
- P1: Break App.js into modular components (ScanPanel, ChainPanel, C2Panel, etc.)
- P1: Add a Logs section that shows real-time job logs in frontend
- P2: PostgreSQL support via repository pattern swap
- P2: BloodHound AD paths & multi-target campaigns
- P2: OpSec/Evasion, payload obfuscation
- P3: User authentication & role-based access
