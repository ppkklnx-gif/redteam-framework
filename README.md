# Red Team Automation Framework v7.0 — AI-Driven

Plataforma de automatización Red Team con arquitectura **Local-First**: SQLite, sistema de Jobs async, orquestación adaptativa, C2 (Metasploit + Sliver), generador de payloads, y análisis AI.

## Instalación (Kali Linux)

```bash
git clone https://github.com/TU_USUARIO/TU_REPO.git
cd TU_REPO
chmod +x install.sh run.sh stop.sh doctor.sh
./install.sh
nano backend/.env       # Configura tus keys (KIMI_API_KEY, MSF_RPC_TOKEN, LISTENER_IP)
./run.sh
```

Abrir: `http://localhost:3000`

## Scripts

| Script | Función |
|---|---|
| `./install.sh` | Instala .venv, dependencias, crea directorios |
| `./run.sh` | Arranca backend + frontend |
| `./stop.sh` | Para todo limpiamente (sin orphans) |
| `./doctor.sh` | Diagnóstico profundo del sistema |

## Arquitectura

| Componente | Tecnología |
|---|---|
| Frontend | React 19, TailwindCSS |
| Backend | FastAPI, Python, SQLite |
| Database | SQLite (local, sin Docker) |
| Job System | Async jobs con polling |
| MSF RPC | msfrpcd (opcional) |
| Sliver C2 | sliver-server (opcional) |
| Herramientas | nmap, nikto, sqlmap, hydra, gobuster |
| AI | Moonshot/Kimi K2 (opcional) |
