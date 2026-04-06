"""Configuration management with validation."""
import os
import ipaddress
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

from dotenv import load_dotenv

ROOT_DIR = Path(__file__).parent.parent.resolve()
BACKEND_DIR = Path(__file__).parent.resolve()

# Load .env from backend dir
load_dotenv(BACKEND_DIR / ".env")


@dataclass
class Config:
    # App
    app_mode: str = "local"  # local | lab | vps
    backend_port: int = 8001
    frontend_port: int = 3000
    cors_origins: str = "*"

    # Database
    db_path: str = ""

    # Listener
    listener_ip: str = ""
    listener_port: int = 4444

    # MSF RPC (optional)
    msf_rpc_host: str = "127.0.0.1"
    msf_rpc_port: int = 55553
    msf_rpc_token: str = ""

    # Sliver (optional)
    sliver_config_path: str = ""

    # AI (optional)
    kimi_api_key: str = ""

    # Runtime
    pid_file: str = ""
    log_level: str = "INFO"

    # Validation errors collected during load
    warnings: list = field(default_factory=list)
    errors: list = field(default_factory=list)

    def validate(self):
        """Validate configuration, populate warnings/errors."""
        self.warnings = []
        self.errors = []

        # DB
        if not self.db_path:
            self.errors.append("DB_PATH is empty")
        else:
            db_dir = Path(self.db_path).parent
            if not db_dir.exists():
                try:
                    db_dir.mkdir(parents=True, exist_ok=True)
                except Exception as e:
                    self.errors.append(f"Cannot create DB directory {db_dir}: {e}")

        # Listener
        if not self.listener_ip:
            self.warnings.append("LISTENER_IP not set — payloads will not have LHOST configured")
        else:
            try:
                ipaddress.ip_address(self.listener_ip)
            except ValueError:
                self.errors.append(f"LISTENER_IP '{self.listener_ip}' is not a valid IP address")

        if self.listener_port < 1 or self.listener_port > 65535:
            self.errors.append(f"LISTENER_PORT {self.listener_port} out of range (1-65535)")

        # MSF RPC
        if self.msf_rpc_token:
            if self.msf_rpc_host in ("mongo", "backend", "frontend", "redteam-backend"):
                self.errors.append(f"MSF_RPC_HOST '{self.msf_rpc_host}' looks like a Docker container name. Use 127.0.0.1 for local.")
        else:
            self.warnings.append("MSF_RPC_TOKEN not set — Metasploit integration disabled")

        # Sliver
        if self.sliver_config_path:
            p = Path(os.path.expanduser(self.sliver_config_path))
            if p.is_dir():
                self.errors.append(f"SLIVER_CONFIG_PATH is a directory, not a file: {p}")
            elif not p.exists():
                self.warnings.append(f"SLIVER_CONFIG_PATH file not found: {p}")
        else:
            self.warnings.append("SLIVER_CONFIG_PATH not set — Sliver integration disabled")

        # AI
        if not self.kimi_api_key:
            self.warnings.append("KIMI_API_KEY not set — AI analysis disabled")

        # Mode consistency
        if self.app_mode == "local" and self.listener_ip and not self.listener_ip.startswith(("10.", "172.", "192.168.", "100.")):
            self.warnings.append(f"APP_MODE=local but LISTENER_IP={self.listener_ip} looks like a public IP. Consider APP_MODE=vps")

        return len(self.errors) == 0


def load_config() -> Config:
    """Load config from environment variables."""
    data_dir = BACKEND_DIR / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    default_db = str(data_dir / "redteam.db")

    raw_db_path = os.environ.get("DB_PATH", "").strip().strip('"').strip("'")
    db_path = raw_db_path if raw_db_path else default_db

    cfg = Config(
        app_mode=os.environ.get("APP_MODE", "local"),
        backend_port=int(os.environ.get("BACKEND_PORT", "8001")),
        frontend_port=int(os.environ.get("FRONTEND_PORT", "3000")),
        cors_origins=os.environ.get("CORS_ORIGINS", "*"),
        db_path=db_path,
        listener_ip=os.environ.get("LISTENER_IP", ""),
        listener_port=int(os.environ.get("LISTENER_PORT", "4444")),
        msf_rpc_host=os.environ.get("MSF_RPC_HOST", "127.0.0.1"),
        msf_rpc_port=int(os.environ.get("MSF_RPC_PORT", "55553")),
        msf_rpc_token=os.environ.get("MSF_RPC_TOKEN", ""),
        sliver_config_path=os.environ.get("SLIVER_CONFIG_PATH", ""),
        kimi_api_key=os.environ.get("KIMI_API_KEY", ""),
        pid_file=os.environ.get("PID_FILE", str(BACKEND_DIR / "data" / "backend.pid")),
        log_level=os.environ.get("LOG_LEVEL", "INFO"),
    )
    cfg.validate()
    return cfg


# Singleton
config = load_config()
