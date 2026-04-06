"""Metasploit RPC Integration Module - Connects to msfrpcd for real exploitation"""
import logging
import time
import threading
import socket
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

# msf_rpc_client singleton
_msf_client = None
_msf_connected = False
_msf_last_error = ""
_msf_retry_count = 0
_msf_max_retries = 5
_msf_reconnect_thread = None
_msf_reconnect_active = False

# Connection config cache
_msf_config = {"token": "", "host": "127.0.0.1", "port": 55553, "ssl": True}


def _test_port(host: str, port: int, timeout: float = 2) -> bool:
    """Test if port is open with proper timeout"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def _attempt_rpc_connect(token: str, host: str, port: int, ssl: bool = True) -> tuple:
    """Attempt actual RPC handshake. Returns (client, error_string)"""
    if not token:
        return None, "MSF_RPC_TOKEN not set in .env"

    if not _test_port(host, port):
        return None, f"msfrpcd not reachable at {host}:{port} (port closed/filtered)"

    # Try SSL first (default for msfrpcd -S), then non-SSL
    for use_ssl in ([True, False] if ssl else [False, True]):
        try:
            from pymetasploit3.msfrpc import MsfRpcClient
            client = MsfRpcClient(token, server=host, port=port, ssl=use_ssl)
            # Validate handshake by calling core.version
            version = client.call("core.version")
            proto = "SSL" if use_ssl else "plaintext"
            logger.info(f"MSF RPC connected to {host}:{port} ({proto}) - MSF v{version.get('version', '?')}")
            return client, None
        except Exception as e:
            err = str(e)
            # If SSL fails with specific SSL error, try non-SSL
            if "SSL" in err or "ssl" in err or "CERTIFICATE" in err:
                logger.debug(f"MSF RPC SSL attempt failed: {err}, trying {'non-SSL' if use_ssl else 'SSL'}")
                continue
            # Auth errors are definitive - don't retry with different SSL
            if "401" in err or "auth" in err.lower() or "token" in err.lower():
                return None, f"Authentication failed (bad token): {err}"
            return None, f"RPC handshake failed: {err}"

    return None, f"Could not connect to msfrpcd at {host}:{port} (tried SSL and plaintext)"


def get_msf_client(token: str, host: str = "127.0.0.1", port: int = 55553):
    """Get or create MSF RPC client connection"""
    global _msf_client, _msf_connected, _msf_last_error, _msf_retry_count, _msf_config

    # Cache config for reconnection
    _msf_config.update({"token": token, "host": host, "port": port})

    if _msf_client and _msf_connected:
        # Validate connection is still alive
        try:
            _msf_client.call("core.version")
            return _msf_client
        except Exception:
            logger.warning("MSF RPC connection lost, reconnecting...")
            _msf_connected = False
            _msf_client = None

    client, error = _attempt_rpc_connect(token, host, port)
    if client:
        _msf_client = client
        _msf_connected = True
        _msf_last_error = ""
        _msf_retry_count = 0
        return _msf_client
    else:
        _msf_last_error = error
        logger.warning(f"MSF RPC: {error}")
        # Start background reconnection if not already running
        _start_reconnect_loop()
        return None


def _start_reconnect_loop():
    """Start background reconnection with exponential backoff"""
    global _msf_reconnect_thread, _msf_reconnect_active
    if _msf_reconnect_active:
        return
    _msf_reconnect_active = True
    _msf_reconnect_thread = threading.Thread(target=_reconnect_worker, daemon=True)
    _msf_reconnect_thread.start()


def _reconnect_worker():
    """Background worker that retries MSF RPC connection with exponential backoff"""
    global _msf_client, _msf_connected, _msf_last_error, _msf_retry_count, _msf_reconnect_active

    base_delay = 5  # seconds
    max_delay = 120  # max 2 minutes between retries

    while _msf_retry_count < _msf_max_retries * 3 and not _msf_connected:
        _msf_retry_count += 1
        delay = min(base_delay * (2 ** (_msf_retry_count - 1)), max_delay)
        logger.info(f"MSF RPC reconnect attempt {_msf_retry_count} in {delay}s...")
        time.sleep(delay)

        if _msf_connected:
            break

        client, error = _attempt_rpc_connect(
            _msf_config["token"], _msf_config["host"], _msf_config["port"]
        )
        if client:
            _msf_client = client
            _msf_connected = True
            _msf_last_error = ""
            _msf_retry_count = 0
            logger.info("MSF RPC reconnected successfully!")
            break
        else:
            _msf_last_error = error
            # If it's an auth error, stop retrying
            if "Authentication failed" in error:
                logger.error(f"MSF RPC auth failed, stopping retries: {error}")
                break

    _msf_reconnect_active = False


def disconnect_msf():
    global _msf_client, _msf_connected, _msf_retry_count
    _msf_client = None
    _msf_connected = False
    _msf_retry_count = 0


def is_connected() -> bool:
    return _msf_connected and _msf_client is not None


def get_connection_detail() -> Dict:
    """Get detailed connection diagnostics"""
    port_open = _test_port(_msf_config["host"], _msf_config["port"]) if _msf_config["token"] else False
    return {
        "connected": _msf_connected,
        "host": _msf_config["host"],
        "port": _msf_config["port"],
        "token_set": bool(_msf_config["token"]),
        "port_reachable": port_open,
        "last_error": _msf_last_error,
        "retry_count": _msf_retry_count,
        "reconnecting": _msf_reconnect_active,
    }


def get_msf_status(token: str, host: str, port: int) -> Dict:
    """Get MSF RPC connection status and info"""
    client = get_msf_client(token, host, port)
    diag = get_connection_detail()

    if not client:
        hints = []
        if not diag["token_set"]:
            hints.append("Set MSF_RPC_TOKEN in backend/.env")
        if not diag["port_reachable"]:
            hints.append(f"msfrpcd not listening on {host}:{port}. Run: msfrpcd -P YOUR_TOKEN -S -a {host} -p {port}")
        elif "Authentication" in diag["last_error"]:
            hints.append("Token mismatch. Verify MSF_RPC_TOKEN matches msfrpcd -P password")
        if diag["reconnecting"]:
            hints.append(f"Auto-reconnecting... (attempt {diag['retry_count']})")

        return {
            "connected": False,
            "error": diag["last_error"] or "Cannot connect to msfrpcd",
            "hint": " | ".join(hints) if hints else f"Run: msfrpcd -P YOUR_TOKEN -S -a {host} -p {port}",
            "diagnostics": diag
        }
    try:
        version = client.call("core.version")
        return {
            "connected": True,
            "version": version.get("version", "unknown"),
            "ruby": version.get("ruby", "unknown"),
            "api": version.get("api", "unknown"),
            "host": host,
            "port": port,
            "diagnostics": diag
        }
    except Exception as e:
        disconnect_msf()
        return {"connected": False, "error": str(e), "diagnostics": diag}


def search_modules(token: str, host: str, port: int, query: str, module_type: str = "") -> List[Dict]:
    """Search MSF modules via RPC"""
    client = get_msf_client(token, host, port)
    if not client:
        return []
    try:
        results = client.call("module.search", [query])
        modules = []
        for mod in results:
            if module_type and not mod.get("type", "").startswith(module_type):
                continue
            modules.append({
                "name": f"{mod.get('type','')}/{mod.get('fullname', mod.get('name',''))}",
                "type": mod.get("type", ""),
                "rank": mod.get("rank", 0),
                "desc": mod.get("description", "")[:120],
                "source": "msfrpcd"
            })
        return modules[:50]
    except Exception as e:
        logger.error(f"MSF search error: {e}")
        disconnect_msf()
        return []


def get_module_info(token: str, host: str, port: int, module_type: str, module_name: str) -> Dict:
    """Get detailed module info via RPC"""
    client = get_msf_client(token, host, port)
    if not client:
        return {"error": "Not connected to msfrpcd"}
    try:
        info = client.call("module.info", [module_type, module_name])
        options = client.call("module.options", [module_type, module_name])
        return {
            "name": module_name,
            "type": module_type,
            "description": info.get("description", ""),
            "authors": info.get("authors", []),
            "references": info.get("references", []),
            "rank": info.get("rank", ""),
            "options": {k: {"required": v.get("required", False), "default": v.get("default", ""), "desc": v.get("desc", "")} for k, v in options.items()},
            "source": "msfrpcd"
        }
    except Exception as e:
        disconnect_msf()
        return {"error": str(e)}


def execute_module(token: str, host: str, port: int, module_type: str, module_name: str, options: Dict) -> Dict:
    """Execute a module via msfrpcd"""
    client = get_msf_client(token, host, port)
    if not client:
        return {"success": False, "error": "Not connected to msfrpcd"}
    try:
        result = client.call("module.execute", [module_type, module_name, options])
        job_id = result.get("job_id")
        return {
            "success": True,
            "job_id": job_id,
            "uuid": result.get("uuid", ""),
            "module": f"{module_type}/{module_name}",
            "source": "msfrpcd"
        }
    except Exception as e:
        disconnect_msf()
        return {"success": False, "error": str(e)}


def list_sessions(token: str, host: str, port: int) -> List[Dict]:
    """List active MSF sessions"""
    client = get_msf_client(token, host, port)
    if not client:
        return []
    try:
        sessions = client.call("session.list")
        result = []
        for sid, info in sessions.items():
            result.append({
                "id": sid,
                "type": info.get("type", ""),
                "tunnel_local": info.get("tunnel_local", ""),
                "tunnel_peer": info.get("tunnel_peer", ""),
                "via_exploit": info.get("via_exploit", ""),
                "via_payload": info.get("via_payload", ""),
                "desc": info.get("desc", ""),
                "info": info.get("info", ""),
                "workspace": info.get("workspace", ""),
                "target_host": info.get("target_host", ""),
                "username": info.get("username", ""),
                "uuid": info.get("uuid", ""),
                "exploit_uuid": info.get("exploit_uuid", ""),
                "routes": info.get("routes", ""),
                "platform": info.get("platform", "")
            })
        return result
    except Exception as e:
        logger.error(f"Session list error: {e}")
        disconnect_msf()
        return []


def session_command(token: str, host: str, port: int, session_id: str, command: str) -> Dict:
    """Run command on a session"""
    client = get_msf_client(token, host, port)
    if not client:
        return {"error": "Not connected to msfrpcd"}
    try:
        result = client.call("session.shell_write", [session_id, command + "\n"])
        time.sleep(2)
        output = client.call("session.shell_read", [session_id])
        return {
            "session_id": session_id,
            "command": command,
            "output": output.get("data", ""),
            "success": True
        }
    except Exception as e:
        disconnect_msf()
        return {"error": str(e), "success": False}


def list_jobs(token: str, host: str, port: int) -> List[Dict]:
    """List active MSF jobs"""
    client = get_msf_client(token, host, port)
    if not client:
        return []
    try:
        jobs = client.call("job.list")
        return [{"id": jid, "name": name} for jid, name in jobs.items()]
    except Exception as e:
        disconnect_msf()
        return []


def kill_job(token: str, host: str, port: int, job_id: str) -> Dict:
    """Kill a MSF job"""
    client = get_msf_client(token, host, port)
    if not client:
        return {"error": "Not connected to msfrpcd"}
    try:
        client.call("job.stop", [job_id])
        return {"success": True, "job_id": job_id}
    except Exception as e:
        disconnect_msf()
        return {"error": str(e)}
