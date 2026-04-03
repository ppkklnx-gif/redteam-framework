"""Metasploit RPC Integration Module - Connects to msfrpcd for real exploitation"""
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

# msf_rpc_client singleton
_msf_client = None
_msf_connected = False


def get_msf_client(token: str, host: str = "127.0.0.1", port: int = 55553):
    """Get or create MSF RPC client connection"""
    global _msf_client, _msf_connected
    if _msf_client and _msf_connected:
        return _msf_client
    if not token:
        return None
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((host, port))
        sock.close()
        if result != 0:
            logger.info(f"msfrpcd not reachable at {host}:{port}")
            return None
        from pymetasploit3.msfrpc import MsfRpcClient
        _msf_client = MsfRpcClient(token, server=host, port=port, ssl=True)
        _msf_connected = True
        logger.info(f"Connected to msfrpcd at {host}:{port}")
        return _msf_client
    except Exception as e:
        logger.warning(f"msfrpcd not available: {e}")
        _msf_connected = False
        return None


def disconnect_msf():
    global _msf_client, _msf_connected
    _msf_client = None
    _msf_connected = False


def is_connected() -> bool:
    return _msf_connected and _msf_client is not None


def get_msf_status(token: str, host: str, port: int) -> Dict:
    """Get MSF RPC connection status and info"""
    client = get_msf_client(token, host, port)
    if not client:
        return {"connected": False, "error": "Cannot connect to msfrpcd", "hint": "Run: msfrpcd -P YOUR_TOKEN -S -a 127.0.0.1"}
    try:
        version = client.call("core.version")
        return {
            "connected": True,
            "version": version.get("version", "unknown"),
            "ruby": version.get("ruby", "unknown"),
            "api": version.get("api", "unknown"),
            "host": host,
            "port": port
        }
    except Exception as e:
        disconnect_msf()
        return {"connected": False, "error": str(e)}


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
        return []


def get_module_info(token: str, host: str, port: int, module_type: str, module_name: str) -> Dict:
    """Get detailed module info via RPC"""
    client = get_msf_client(token, host, port)
    if not client:
        return {"error": "Not connected"}
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
        return []


def session_command(token: str, host: str, port: int, session_id: str, command: str) -> Dict:
    """Run command on a session"""
    client = get_msf_client(token, host, port)
    if not client:
        return {"error": "Not connected"}
    try:
        result = client.call("session.shell_write", [session_id, command + "\n"])
        import time
        time.sleep(2)
        output = client.call("session.shell_read", [session_id])
        return {
            "session_id": session_id,
            "command": command,
            "output": output.get("data", ""),
            "success": True
        }
    except Exception as e:
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
        return []


def kill_job(token: str, host: str, port: int, job_id: str) -> Dict:
    """Kill a MSF job"""
    client = get_msf_client(token, host, port)
    if not client:
        return {"error": "Not connected"}
    try:
        client.call("job.stop", [job_id])
        return {"success": True, "job_id": job_id}
    except Exception as e:
        return {"error": str(e)}
