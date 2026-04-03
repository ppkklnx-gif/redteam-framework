"""Credential Vault & Artifact Store - Auto-collects and injects credentials"""
import re
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class CredentialVault:
    """Centralized credential and artifact management"""
    
    MAX_CREDENTIALS = 500
    
    def __init__(self, db=None):
        self.db = db
        self._memory_store = []  # In-memory fallback
        self._artifacts = {}  # {scan_id: {lhost, rhost, os, sessions, etc}}
    
    def get_context(self, scan_id: str) -> Dict:
        """Get full context for a scan including all artifacts"""
        return self._artifacts.get(scan_id, {})
    
    def update_context(self, scan_id: str, **kwargs):
        """Update scan context with new artifacts"""
        if scan_id not in self._artifacts:
            self._artifacts[scan_id] = {"credentials": [], "sessions": [], "hosts": [], "os_info": {}}
        self._artifacts[scan_id].update(kwargs)
    
    def add_credential(self, scan_id: str, cred: Dict):
        """Add a credential to the vault"""
        if scan_id not in self._artifacts:
            self._artifacts[scan_id] = {"credentials": [], "sessions": [], "hosts": [], "os_info": {}}
        
        creds = self._artifacts[scan_id]["credentials"]
        if len(creds) >= self.MAX_CREDENTIALS:
            return
        
        # Deduplicate
        for existing in creds:
            if existing.get("username") == cred.get("username") and existing.get("value") == cred.get("value"):
                return
        
        cred["found_at"] = datetime.now(timezone.utc).isoformat()
        creds.append(cred)
        self._memory_store.append(cred)
        logger.info(f"[VAULT] New credential: {cred.get('type','?')} - {cred.get('username','?')}@{cred.get('host','?')}")
    
    def add_session(self, scan_id: str, session: Dict):
        """Register an active session"""
        if scan_id not in self._artifacts:
            self._artifacts[scan_id] = {"credentials": [], "sessions": [], "hosts": [], "os_info": {}}
        self._artifacts[scan_id]["sessions"].append({**session, "found_at": datetime.now(timezone.utc).isoformat()})
    
    def has_session(self, scan_id: str) -> bool:
        """Check if there are active sessions"""
        return len(self._artifacts.get(scan_id, {}).get("sessions", [])) > 0
    
    def get_credentials(self, scan_id: str, cred_type: str = None) -> List[Dict]:
        """Get credentials, optionally filtered by type"""
        creds = self._artifacts.get(scan_id, {}).get("credentials", [])
        if cred_type:
            return [c for c in creds if c.get("type") == cred_type]
        return creds
    
    def inject_context(self, command: str, scan_id: str, target: str, extra: Dict = None) -> str:
        """Auto-inject credentials and artifacts into command placeholders"""
        ctx = self._artifacts.get(scan_id, {})
        creds = ctx.get("credentials", [])
        
        # Basic replacements
        command = command.replace("{target}", target)
        
        # Extra context overrides
        if extra:
            for k, v in extra.items():
                command = command.replace(f"{{{k}}}", str(v))
        
        # Auto-inject from vault
        if "{user}" in command and creds:
            for c in creds:
                if c.get("username"):
                    command = command.replace("{user}", c["username"])
                    break
        
        if "{pass}" in command and creds:
            for c in creds:
                if c.get("value") and c.get("type") == "plaintext":
                    command = command.replace("{pass}", c["value"])
                    break
        
        if "{hash}" in command and creds:
            for c in creds:
                if c.get("value") and c.get("type") == "hash":
                    command = command.replace("{hash}", c["value"])
                    break
        
        if "{domain}" in command:
            domain = ctx.get("domain") or (extra or {}).get("domain", "")
            command = command.replace("{domain}", domain)
        
        if "{lhost}" in command:
            lhost = (extra or {}).get("lhost", "") or ctx.get("lhost", "")
            command = command.replace("{lhost}", lhost)
        
        return command
    
    @staticmethod
    def parse_credentials_from_output(output: str, tool: str, host: str = "") -> List[Dict]:
        """Extract credentials from tool output"""
        creds = []
        
        # Hash patterns (NTLM, MD5, SHA1, etc)
        hash_patterns = [
            (r'(\w+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32})', "ntlm"),  # user:rid:lm:nt
            (r'(\w+):\$(\d)\$(.+?):', "unix_hash"),  # user:$6$salt:hash
            (r'(\w+):([a-fA-F0-9]{32})(?:\s|$)', "md5_hash"),  # user:md5hash
        ]
        
        for pattern, hash_type in hash_patterns:
            for match in re.finditer(pattern, output):
                username = match.group(1)
                if hash_type == "ntlm":
                    creds.append({"type": "hash", "hash_type": "ntlm", "username": username, "value": match.group(4), "lm_hash": match.group(3), "host": host, "source": tool})
                elif hash_type == "unix_hash":
                    creds.append({"type": "hash", "hash_type": f"sha{match.group(2)}crypt", "username": username, "value": match.group(0), "host": host, "source": tool})
                elif hash_type == "md5_hash":
                    creds.append({"type": "hash", "hash_type": "md5", "username": username, "value": match.group(2), "host": host, "source": tool})
        
        # Plaintext credentials
        plain_patterns = [
            r'(?:user(?:name)?|login)\s*[:=]\s*["\']?(\w+)["\']?\s*(?:pass(?:word)?)\s*[:=]\s*["\']?([^\s"\']+)',
            r'credentials?\s*found[:\s]+(\w+)\s*[:/]\s*(\S+)',
            r'(\w+):(\S+)\s+- Success',  # hydra format
        ]
        
        for pattern in plain_patterns:
            for match in re.finditer(pattern, output, re.IGNORECASE):
                creds.append({"type": "plaintext", "username": match.group(1), "value": match.group(2), "host": host, "source": tool})
        
        # Kerberos tickets
        if "TGT" in output or "kirbi" in output.lower():
            ticket_match = re.search(r'Saved to\s*:\s*(.+\.(?:kirbi|ccache))', output)
            if ticket_match:
                creds.append({"type": "ticket", "ticket_type": "TGT", "value": ticket_match.group(1), "host": host, "source": tool})
        
        return creds
    
    @staticmethod
    def detect_os_from_output(output: str) -> Dict:
        """Detect OS info from tool output"""
        os_info = {}
        output_lower = output.lower()
        
        if "windows" in output_lower:
            os_info["os"] = "windows"
            version_match = re.search(r'Windows\s+([\w\s]+?)(?:\s|$)', output, re.IGNORECASE)
            if version_match:
                os_info["version"] = version_match.group(1).strip()
        elif "linux" in output_lower or "ubuntu" in output_lower or "debian" in output_lower or "centos" in output_lower:
            os_info["os"] = "linux"
            distro_match = re.search(r'(Ubuntu|Debian|CentOS|Fedora|Red Hat|Kali)[\s/]*([\d.]+)?', output, re.IGNORECASE)
            if distro_match:
                os_info["distro"] = distro_match.group(1)
                os_info["version"] = distro_match.group(2) or ""
        
        return os_info
    
    async def save_to_db(self, scan_id: str):
        """Persist vault contents to MongoDB"""
        if self.db and scan_id in self._artifacts:
            await self.db.credentials.update_one(
                {"scan_id": scan_id},
                {"$set": {"scan_id": scan_id, **self._artifacts[scan_id]}},
                upsert=True
            )
    
    def get_vault_summary(self, scan_id: str) -> Dict:
        """Get summary of vault contents"""
        ctx = self._artifacts.get(scan_id, {})
        creds = ctx.get("credentials", [])
        return {
            "total_credentials": len(creds),
            "hashes": len([c for c in creds if c.get("type") == "hash"]),
            "plaintext": len([c for c in creds if c.get("type") == "plaintext"]),
            "tickets": len([c for c in creds if c.get("type") == "ticket"]),
            "sessions": len(ctx.get("sessions", [])),
            "os_info": ctx.get("os_info", {}),
            "has_domain": bool(ctx.get("domain")),
        }
