import { useState, useEffect, useRef, useCallback } from "react";
import "@/App.css";
import axios from "axios";
import { 
  Shield, Radar, Bug, Globe, Crosshair, Fingerprint, Play, Square, Download, 
  Trash2, Clock, Terminal, Cpu, AlertTriangle, CheckCircle, XCircle, Copy, 
  History, ChevronRight, Zap, Target, GitBranch, Server, Unlock, Skull, 
  RefreshCw, Eye, Database, Key, Network, Lock, Layers, Activity, Link,
  Radio, Wifi, Upload, Command, MonitorSmartphone
} from "lucide-react";
import { ScrollArea } from "./components/ui/scroll-area";
import { Progress } from "./components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./components/ui/tabs";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

// Kill Chain Phases with MITRE ATT&CK mapping
const KILL_CHAIN = [
  { id: "reconnaissance", name: "RECON", icon: Eye, color: "#00F0FF", mitre: "TA0043" },
  { id: "resource_development", name: "RESOURCE", icon: Layers, color: "#00F0FF", mitre: "TA0042" },
  { id: "initial_access", name: "INITIAL ACCESS", icon: Key, color: "#FFB000", mitre: "TA0001" },
  { id: "execution", name: "EXECUTION", icon: Play, color: "#FF003C", mitre: "TA0002" },
  { id: "persistence", name: "PERSISTENCE", icon: Lock, color: "#FF003C", mitre: "TA0003" },
  { id: "privilege_escalation", name: "PRIV ESC", icon: Zap, color: "#FF003C", mitre: "TA0004" },
  { id: "defense_evasion", name: "EVASION", icon: Shield, color: "#FFB000", mitre: "TA0005" },
  { id: "credential_access", name: "CREDS", icon: Key, color: "#FF003C", mitre: "TA0006" },
  { id: "discovery", name: "DISCOVERY", icon: Radar, color: "#00F0FF", mitre: "TA0007" },
  { id: "lateral_movement", name: "LATERAL", icon: Network, color: "#FF003C", mitre: "TA0008" },
  { id: "collection", name: "COLLECT", icon: Database, color: "#FFB000", mitre: "TA0009" },
  { id: "command_and_control", name: "C2", icon: Activity, color: "#FF003C", mitre: "TA0011" },
  { id: "exfiltration", name: "EXFIL", icon: Download, color: "#FF003C", mitre: "TA0010" },
  { id: "impact", name: "IMPACT", icon: Skull, color: "#FF003C", mitre: "TA0040" }
];

const NODE_ICONS = { target: Target, phase: Layers, tool: Terminal, service: Server, vulnerability: Bug, exploit: Skull, access: Unlock, defense: Shield, subdomain: Globe };
const NODE_COLORS = { target: "#00FF41", phase: "#00F0FF", tool: "#FFB000", service: "#00F0FF", vulnerability: "#FF003C", exploit: "#FF003C", access: "#00FF41", defense: "#FFB000" };
const STATUS_COLORS = { pending: "#008F11", testing: "#FFB000", success: "#00FF41", failed: "#FF003C", verified: "#00F0FF", completed: "#00FF41" };

const ASCII_LOGO = `
 ██████╗ ███████╗██████╗     ████████╗███████╗ █████╗ ███╗   ███╗
 ██╔══██╗██╔════╝██╔══██╗    ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║
 ██████╔╝█████╗  ██║  ██║       ██║   █████╗  ███████║██╔████╔██║
 ██╔══██╗██╔══╝  ██║  ██║       ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║
 ██║  ██║███████╗██████╔╝       ██║   ███████╗██║  ██║██║ ╚═╝ ██║
 ╚═╝  ╚═╝╚══════╝╚═════╝        ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝
       TACTICAL ENGINE v3.1 | ADAPTIVE ATTACK PLANNING`;

function App() {
  const [target, setTarget] = useState("");
  const [selectedPhases, setSelectedPhases] = useState(["reconnaissance", "initial_access"]);
  const [isScanning, setIsScanning] = useState(false);
  const [currentScanId, setCurrentScanId] = useState(null);
  const [scanStatus, setScanStatus] = useState(null);
  const [attackTree, setAttackTree] = useState(null);
  const [mitreTactics, setMitreTactics] = useState({});
  const [tacticalDecisions, setTacticalDecisions] = useState([]);
  const [terminalLines, setTerminalLines] = useState([
    { type: "system", text: "RED TEAM AUTOMATION FRAMEWORK v3.0" },
    { type: "system", text: "MITRE ATT&CK Integration Enabled" },
    { type: "info", text: "Selecciona fases del Kill Chain y un target para comenzar" }
  ]);
  const [history, setHistory] = useState([]);
  const [activeTab, setActiveTab] = useState("killchain");
  const [msfModule, setMsfModule] = useState(null);
  const [msfModules, setMsfModules] = useState([]);
  const [moduleSearch, setModuleSearch] = useState("");
  const [msfCategory, setMsfCategory] = useState("");
  const [msfPort, setMsfPort] = useState("");
  const [msfLhost, setMsfLhost] = useState("");
  const [msfExecuting, setMsfExecuting] = useState(false);
  const [msfResult, setMsfResult] = useState(null);
  const [attackChains, setAttackChains] = useState([]);
  const [selectedChain, setSelectedChain] = useState(null);
  const [chainExecution, setChainExecution] = useState(null);
  const [chainContext, setChainContext] = useState({ lhost: "", domain: "", user: "", pass: "" });
  const [chainAutoExec, setChainAutoExec] = useState(false);
  const [chainPolling, setChainPolling] = useState(false);
  const [suggestedChains, setSuggestedChains] = useState([]);
  const [recommendedModules, setRecommendedModules] = useState([]);
  const [c2Dashboard, setC2Dashboard] = useState(null);
  const [c2Loading, setC2Loading] = useState(false);
  const [msfSearchQuery, setMsfSearchQuery] = useState("");
  const [msfRpcModules, setMsfRpcModules] = useState([]);
  const [sliverGenConfig, setSliverGenConfig] = useState({ name: "implant", lhost: "", lport: 443, os: "linux", arch: "amd64", type: "session", protocol: "mtls" });
  const [selectedSession, setSelectedSession] = useState(null);
  const [sessionCmd, setSessionCmd] = useState("");
  const [sessionOutput, setSessionOutput] = useState([]);
  const chainPollRef = useRef(null);
  const wsRef = useRef(null);
  const terminalRef = useRef(null);
  const pollIntervalRef = useRef(null);

  const addTerminalLine = useCallback((type, text) => {
    setTerminalLines(prev => [...prev.slice(-100), { type, text }]);
  }, []);

  useEffect(() => {
    if (terminalRef.current) terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
  }, [terminalLines]);

  const loadMitreTactics = useCallback(async () => {
    try {
      const response = await axios.get(`${API}/mitre/tactics`);
      setMitreTactics(response.data.tactics);
    } catch (error) { console.error("Error loading MITRE:", error); }
  }, []);

  const loadHistory = useCallback(async () => {
    try {
      const response = await axios.get(`${API}/scan/history`);
      setHistory(response.data);
    } catch (error) { console.error("Error loading history:", error); }
  }, []);

  const loadMsfModules = useCallback(async (query = "", category = "") => {
    try {
      const response = await axios.get(`${API}/metasploit/modules`, { params: { query, category } });
      setMsfModules(response.data.modules);
    } catch (error) { console.error("Error loading MSF modules:", error); }
  }, []);

  const loadAttackChains = useCallback(async () => {
    try {
      const response = await axios.get(`${API}/chains`);
      setAttackChains(response.data.chains);
    } catch (error) { console.error("Error loading chains:", error); }
  }, []);

  const loadC2Dashboard = useCallback(async () => {
    setC2Loading(true);
    try {
      const response = await axios.get(`${API}/c2/dashboard`);
      setC2Dashboard(response.data);
    } catch (error) { console.error("C2 dashboard error:", error); }
    setC2Loading(false);
  }, []);

  const searchMsfRpc = async (query) => {
    try {
      const response = await axios.get(`${API}/msf/search`, { params: { query } });
      setMsfRpcModules(response.data.modules || []);
    } catch (error) { console.error("MSF RPC search error:", error); }
  };

  const executeMsfRpc = async (moduleType, moduleName, options) => {
    addTerminalLine("command", `> msf rpc: ${moduleType}/${moduleName}`);
    try {
      const response = await axios.post(`${API}/msf/module/execute`, { module_type: moduleType, module_name: moduleName, options });
      if (response.data.success) {
        addTerminalLine("success", `Job started: ${response.data.job_id}`);
      } else {
        addTerminalLine("error", `Failed: ${response.data.error}`);
      }
      return response.data;
    } catch (error) { addTerminalLine("error", error.message); return null; }
  };

  const runSessionCommand = async () => {
    if (!selectedSession || !sessionCmd) return;
    const source = selectedSession.source;
    addTerminalLine("command", `> [${source}] ${sessionCmd}`);
    try {
      let response;
      if (source === "msf") {
        response = await axios.post(`${API}/msf/session/command`, { session_id: selectedSession.id, command: sessionCmd });
      } else {
        response = await axios.post(`${API}/sliver/session/exec`, { session_id: selectedSession.id, command: sessionCmd });
      }
      const output = response.data.output || response.data.stdout || "";
      const error = response.data.error || response.data.stderr || "";
      setSessionOutput(prev => [...prev, { cmd: sessionCmd, output, error }]);
      if (output) addTerminalLine("info", output.substring(0, 200));
      if (error) addTerminalLine("error", error.substring(0, 200));
    } catch (error) { addTerminalLine("error", error.message); }
    setSessionCmd("");
  };

  const connectWebSocket = useCallback((scanId) => {
    const wsUrl = API.replace("https://", "wss://").replace("http://", "ws://") + `/ws/scan/${scanId}`;
    try {
      const ws = new WebSocket(wsUrl);
      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === "scan_update") {
          setScanStatus(data);
          if (data.current_tool) addTerminalLine("info", `[WS] ${data.current_tool}: ${data.progress}%`);
          if (data.status === "completed") {
            if (data.suggested_chains?.length > 0) setSuggestedChains(data.suggested_chains);
            if (data.recommended_modules?.length > 0) setRecommendedModules(data.recommended_modules);
          }
        }
      };
      ws.onerror = () => { logger("WS error, falling back to polling"); };
      ws.onclose = () => { wsRef.current = null; };
      wsRef.current = ws;
    } catch (e) { /* WebSocket not available, polling will handle it */ }
  }, [addTerminalLine]);

  useEffect(() => { loadMitreTactics(); loadHistory(); loadMsfModules(); loadAttackChains(); }, [loadMitreTactics, loadHistory, loadMsfModules, loadAttackChains]);

  const togglePhase = (phaseId) => {
    setSelectedPhases(prev => prev.includes(phaseId) ? prev.filter(p => p !== phaseId) : [...prev, phaseId]);
  };

  const startScan = async () => {
    if (!target.trim() || selectedPhases.length === 0) {
      addTerminalLine("error", "ERROR: Target y fases requeridos");
      return;
    }
    setIsScanning(true);
    setAttackTree(null);
    addTerminalLine("command", `> INICIANDO OPERACIÓN RED TEAM`);
    addTerminalLine("info", `Target: ${target}`);
    addTerminalLine("info", `Kill Chain Phases: ${selectedPhases.join(" → ")}`);

    try {
      const response = await axios.post(`${API}/scan/start`, { target, scan_phases: selectedPhases, tools: [] });
      setCurrentScanId(response.data.scan_id);
      addTerminalLine("success", `Operation ID: ${response.data.scan_id}`);
      
      // Try WebSocket first, fallback to polling
      connectWebSocket(response.data.scan_id);
      pollIntervalRef.current = setInterval(() => pollScanStatus(response.data.scan_id), 2000);
    } catch (error) {
      addTerminalLine("error", `ERROR: ${error.response?.data?.detail || error.message}`);
      setIsScanning(false);
    }
  };

  const pollScanStatus = async (scanId) => {
    try {
      const response = await axios.get(`${API}/scan/${scanId}/status`);
      setScanStatus(response.data);
      if (response.data.current_tool) addTerminalLine("info", `[${response.data.progress}%] ${response.data.current_tool.toUpperCase()}`);
      if (response.data.attack_tree) setAttackTree(response.data.attack_tree);
      
      // Show tactical decisions in real-time
      if (response.data.tactical_decisions && response.data.tactical_decisions.length > 0) {
        const latestTactical = response.data.tactical_decisions[response.data.tactical_decisions.length - 1];
        if (latestTactical?.advice?.overall_strategy) {
          addTerminalLine("warning", `[TACTICAL] ${latestTactical.advice.overall_strategy}`);
        }
        // Show WAF detection alert
        if (latestTactical?.advice?.waf_analysis?.waf_detected) {
          addTerminalLine("error", `[!] WAF DETECTED: ${latestTactical.advice.waf_analysis.waf_name}`);
          addTerminalLine("info", `[>] Bypass strategy: ${latestTactical.advice.waf_analysis.alternative_approach}`);
        }
        // Show priority actions
        latestTactical?.advice?.priority_actions?.forEach(action => {
          addTerminalLine("warning", `[P${action.priority}] ${action.action}: ${action.details}`);
        });
        setTacticalDecisions(response.data.tactical_decisions);
      }
      // Show adaptive decisions in terminal
      if (response.data.adaptive_log?.length > 0) {
        const newDecisions = response.data.adaptive_log.slice(-3);
        newDecisions.forEach(d => {
          if (d.decision === "SKIP") addTerminalLine("warning", `[ADAPT] SKIP: ${d.reason}`);
          else if (d.decision === "ADD") addTerminalLine("info", `[ADAPT] +TOOL: ${d.reason}`);
          else if (d.decision === "EXPLOIT") addTerminalLine("error", `[ADAPT] AUTO-EXPLOIT: ${d.reason}`);
          else if (d.decision === "CHAIN_TRIGGER") addTerminalLine("error", `[ADAPT] CHAIN TRIGGERED: ${d.reason}`);
        });
      }
      
      if (response.data.status === "completed") {
        clearInterval(pollIntervalRef.current);
        setIsScanning(false);
        addTerminalLine("success", "═══════════════════════════════════════════════════════");
        addTerminalLine("success", "ADAPTIVE SCAN COMPLETE");
        addTerminalLine("success", "═══════════════════════════════════════════════════════");
        
        // Show vault summary
        const vault = response.data.vault_summary;
        if (vault) {
          addTerminalLine("info", `[VAULT] Creds: ${vault.total_credentials || 0} (${vault.hashes || 0} hashes, ${vault.plaintext || 0} plain) | Sessions: ${vault.sessions || 0}`);
        }
        
        // Show auto-triggered chain
        if (response.data.auto_triggered_chain) {
          const tc = response.data.auto_triggered_chain;
          addTerminalLine("error", `[AUTO-CHAIN] ${tc.chain_id} triggered (confidence: ${(tc.confidence * 100).toFixed(0)}%)`);
          addTerminalLine("info", `  Reason: ${tc.reason}`);
        }
        
        // Show suggested chains
        if (response.data.suggested_chains?.length > 0) {
          setSuggestedChains(response.data.suggested_chains);
          addTerminalLine("warning", `[CHAINS] ${response.data.suggested_chains.length} cadena(s) de ataque sugerida(s):`);
          response.data.suggested_chains.forEach(c => {
            addTerminalLine("info", `  >> ${c.name} (trigger: ${c.trigger_matched})`);
          });
        }
        
        // Store recommended modules
        if (response.data.recommended_modules?.length > 0) {
          setRecommendedModules(response.data.recommended_modules);
          addTerminalLine("warning", `[MSF] ${response.data.recommended_modules.length} modulo(s) recomendado(s) segun hallazgos`);
        }
        
        loadHistory();
        setActiveTab("tree");
      }
      if (response.data.status === "error") {
        clearInterval(pollIntervalRef.current);
        setIsScanning(false);
        addTerminalLine("error", "OPERATION FAILED");
      }
    } catch (error) { console.error("Error polling:", error); }
  };

  const stopScan = async () => {
    if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
    setIsScanning(false);
    if (currentScanId) {
      try { await axios.post(`${API}/scan/${currentScanId}/abort`); } catch (e) {}
    }
    addTerminalLine("error", "═══ SCAN ABORTED ═══");
  };

  const updateNodeStatus = async (nodeId, status) => {
    if (!currentScanId) return;
    try {
      await axios.put(`${API}/scan/${currentScanId}/tree/node/${nodeId}`, { status });
      const response = await axios.get(`${API}/scan/${currentScanId}/tree`);
      setAttackTree(response.data);
      addTerminalLine("info", `Node ${nodeId} → ${status.toUpperCase()}`);
    } catch (error) { addTerminalLine("error", `Error: ${error.message}`); }
  };

  const executeMsfExploit = async () => {
    if (!msfModule) return;
    setMsfExecuting(true);
    addTerminalLine("command", `> msfconsole -x "use ${msfModule}; set RHOSTS ${target}; run"`);
    try {
      const response = await axios.post(`${API}/metasploit/execute`, {
        scan_id: currentScanId || "", node_id: "", module: msfModule,
        target_host: target || "127.0.0.1", target_port: msfPort ? parseInt(msfPort) : null,
        options: {}, lhost: msfLhost || null, lport: 4444
      });
      setMsfResult(response.data);
      if (response.data.success) {
        addTerminalLine("success", `[+] EXPLOIT SUCCESS: ${msfModule}`);
        if (response.data.session_opened) addTerminalLine("success", "[+] SESSION OBTAINED!");
      } else {
        addTerminalLine("warning", `[-] Exploit failed: ${msfModule}`);
      }
      if (currentScanId) {
        const treeResponse = await axios.get(`${API}/scan/${currentScanId}/tree`);
        setAttackTree(treeResponse.data);
      }
    } catch (error) {
      setMsfResult({ error: error.message });
      addTerminalLine("error", `Error: ${error.message}`);
    }
    setMsfExecuting(false);
  };

  const copyToClipboard = (text) => { navigator.clipboard.writeText(text); addTerminalLine("info", "Copied to clipboard"); };

  const pollChainExecution = useCallback(async (executionId) => {
    try {
      const response = await axios.get(`${API}/chains/execution/${executionId}`);
      const data = response.data;
      setChainExecution(data);
      
      if (data.status === "running" && data.current_step > 0) {
        const stepStatus = data.step_statuses?.[String(data.current_step)];
        if (stepStatus?.status === "running") {
          addTerminalLine("warning", `[CHAIN] Step ${data.current_step}/${data.total_steps}: ${stepStatus.step_name}...`);
        } else if (stepStatus?.status === "completed") {
          addTerminalLine("success", `[CHAIN] Step ${data.current_step} completed: ${stepStatus.step_name}`);
        }
      }
      
      if (data.status === "completed") {
        if (chainPollRef.current) {
          clearInterval(chainPollRef.current);
          chainPollRef.current = null;
        }
        setChainPolling(false);
        addTerminalLine("success", "═══ ATTACK CHAIN COMPLETED ═══");
        data.results?.forEach(r => {
          addTerminalLine("info", `  Step ${r.step_id} [${r.step_name}]: ${r.status?.toUpperCase()}`);
        });
      }
    } catch (error) {
      console.error("Chain poll error:", error);
    }
  }, [addTerminalLine]);

  const executeChainAuto = async () => {
    if (!selectedChain || !target) return;
    addTerminalLine("command", `> AUTO-EXECUTING CHAIN: ${selectedChain.name}`);
    addTerminalLine("info", `Target: ${target}`);
    try {
      const response = await axios.post(`${API}/chains/execute`, {
        scan_id: currentScanId || "",
        chain_id: selectedChain.id,
        target: target,
        context: chainContext,
        auto_execute: true
      });
      setChainExecution(response.data);
      setChainPolling(true);
      addTerminalLine("success", `Chain started: ${response.data.execution_id}`);
      
      chainPollRef.current = setInterval(() => pollChainExecution(response.data.execution_id), 1500);
    } catch (error) {
      addTerminalLine("error", `Error: ${error.message}`);
    }
  };

  const executeChainStep = async (executionId, stepId) => {
    addTerminalLine("command", `> Executing step ${stepId}...`);
    try {
      const response = await axios.post(`${API}/chains/execution/${executionId}/step/${stepId}`);
      addTerminalLine("success", `Step ${stepId} [${response.data.step_name}]: ${response.data.status?.toUpperCase()}`);
      response.data.command_results?.forEach(cr => {
        if (cr.output) addTerminalLine("info", `  ${cr.output}`);
        if (cr.error) addTerminalLine("error", `  ${cr.error}`);
      });
      // Refresh execution status
      const statusRes = await axios.get(`${API}/chains/execution/${executionId}`);
      setChainExecution(statusRes.data);
    } catch (error) {
      addTerminalLine("error", `Step error: ${error.message}`);
    }
  };

  const downloadReport = async (scanId) => {
    try {
      const response = await axios.get(`${API}/scan/${scanId}/report`);
      const blob = new Blob([JSON.stringify(response.data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = `redteam-report-${scanId}.json`; a.click();
      addTerminalLine("success", "Report downloaded");
    } catch (error) { addTerminalLine("error", "Download failed"); }
  };

  const deleteScan = async (scanId) => {
    try {
      await axios.delete(`${API}/scan/${scanId}`);
      loadHistory();
      if (currentScanId === scanId) { setAttackTree(null); setScanStatus(null); setCurrentScanId(null); }
      addTerminalLine("info", "Operation deleted");
    } catch (error) { addTerminalLine("error", "Delete failed"); }
  };

  const loadScan = async (scanId) => {
    try {
      const response = await axios.get(`${API}/scan/${scanId}/status`);
      setScanStatus(response.data);
      setCurrentScanId(scanId);
      if (response.data.attack_tree) setAttackTree(response.data.attack_tree);
      addTerminalLine("info", `Loading operation: ${scanId}`);
      setActiveTab("tree");
    } catch (error) { addTerminalLine("error", "Load failed"); }
  };

  const getTreeNodes = () => {
    if (!attackTree) return [];
    const nodes = [];
    if (attackTree.root) {
      nodes.push({ ...attackTree.root, depth: 0, isRoot: true });
      const addChildren = (parentId, depth) => {
        const parent = parentId === "root" ? attackTree.root : attackTree.nodes[parentId];
        if (parent?.children) {
          parent.children.forEach(childId => {
            const node = attackTree.nodes[childId];
            if (node) {
              nodes.push({ ...node, depth });
              addChildren(childId, depth + 1);
            }
          });
        }
      };
      addChildren("root", 1);
    }
    return nodes;
  };

  const treeNodes = getTreeNodes();
  const treeStats = attackTree?.nodes ? {
    total: Object.keys(attackTree.nodes).length,
    pending: Object.values(attackTree.nodes).filter(n => n.status === "pending").length,
    success: Object.values(attackTree.nodes).filter(n => n.status === "success" || n.status === "completed").length,
    failed: Object.values(attackTree.nodes).filter(n => n.status === "failed").length
  } : { total: 0, pending: 0, success: 0, failed: 0 };

  return (
    <div className="app-container crt-flicker">
      <div className="scanlines" />
      <div className="matrix-bg" />

      <header className="app-header">
        <div className="app-logo">
          <div className="logo-icon" style={{ borderColor: "#FF003C" }}><Skull size={24} className="text-[#FF003C]" /></div>
          <h1 data-testid="app-title" className="text-[#FF003C]">RED TEAM FRAMEWORK</h1>
        </div>
        <div className="flex items-center gap-4">
          <span className="text-xs uppercase tracking-widest" style={{ color: isScanning ? "#FFB000" : "#00FF41" }}>
            {isScanning ? "OPERATION IN PROGRESS" : "READY"}
          </span>
          {isScanning && <div className="w-2 h-2 bg-[#FFB000] rounded-full animate-pulse" />}
        </div>
      </header>

      <main className="main-grid">
        <section className="target-section panel p-4" data-testid="target-section">
          <div className="flex flex-col md:flex-row gap-4 items-stretch md:items-center relative z-10">
            <div className="flex-1">
              <label className="text-xs text-[#FF003C] uppercase tracking-widest mb-2 block">TARGET</label>
              <input type="text" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="10.10.10.x | domain.com | 192.168.1.0/24" className="matrix-input w-full" style={{ borderColor: "rgba(255,0,60,0.5)" }} disabled={isScanning} data-testid="target-input" />
            </div>
            <div className="flex gap-2">
              {!isScanning ? (
                <button onClick={startScan} className="matrix-btn" style={{ borderColor: "#FF003C", color: "#FF003C" }} disabled={!target.trim() || selectedPhases.length === 0} data-testid="start-scan-btn"><Play size={16} /> ENGAGE</button>
              ) : (
                <button onClick={stopScan} className="matrix-btn matrix-btn-danger" data-testid="stop-scan-btn"><Square size={16} /> ABORT</button>
              )}
            </div>
          </div>
          {isScanning && scanStatus && (
            <div className="mt-4 relative z-10">
              <div className="flex justify-between text-xs text-[#008F11] mb-1">
                <span className="text-[#FF003C]">PHASE: {scanStatus.current_tool?.toUpperCase() || "INITIALIZING"}</span>
                <span>{scanStatus.progress}%</span>
              </div>
              <Progress value={scanStatus.progress} className="h-1 bg-[#0a140a]" />
            </div>
          )}
        </section>

        <section className="terminal-panel panel flex flex-col" data-testid="terminal-panel">
          <div className="panel-header" style={{ borderColor: "rgba(255,0,60,0.3)" }}>
            <div className="flex items-center gap-2 text-[#FF003C]"><Terminal size={16} /><span>OPERATION LOG</span></div>
            <button onClick={() => setTerminalLines([])} className="text-[#008F11] hover:text-[#FF003C]">CLEAR</button>
          </div>
          <ScrollArea className="flex-1 p-4 terminal-output" ref={terminalRef}>
            <pre className="ascii-logo text-center mb-4 text-[#FF003C]" style={{ fontSize: "0.35rem" }}>{ASCII_LOGO}</pre>
            {terminalLines.map((line, idx) => (
              <div key={idx} className={`terminal-line ${line.type === 'error' ? 'text-[#FF003C]' : line.type === 'warning' ? 'text-[#FFB000]' : line.type === 'success' ? 'text-[#00FF41]' : line.type === 'command' ? 'text-[#00F0FF]' : 'text-[#008F11]'}`}>
                <span className="terminal-prompt">{line.type === 'command' ? 'root@kali# ' : line.type === 'error' ? '[!] ' : line.type === 'warning' ? '[*] ' : line.type === 'success' ? '[+] ' : '[>] '}</span>{line.text}
              </div>
            ))}
            {isScanning && <span className="cursor-blink text-[#FF003C]">█</span>}
          </ScrollArea>
        </section>

        <section className="ai-panel panel flex flex-col" data-testid="ai-panel">
          <Tabs value={activeTab} onValueChange={setActiveTab} className="flex flex-col h-full">
            <TabsList className="bg-transparent border-b border-[#FF003C]/20 rounded-none p-0 flex-wrap">
              <TabsTrigger value="killchain" className="rounded-none border-b-2 border-transparent data-[state=active]:border-[#FF003C] data-[state=active]:bg-transparent data-[state=active]:text-[#FF003C] text-[#008F11] uppercase tracking-widest text-xs px-2 py-3" data-testid="killchain-tab"><Layers size={12} className="mr-1" />KILL CHAIN</TabsTrigger>
              <TabsTrigger value="tree" className="rounded-none border-b-2 border-transparent data-[state=active]:border-[#FFB000] data-[state=active]:bg-transparent data-[state=active]:text-[#FFB000] text-[#008F11] uppercase tracking-widest text-xs px-2 py-3" data-testid="tree-tab"><GitBranch size={12} className="mr-1" />ATTACK TREE</TabsTrigger>
              <TabsTrigger value="msf" className="rounded-none border-b-2 border-transparent data-[state=active]:border-[#FF003C] data-[state=active]:bg-transparent data-[state=active]:text-[#FF003C] text-[#008F11] uppercase tracking-widest text-xs px-2 py-3" data-testid="msf-tab"><Skull size={12} className="mr-1" />EXPLOIT</TabsTrigger>
              <TabsTrigger value="ai" className="rounded-none border-b-2 border-transparent data-[state=active]:border-[#00F0FF] data-[state=active]:bg-transparent data-[state=active]:text-[#00F0FF] text-[#008F11] uppercase tracking-widest text-xs px-2 py-3" data-testid="ai-tab"><Cpu size={12} className="mr-1" />AI</TabsTrigger>
              <TabsTrigger value="history" className="rounded-none border-b-2 border-transparent data-[state=active]:border-[#00FF41] data-[state=active]:bg-transparent data-[state=active]:text-[#00FF41] text-[#008F11] uppercase tracking-widest text-xs px-2 py-3" data-testid="history-tab"><History size={12} className="mr-1" />OPS</TabsTrigger>
              <TabsTrigger value="chains" className="rounded-none border-b-2 border-transparent data-[state=active]:border-[#FF003C] data-[state=active]:bg-transparent data-[state=active]:text-[#FF003C] text-[#008F11] uppercase tracking-widest text-xs px-2 py-3" data-testid="chains-tab"><Link size={12} className="mr-1" />CHAINS</TabsTrigger>
              <TabsTrigger value="c2" onClick={() => { if (!c2Dashboard) loadC2Dashboard(); }} className="rounded-none border-b-2 border-transparent data-[state=active]:border-[#00F0FF] data-[state=active]:bg-transparent data-[state=active]:text-[#00F0FF] text-[#008F11] uppercase tracking-widest text-xs px-2 py-3" data-testid="c2-tab"><Radio size={12} className="mr-1" />C2</TabsTrigger>
            </TabsList>

            <TabsContent value="killchain" className="flex-1 overflow-auto p-3 mt-0">
              <p className="text-xs text-[#FF003C] mb-3 uppercase tracking-wider">MITRE ATT&CK KILL CHAIN - SELECT PHASES:</p>
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2">
                {KILL_CHAIN.map(phase => {
                  const Icon = phase.icon;
                  const isSelected = selectedPhases.includes(phase.id);
                  const handleClick = (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    if (!isScanning) {
                      togglePhase(phase.id);
                    }
                  };
                  return (
                    <div key={phase.id} onClick={handleClick} className={`p-2 border cursor-pointer transition-all ${isSelected ? 'bg-[#FF003C]/10' : 'hover:bg-[#FF003C]/5'} ${isScanning ? 'opacity-50' : ''}`} style={{ borderColor: isSelected ? phase.color : 'rgba(255,0,60,0.2)' }} data-testid={`phase-${phase.id}`}>
                      <div className="flex items-center gap-2">
                        <input type="checkbox" checked={isSelected} onChange={handleClick} className="matrix-checkbox" style={{ borderColor: phase.color }} />
                        <Icon size={14} style={{ color: phase.color }} />
                      </div>
                      <h3 className="text-xs font-bold uppercase tracking-wider mt-1" style={{ color: phase.color }}>{phase.name}</h3>
                      <p className="text-[10px] text-[#008F11]">{phase.mitre}</p>
                    </div>
                  );
                })}
              </div>
              <div className="mt-4 p-3 border border-[#FF003C]/30">
                <h4 className="text-xs text-[#FF003C] uppercase tracking-wider mb-2">SELECTED ATTACK PATH:</h4>
                <div className="flex flex-wrap items-center gap-1">
                  {selectedPhases.length > 0 ? selectedPhases.map((p, i) => {
                    const phase = KILL_CHAIN.find(k => k.id === p);
                    return (
                      <span key={p} className="flex items-center gap-1">
                        <span className="text-xs px-2 py-0.5" style={{ color: phase?.color, border: `1px solid ${phase?.color}40` }}>{phase?.name}</span>
                        {i < selectedPhases.length - 1 && <span className="text-[#008F11]">→</span>}
                      </span>
                    );
                  }) : <span className="text-xs text-[#008F11]">No phases selected</span>}
                </div>
              </div>
            </TabsContent>

            <TabsContent value="tree" className="flex-1 overflow-auto mt-0">
              <div className="h-full flex flex-col">
                {attackTree && (
                  <div className="flex items-center gap-3 p-2 border-b border-[#FF003C]/20 text-xs flex-wrap">
                    <span className="text-[#008F11]">NODES: {treeStats.total}</span>
                    <span style={{ color: STATUS_COLORS.pending }}>PENDING: {treeStats.pending}</span>
                    <span style={{ color: STATUS_COLORS.success }}>SUCCESS: {treeStats.success}</span>
                    <span style={{ color: STATUS_COLORS.failed }}>FAILED: {treeStats.failed}</span>
                  </div>
                )}
                <ScrollArea className="flex-1 p-3">
                  {treeNodes.length > 0 ? (
                    <div className="attack-tree space-y-1">
                      {treeNodes.map((node, idx) => {
                        const Icon = NODE_ICONS[node.type] || Server;
                        const color = NODE_COLORS[node.type] || "#00FF41";
                        return (
                          <div key={node.id || idx} className="flex items-start gap-2 p-2 border-l-2 hover:bg-[#FF003C]/5" style={{ borderLeftColor: STATUS_COLORS[node.status] || STATUS_COLORS.pending, marginLeft: node.depth * 16 }}>
                            <Icon size={14} style={{ color }} className="flex-shrink-0 mt-0.5" />
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className="text-xs font-bold truncate" style={{ color }}>{node.name}</span>
                                {node.mitre && <span className="text-[10px] text-[#00F0FF]">{node.mitre}</span>}
                                {node.severity && <span className={`text-[10px] px-1 ${node.severity === 'critical' ? 'text-[#FF003C] border-[#FF003C]/50' : node.severity === 'high' ? 'text-[#FFB000] border-[#FFB000]/50' : 'text-[#00F0FF] border-[#00F0FF]/50'} border`}>{node.severity.toUpperCase()}</span>}
                                <span className="text-[10px] px-1" style={{ color: STATUS_COLORS[node.status], border: `1px solid ${STATUS_COLORS[node.status]}40` }}>{node.status}</span>
                              </div>
                              <p className="text-[10px] text-[#008F11] mt-0.5 truncate">{node.description}</p>
                              {node.type === "exploit" && node.status === "pending" && (
                                <div className="flex gap-2 mt-1">
                                  <button onClick={() => { setMsfModule(node.data?.module || node.name); setActiveTab("msf"); }} className="text-[10px] text-[#FF003C] hover:underline">[EXPLOIT]</button>
                                  <button onClick={() => updateNodeStatus(node.id, "success")} className="text-[10px] text-[#00FF41] hover:underline">[SUCCESS]</button>
                                  <button onClick={() => updateNodeStatus(node.id, "failed")} className="text-[10px] text-[#FFB000] hover:underline">[FAILED]</button>
                                </div>
                              )}
                              {!node.isRoot && node.type !== "exploit" && node.status === "pending" && (
                                <div className="flex gap-2 mt-1">
                                  <button onClick={() => updateNodeStatus(node.id, "testing")} className="text-[10px] text-[#FFB000] hover:underline">[TEST]</button>
                                  <button onClick={() => updateNodeStatus(node.id, "success")} className="text-[10px] text-[#00FF41] hover:underline">[✓]</button>
                                </div>
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  ) : (
                    <div className="flex flex-col items-center justify-center h-full text-center">
                      <GitBranch size={40} className="text-[#FFB000] opacity-30 mb-3" />
                      <p className="text-[#008F11] text-xs uppercase">{isScanning ? "Building attack tree..." : "Start operation to generate attack tree"}</p>
                    </div>
                  )}
                </ScrollArea>
              </div>
            </TabsContent>

            <TabsContent value="msf" className="flex-1 overflow-auto mt-0 p-3">
              {msfModule ? (
                <div className="p-3 border border-[#FF003C]/50">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-[#FF003C] uppercase tracking-widest text-xs flex items-center gap-2"><Skull size={14} /> METASPLOIT</h3>
                    <button onClick={() => { setMsfModule(null); setMsfResult(null); }} className="text-[#008F11] hover:text-[#FF003C]"><XCircle size={16} /></button>
                  </div>
                  <div className="space-y-2">
                    <div><label className="text-[10px] text-[#008F11] uppercase">Module</label><div className="matrix-input bg-black/80 text-[#FF003C] text-xs mt-1 p-2">{msfModule}</div></div>
                    <div className="grid grid-cols-2 gap-2">
                      <div><label className="text-[10px] text-[#008F11] uppercase">RHOSTS</label><input type="text" value={target || "127.0.0.1"} readOnly className="matrix-input w-full mt-1 text-xs" /></div>
                      <div><label className="text-[10px] text-[#008F11] uppercase">RPORT</label><input type="text" value={msfPort} onChange={(e) => setMsfPort(e.target.value)} placeholder="80" className="matrix-input w-full mt-1 text-xs" /></div>
                    </div>
                    <div><label className="text-[10px] text-[#008F11] uppercase">LHOST (for reverse shells)</label><input type="text" value={msfLhost} onChange={(e) => setMsfLhost(e.target.value)} placeholder="Your IP" className="matrix-input w-full mt-1 text-xs" /></div>
                    <button onClick={executeMsfExploit} disabled={msfExecuting} className="matrix-btn w-full justify-center text-xs" style={{ borderColor: "#FF003C", color: "#FF003C" }} data-testid="execute-exploit-btn">
                      {msfExecuting ? <><RefreshCw size={12} className="animate-spin" /> EXPLOITING...</> : <><Skull size={12} /> EXECUTE EXPLOIT</>}
                    </button>
                    {msfResult && (
                      <div className={`p-2 border text-xs ${msfResult.success ? 'border-[#00FF41]/50 bg-[#00FF41]/10' : 'border-[#FF003C]/50 bg-[#FF003C]/10'}`}>
                        <div className="flex items-center gap-2 mb-1">
                          {msfResult.success ? <CheckCircle size={12} className="text-[#00FF41]" /> : <XCircle size={12} className="text-[#FF003C]" />}
                          <span className={msfResult.success ? 'text-[#00FF41]' : 'text-[#FF003C]'}>{msfResult.success ? 'SUCCESS' : 'FAILED'}</span>
                          {msfResult.session_opened && <span className="text-[#00FF41] font-bold animate-pulse">SESSION!</span>}
                        </div>
                        {msfResult.simulated && <p className="text-[10px] text-[#FFB000] mb-1">[SIMULATED]</p>}
                        <pre className="text-[10px] text-[#008F11] overflow-auto max-h-24 bg-black/50 p-1">{msfResult.rc_command}</pre>
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div className="space-y-3">
                  {/* Recommended modules based on scan */}
                  {recommendedModules.length > 0 && (
                    <div data-testid="recommended-modules-section">
                      <p className="text-xs text-[#FF003C] uppercase tracking-wider mb-2 flex items-center gap-1"><Zap size={12} /> RECOMENDADOS (segun escaneo)</p>
                      <div className="space-y-1 mb-3">
                        {recommendedModules.map((mod, idx) => (
                          <div key={`rec-${idx}`} onClick={() => setMsfModule(mod.name)} className="p-2 border border-[#FF003C]/50 hover:border-[#FF003C] cursor-pointer bg-[#FF003C]/5" data-testid={`recommended-module-${idx}`}>
                            <div className="flex items-center justify-between">
                              <span className="text-[10px] text-[#FF003C] font-mono truncate flex-1">{mod.name}</span>
                              <div className="flex items-center gap-1">
                                <span className="text-[10px] px-1 border border-[#FFB000]/50 text-[#FFB000]">Score: {mod.relevance_score}</span>
                                <span className={`text-[10px] ${mod.rank === 'excellent' ? 'text-[#00FF41]' : 'text-[#008F11]'}`}>{mod.rank}</span>
                              </div>
                            </div>
                            <p className="text-[10px] text-[#008F11]">{mod.desc}</p>
                            <div className="flex gap-1 mt-1 flex-wrap">
                              {mod.reasons?.map((r, ri) => (
                                <span key={ri} className="text-[10px] px-1 border border-[#00FF41]/30 text-[#00FF41]">{r}</span>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  
                  {/* All modules browser */}
                  <p className="text-xs text-[#008F11] uppercase tracking-wider mb-1">{recommendedModules.length > 0 ? "TODOS LOS MODULOS" : "MODULOS METASPLOIT"}</p>
                  <div className="flex gap-2">
                    <input type="text" value={moduleSearch} onChange={(e) => { setModuleSearch(e.target.value); loadMsfModules(e.target.value, msfCategory); }} placeholder="Search modules..." className="matrix-input flex-1 text-xs" data-testid="msf-search-input" />
                    <select value={msfCategory} onChange={(e) => { setMsfCategory(e.target.value); loadMsfModules(moduleSearch, e.target.value); }} className="matrix-input text-xs w-24" data-testid="msf-category-select">
                      <option value="">All</option>
                      <option value="exploit">Exploit</option>
                      <option value="auxiliary">Auxiliary</option>
                      <option value="post">Post</option>
                    </select>
                  </div>
                  <ScrollArea className="h-[200px]">
                    <div className="space-y-1">
                      {msfModules.map((mod, idx) => (
                        <div key={idx} onClick={() => setMsfModule(mod.name)} className="p-2 border border-[#FF003C]/20 hover:border-[#FF003C] cursor-pointer">
                          <div className="flex items-center justify-between">
                            <span className="text-[10px] text-[#FF003C] font-mono truncate flex-1">{mod.name}</span>
                            <div className="flex items-center gap-1">
                              <span className="text-[10px] text-[#00F0FF]">{mod.mitre}</span>
                              <span className={`text-[10px] ${mod.rank === 'excellent' ? 'text-[#00FF41]' : 'text-[#008F11]'}`}>{mod.rank}</span>
                            </div>
                          </div>
                          <p className="text-[10px] text-[#008F11] truncate">{mod.desc}</p>
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                </div>
              )}
            </TabsContent>

            <TabsContent value="ai" className="flex-1 overflow-auto mt-0">
              <div className="panel-ai h-full">
                <div className="panel-header panel-header-ai p-2"><div className="flex items-center gap-2"><Cpu size={14} className="text-[#00F0FF]" /><span className="text-[#00F0FF] text-xs">KIMI K2 - RED TEAM ADVISOR</span></div></div>
                <ScrollArea className="h-[calc(100%-40px)] p-3">
                  {scanStatus?.ai_analysis ? (
                    <div className="space-y-3">
                      <div className="text-xs text-[#00F0FF] whitespace-pre-wrap font-mono leading-relaxed">{scanStatus.ai_analysis}</div>
                      {scanStatus.exploits?.length > 0 && (
                        <div className="mt-4">
                          <h4 className="text-[10px] uppercase tracking-widest text-[#FF003C] mb-2 flex items-center gap-1"><AlertTriangle size={12} />RECOMMENDED EXPLOITS</h4>
                          {scanStatus.exploits.map((exploit, idx) => (
                            <div key={idx} className="p-2 border border-[#FF003C]/30 mb-1">
                              <div className="flex items-center justify-between">
                                <span className="text-[10px] text-[#FF003C]">{exploit.type?.toUpperCase()}</span>
                                <div className="flex gap-1">
                                  <button onClick={() => copyToClipboard(exploit.command || exploit.module)} className="text-[#008F11] hover:text-[#00FF41]"><Copy size={12} /></button>
                                  {exploit.module && <button onClick={() => { setMsfModule(exploit.module); setActiveTab("msf"); }} className="text-[#FF003C]"><Play size={12} /></button>}
                                </div>
                              </div>
                              <pre className="text-[10px] text-[#008F11] mt-1 bg-black/50 p-1 overflow-x-auto">{exploit.command || exploit.module}</pre>
                            </div>
                          ))}
                        </div>
                      )}
                      {currentScanId && (
                        <div className="flex gap-2 mt-3">
                          <button onClick={() => downloadReport(currentScanId)} className="matrix-btn flex-1 justify-center text-xs" data-testid="download-json-btn"><Download size={12} /> JSON</button>
                          <button onClick={() => { window.open(`${API}/scan/${currentScanId}/report/pdf`, '_blank'); addTerminalLine("success", "PDF report descargado"); }} className="matrix-btn flex-1 justify-center text-xs" style={{ borderColor: "#00F0FF", color: "#00F0FF" }} data-testid="download-pdf-btn"><Download size={12} /> PDF REPORT</button>
                        </div>
                      )}
                      
                      {/* Suggested Chains Section */}
                      {suggestedChains.length > 0 && (
                        <div className="mt-4 p-2 border border-[#FFB000]/40" data-testid="suggested-chains-section">
                          <h4 className="text-[10px] uppercase tracking-widest text-[#FFB000] mb-2 flex items-center gap-1"><Link size={12} /> CADENAS DE ATAQUE SUGERIDAS</h4>
                          {suggestedChains.map((chain, idx) => (
                            <div key={idx} onClick={async () => {
                              try {
                                const resp = await axios.get(`${API}/chains/${chain.id}`);
                                setSelectedChain({ id: chain.id, ...resp.data });
                                setChainExecution(null);
                                setActiveTab("chains");
                              } catch (e) { addTerminalLine("error", e.message); }
                            }} className="p-2 border border-[#FFB000]/30 hover:border-[#FFB000] cursor-pointer mb-1" data-testid={`suggested-chain-${chain.id}`}>
                              <div className="flex items-center justify-between">
                                <span className="text-[10px] text-[#FFB000] font-bold">{chain.name}</span>
                                <span className="text-[10px] text-[#008F11]">{chain.total_steps} steps</span>
                              </div>
                              <p className="text-[10px] text-[#008F11]">{chain.description}</p>
                              <span className="text-[10px] text-[#00FF41]">Trigger: {chain.trigger_matched}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="flex flex-col items-center justify-center h-full text-center"><Cpu size={32} className="text-[#00F0FF] opacity-30 mb-2" /><p className="text-[#008F11] text-xs uppercase">{isScanning ? "Analyzing..." : "Start operation for AI analysis"}</p></div>
                  )}
                </ScrollArea>
              </div>
            </TabsContent>

            <TabsContent value="history" className="flex-1 overflow-auto mt-0">
              <ScrollArea className="h-full p-2">
                {history.length > 0 ? (
                  <div className="space-y-1">
                    {history.map(scan => (
                      <div key={scan.id} className="flex items-center justify-between p-2 border border-[#FF003C]/20 hover:border-[#FF003C]/50">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            {scan.status === 'completed' ? <CheckCircle size={12} className="text-[#00FF41]" /> : <XCircle size={12} className="text-[#FF003C]" />}
                            <span className="text-xs font-bold text-[#00FF41] truncate">{scan.target}</span>
                          </div>
                          <div className="text-[10px] text-[#008F11] flex gap-2 mt-0.5">
                            <span>{new Date(scan.created_at).toLocaleString()}</span>
                            <span>{scan.phases?.length || 0} phases</span>
                          </div>
                        </div>
                        <div className="flex items-center gap-1">
                          <button onClick={() => loadScan(scan.id)} className="text-[#008F11] hover:text-[#00FF41] p-1"><ChevronRight size={14} /></button>
                          <button onClick={() => downloadReport(scan.id)} className="text-[#008F11] hover:text-[#00FF41] p-1"><Download size={12} /></button>
                          <button onClick={() => deleteScan(scan.id)} className="text-[#008F11] hover:text-[#FF003C] p-1"><Trash2 size={12} /></button>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="flex flex-col items-center justify-center h-full"><History size={32} className="text-[#008F11] opacity-30 mb-2" /><p className="text-[#008F11] text-xs uppercase">No operations</p></div>
                )}
              </ScrollArea>
            </TabsContent>

            {/* Attack Chains Tab */}
            <TabsContent value="chains" className="flex-1 overflow-auto mt-0 p-3">
              {selectedChain ? (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <h3 className="text-[#FF003C] text-xs uppercase tracking-widest flex items-center gap-2">
                      <Link size={14} /> {selectedChain.name}
                    </h3>
                    <button onClick={() => { setSelectedChain(null); setChainExecution(null); if (chainPollRef.current) { clearInterval(chainPollRef.current); chainPollRef.current = null; } setChainPolling(false); }} className="text-[#008F11] hover:text-[#FF003C]" data-testid="chain-close-btn">
                      <XCircle size={16} />
                    </button>
                  </div>
                  <p className="text-[10px] text-[#008F11]">{selectedChain.description}</p>
                  
                  {/* Context inputs */}
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <label className="text-[10px] text-[#008F11] uppercase">LHOST (Your IP)</label>
                      <input type="text" value={chainContext.lhost} onChange={(e) => setChainContext({...chainContext, lhost: e.target.value})} className="matrix-input w-full text-xs mt-1" placeholder="10.10.14.x" data-testid="chain-lhost-input" />
                    </div>
                    <div>
                      <label className="text-[10px] text-[#008F11] uppercase">Domain</label>
                      <input type="text" value={chainContext.domain} onChange={(e) => setChainContext({...chainContext, domain: e.target.value})} className="matrix-input w-full text-xs mt-1" placeholder="CORP.LOCAL" data-testid="chain-domain-input" />
                    </div>
                    <div>
                      <label className="text-[10px] text-[#008F11] uppercase">User</label>
                      <input type="text" value={chainContext.user} onChange={(e) => setChainContext({...chainContext, user: e.target.value})} className="matrix-input w-full text-xs mt-1" placeholder="admin" data-testid="chain-user-input" />
                    </div>
                    <div>
                      <label className="text-[10px] text-[#008F11] uppercase">Password</label>
                      <input type="text" value={chainContext.pass} onChange={(e) => setChainContext({...chainContext, pass: e.target.value})} className="matrix-input w-full text-xs mt-1" placeholder="********" data-testid="chain-pass-input" />
                    </div>
                  </div>

                  {/* Execution Progress Pipeline */}
                  {chainExecution && (
                    <div className="p-2 border border-[#FF003C]/40" data-testid="chain-execution-panel">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-[10px] text-[#FF003C] uppercase tracking-widest">EXECUTION: {chainExecution.status?.toUpperCase()}</span>
                        <span className="text-[10px] text-[#008F11]">{chainExecution.progress || 0}%</span>
                      </div>
                      <Progress value={chainExecution.progress || 0} className="h-1 bg-[#0a140a] mb-2" />
                      <div className="flex items-center gap-1 flex-wrap mb-2">
                        {chainExecution.commands?.map((step, idx) => {
                          const stepStatus = chainExecution.step_statuses?.[String(step.step_id)];
                          const status = stepStatus?.status || "pending";
                          const color = status === "completed" ? "#00FF41" : status === "running" ? "#FFB000" : status === "failed" ? "#FF003C" : "#008F11";
                          return (
                            <span key={step.step_id} className="flex items-center gap-1">
                              <span className={`text-[10px] px-2 py-0.5 border ${status === "running" ? "animate-pulse" : ""}`} style={{ color, borderColor: `${color}60` }} data-testid={`chain-step-status-${step.step_id}`}>
                                {status === "completed" ? "+" : status === "running" ? "~" : status === "failed" ? "X" : "."} S{step.step_id}
                              </span>
                              {idx < chainExecution.commands.length - 1 && <span className="text-[#008F11] text-[10px]">&gt;</span>}
                            </span>
                          );
                        })}
                      </div>
                    </div>
                  )}

                  {/* Chain Steps with Execute Buttons */}
                  <ScrollArea className="h-[180px]">
                    <div className="space-y-2">
                      {selectedChain.steps?.map((step) => {
                        const stepStatus = chainExecution?.step_statuses?.[String(step.id)];
                        const status = stepStatus?.status || "pending";
                        const borderColor = status === "completed" ? "#00FF41" : status === "running" ? "#FFB000" : status === "failed" ? "#FF003C" : "rgba(255,0,60,0.3)";
                        return (
                          <div key={step.id} className={`p-2 border ${status === "running" ? "animate-pulse" : ""}`} style={{ borderColor }} data-testid={`chain-step-${step.id}`}>
                            <div className="flex items-center justify-between">
                              <span className="text-xs font-bold flex items-center gap-2" style={{ color: status === "completed" ? "#00FF41" : status === "running" ? "#FFB000" : "#FF003C" }}>
                                {status === "completed" ? <CheckCircle size={12} /> : status === "running" ? <RefreshCw size={12} className="animate-spin" /> : status === "failed" ? <XCircle size={12} /> : <ChevronRight size={12} />}
                                STEP {step.id}: {step.name}
                              </span>
                              <div className="flex items-center gap-2">
                                <span className="text-[10px] px-1 border" style={{ color: borderColor, borderColor: `${borderColor}60` }}>{status.toUpperCase()}</span>
                                {chainExecution && status === "pending" && !chainPolling && (
                                  <button 
                                    onClick={() => executeChainStep(chainExecution.execution_id || chainExecution.id, step.id)}
                                    className="text-[10px] text-[#FFB000] hover:text-[#FF003C] hover:underline"
                                    data-testid={`exec-step-${step.id}`}
                                  >
                                    [RUN]
                                  </button>
                                )}
                              </div>
                            </div>
                            <div className="mt-1 space-y-1">
                              {step.actions?.map((action, aidx) => (
                                <div key={aidx} className="flex items-center gap-1">
                                  <div className="text-[10px] text-[#008F11] bg-black/30 p-1 font-mono truncate flex-1">
                                    {action.tool && <span className="text-[#FFB000]">[{action.tool}] </span>}
                                    {action.cmd || action.module}
                                  </div>
                                  <button onClick={() => copyToClipboard(action.cmd || action.module || "")} className="text-[#008F11] hover:text-[#00FF41] flex-shrink-0"><Copy size={10} /></button>
                                </div>
                              ))}
                            </div>
                            {/* Show step results if available */}
                            {stepStatus?.command_results?.length > 0 && (
                              <div className="mt-1 p-1 bg-black/50 border border-[#00FF41]/20">
                                {stepStatus.command_results.map((cr, cri) => (
                                  <div key={cri} className="text-[10px] font-mono">
                                    {cr.output && <span className="text-[#00FF41]">{cr.output}</span>}
                                    {cr.error && <span className="text-[#FF003C]">{cr.error}</span>}
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </ScrollArea>

                  {/* Action Buttons */}
                  <div className="flex gap-2">
                    {!chainExecution ? (
                      <>
                        <button
                          onClick={async () => {
                            addTerminalLine("command", `> Preparing Chain: ${selectedChain.name}`);
                            try {
                              const response = await axios.post(`${API}/chains/execute`, {
                                scan_id: currentScanId || "",
                                chain_id: selectedChain.id,
                                target: target,
                                context: chainContext,
                                auto_execute: false
                              });
                              setChainExecution(response.data);
                              addTerminalLine("success", `Chain ready: ${response.data.execution_id}`);
                              addTerminalLine("info", `${response.data.total_steps} steps prepared. Use [RUN] per step or AUTO-EXECUTE all.`);
                            } catch (error) {
                              addTerminalLine("error", `Error: ${error.message}`);
                            }
                          }}
                          className="matrix-btn flex-1 justify-center text-xs"
                          style={{ borderColor: "#FFB000", color: "#FFB000" }}
                          disabled={!target}
                          data-testid="prepare-chain-btn"
                        >
                          <Crosshair size={12} /> PREPARE (MANUAL)
                        </button>
                        <button
                          onClick={executeChainAuto}
                          className="matrix-btn flex-1 justify-center text-xs"
                          style={{ borderColor: "#FF003C", color: "#FF003C" }}
                          disabled={!target}
                          data-testid="auto-execute-chain-btn"
                        >
                          <Zap size={12} /> AUTO-EXECUTE
                        </button>
                      </>
                    ) : chainExecution.status === "completed" ? (
                      <div className="w-full p-2 border border-[#00FF41]/50 bg-[#00FF41]/5 text-center">
                        <span className="text-xs text-[#00FF41] flex items-center justify-center gap-2"><CheckCircle size={14} /> CHAIN EXECUTION COMPLETE</span>
                      </div>
                    ) : chainExecution.status === "running" ? (
                      <div className="w-full p-2 border border-[#FFB000]/50 bg-[#FFB000]/5 text-center">
                        <span className="text-xs text-[#FFB000] flex items-center justify-center gap-2"><RefreshCw size={14} className="animate-spin" /> EXECUTING... Step {chainExecution.current_step}/{chainExecution.total_steps}</span>
                      </div>
                    ) : (
                      <button
                        onClick={executeChainAuto}
                        className="matrix-btn w-full justify-center text-xs"
                        style={{ borderColor: "#FF003C", color: "#FF003C" }}
                        data-testid="run-all-chain-btn"
                      >
                        <Zap size={12} /> RUN ALL REMAINING
                      </button>
                    )}
                  </div>
                </div>
              ) : (
                <div className="space-y-2">
                  <p className="text-xs text-[#FF003C] uppercase tracking-wider mb-3">AUTOMATED ATTACK CHAINS</p>
                  {attackChains.map(chain => (
                    <div 
                      key={chain.id}
                      onClick={async () => {
                        try {
                          const response = await axios.get(`${API}/chains/${chain.id}`);
                          setSelectedChain({ id: chain.id, ...response.data });
                          setChainExecution(null);
                        } catch (error) {
                          addTerminalLine("error", `Error loading chain: ${error.message}`);
                        }
                      }}
                      className="p-3 border border-[#FF003C]/30 hover:border-[#FF003C] cursor-pointer transition-all"
                      data-testid={`chain-card-${chain.id}`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-xs text-[#FF003C] font-bold">{chain.name}</span>
                        <span className="text-[10px] text-[#008F11]">{chain.steps_count} steps</span>
                      </div>
                      <p className="text-[10px] text-[#008F11] mt-1">{chain.description}</p>
                      <div className="flex gap-1 mt-2 flex-wrap">
                        {chain.triggers?.map((t, i) => (
                          <span key={i} className="text-[10px] px-1 border border-[#FFB000]/50 text-[#FFB000]">{t}</span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </TabsContent>

            {/* C2 Dashboard Tab */}
            <TabsContent value="c2" className="flex-1 overflow-auto mt-0 p-3">
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-[#00F0FF] text-xs uppercase tracking-widest flex items-center gap-2"><Radio size={14} /> C2 COMMAND & CONTROL</h3>
                  <button onClick={loadC2Dashboard} className="text-[10px] text-[#008F11] hover:text-[#00FF41]" data-testid="c2-refresh-btn"><RefreshCw size={12} className={c2Loading ? "animate-spin" : ""} /></button>
                </div>

                {!c2Dashboard ? (
                  <div className="p-4 border border-[#00F0FF]/30 text-center">
                    <Radio size={24} className="text-[#00F0FF] mx-auto mb-2" />
                    <p className="text-xs text-[#008F11]">Loading C2 status...</p>
                  </div>
                ) : selectedSession ? (
                  /* Session Interactive Shell */
                  <div className="space-y-2" data-testid="session-shell">
                    <div className="flex items-center justify-between">
                      <span className="text-xs text-[#00FF41] flex items-center gap-1"><Command size={12} /> SESSION: {selectedSession.id}</span>
                      <button onClick={() => { setSelectedSession(null); setSessionOutput([]); }} className="text-[#008F11] hover:text-[#FF003C]"><XCircle size={14} /></button>
                    </div>
                    <div className="p-1 border border-[#008F11]/30 text-[10px] text-[#008F11]">
                      <span>{selectedSession.source === "msf" ? "Metasploit" : "Sliver"} | {selectedSession.target_host || selectedSession.remote_address || "?"} | {selectedSession.type}</span>
                    </div>
                    <ScrollArea className="h-[160px] bg-black/80 border border-[#008F11]/20 p-2">
                      {sessionOutput.map((entry, idx) => (
                        <div key={idx} className="mb-1">
                          <div className="text-[10px] text-[#FFB000] font-mono">&gt; {entry.cmd}</div>
                          {entry.output && <pre className="text-[10px] text-[#00FF41] font-mono whitespace-pre-wrap">{entry.output}</pre>}
                          {entry.error && <pre className="text-[10px] text-[#FF003C] font-mono whitespace-pre-wrap">{entry.error}</pre>}
                        </div>
                      ))}
                    </ScrollArea>
                    <div className="flex gap-1">
                      <input type="text" value={sessionCmd} onChange={(e) => setSessionCmd(e.target.value)} onKeyDown={(e) => e.key === "Enter" && runSessionCommand()} placeholder="Command..." className="matrix-input flex-1 text-xs" data-testid="session-cmd-input" />
                      <button onClick={runSessionCommand} className="matrix-btn text-xs" style={{ borderColor: "#00FF41", color: "#00FF41" }} data-testid="session-cmd-run"><Play size={12} /></button>
                    </div>
                  </div>
                ) : (
                  <>
                    {/* MSF Status */}
                    <div className="p-2 border border-[#FF003C]/30" data-testid="msf-status-panel">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs text-[#FF003C] font-bold flex items-center gap-1"><Skull size={12} /> METASPLOIT RPC</span>
                        <span className={`text-[10px] px-2 py-0.5 border ${c2Dashboard.metasploit?.connected ? "border-[#00FF41] text-[#00FF41]" : "border-[#FF003C] text-[#FF003C]"}`}>
                          {c2Dashboard.metasploit?.connected ? "CONNECTED" : "OFFLINE"}
                        </span>
                      </div>
                      {c2Dashboard.metasploit?.connected ? (
                        <div className="space-y-1">
                          <p className="text-[10px] text-[#008F11]">v{c2Dashboard.metasploit.version} | Sessions: {c2Dashboard.metasploit.session_count} | Jobs: {c2Dashboard.metasploit.job_count}</p>
                          
                          {/* MSF RPC Search */}
                          <div className="flex gap-1 mt-2">
                            <input type="text" value={msfSearchQuery} onChange={(e) => setMsfSearchQuery(e.target.value)} onKeyDown={(e) => e.key === "Enter" && searchMsfRpc(msfSearchQuery)} placeholder="Search MSF modules..." className="matrix-input flex-1 text-xs" data-testid="msf-rpc-search" />
                            <button onClick={() => searchMsfRpc(msfSearchQuery)} className="matrix-btn text-xs" style={{ borderColor: "#FF003C" }}><Radar size={12} /></button>
                          </div>
                          {msfRpcModules.length > 0 && (
                            <ScrollArea className="h-[80px]">
                              {msfRpcModules.map((mod, idx) => (
                                <div key={idx} className="p-1 border-b border-[#FF003C]/10 text-[10px] hover:bg-[#FF003C]/5 cursor-pointer" onClick={() => { setMsfModule(mod.name); setActiveTab("msf"); }}>
                                  <span className="text-[#FF003C]">{mod.name}</span>
                                  <span className="text-[#008F11] ml-2">{mod.desc}</span>
                                </div>
                              ))}
                            </ScrollArea>
                          )}
                          
                          {/* MSF Sessions */}
                          {c2Dashboard.metasploit.sessions?.length > 0 && (
                            <div className="mt-2">
                              <span className="text-[10px] text-[#FFB000] uppercase">Active Sessions:</span>
                              {c2Dashboard.metasploit.sessions.map((s, idx) => (
                                <div key={idx} onClick={() => setSelectedSession({...s, source: "msf"})} className="p-1 border border-[#00FF41]/30 hover:border-[#00FF41] cursor-pointer mt-1 flex items-center justify-between" data-testid={`msf-session-${s.id}`}>
                                  <span className="text-[10px] text-[#00FF41]">{s.type} @ {s.target_host}</span>
                                  <span className="text-[10px] text-[#008F11]">{s.via_exploit}</span>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      ) : (
                        <div className="text-[10px] text-[#008F11] space-y-1">
                          <p>{c2Dashboard.metasploit?.error}</p>
                          <p className="text-[#FFB000]">En tu Kali ejecuta:</p>
                          <div className="bg-black/50 p-1 font-mono text-[#00FF41]">msfrpcd -P {'{'}TOKEN{'}'} -S -a 127.0.0.1</div>
                        </div>
                      )}
                    </div>

                    {/* Sliver Status */}
                    <div className="p-2 border border-[#00F0FF]/30" data-testid="sliver-status-panel">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs text-[#00F0FF] font-bold flex items-center gap-1"><Wifi size={12} /> SLIVER C2</span>
                        <span className={`text-[10px] px-2 py-0.5 border ${c2Dashboard.sliver?.connected ? "border-[#00FF41] text-[#00FF41]" : "border-[#FF003C] text-[#FF003C]"}`}>
                          {c2Dashboard.sliver?.connected ? "CONNECTED" : "OFFLINE"}
                        </span>
                      </div>
                      {c2Dashboard.sliver?.connected ? (
                        <div className="space-y-1">
                          <p className="text-[10px] text-[#008F11]">v{c2Dashboard.sliver.version} | Sessions: {c2Dashboard.sliver.session_count} | Beacons: {c2Dashboard.sliver.beacon_count}</p>
                          
                          {/* Sliver Sessions */}
                          {c2Dashboard.sliver.sessions?.map((s, idx) => (
                            <div key={idx} onClick={() => setSelectedSession({...s, source: "sliver"})} className="p-1 border border-[#00F0FF]/30 hover:border-[#00F0FF] cursor-pointer flex items-center justify-between" data-testid={`sliver-session-${s.id}`}>
                              <span className="text-[10px] text-[#00F0FF]">{s.name} @ {s.hostname}</span>
                              <span className="text-[10px] text-[#008F11]">{s.os}/{s.arch}</span>
                            </div>
                          ))}
                          
                          {/* Sliver Beacons */}
                          {c2Dashboard.sliver.beacons?.map((b, idx) => (
                            <div key={idx} className="p-1 border border-[#FFB000]/30 flex items-center justify-between">
                              <span className="text-[10px] text-[#FFB000]">{b.name} @ {b.hostname}</span>
                              <span className="text-[10px] text-[#008F11]">{b.os} | interval: {b.interval}s</span>
                            </div>
                          ))}
                          
                          {/* Generate Implant */}
                          <div className="mt-2 p-2 border border-[#00F0FF]/20">
                            <span className="text-[10px] text-[#00F0FF] uppercase">Generate Implant</span>
                            <div className="grid grid-cols-3 gap-1 mt-1">
                              <input type="text" value={sliverGenConfig.name} onChange={(e) => setSliverGenConfig({...sliverGenConfig, name: e.target.value})} placeholder="Name" className="matrix-input text-[10px]" data-testid="sliver-name" />
                              <input type="text" value={sliverGenConfig.lhost} onChange={(e) => setSliverGenConfig({...sliverGenConfig, lhost: e.target.value})} placeholder="LHOST" className="matrix-input text-[10px]" data-testid="sliver-lhost" />
                              <input type="number" value={sliverGenConfig.lport} onChange={(e) => setSliverGenConfig({...sliverGenConfig, lport: parseInt(e.target.value)})} className="matrix-input text-[10px]" data-testid="sliver-lport" />
                            </div>
                            <div className="grid grid-cols-3 gap-1 mt-1">
                              <select value={sliverGenConfig.os} onChange={(e) => setSliverGenConfig({...sliverGenConfig, os: e.target.value})} className="matrix-input text-[10px]">
                                <option value="linux">Linux</option><option value="windows">Windows</option><option value="darwin">macOS</option>
                              </select>
                              <select value={sliverGenConfig.arch} onChange={(e) => setSliverGenConfig({...sliverGenConfig, arch: e.target.value})} className="matrix-input text-[10px]">
                                <option value="amd64">x64</option><option value="386">x86</option><option value="arm64">ARM64</option>
                              </select>
                              <select value={sliverGenConfig.type} onChange={(e) => setSliverGenConfig({...sliverGenConfig, type: e.target.value})} className="matrix-input text-[10px]">
                                <option value="session">Session</option><option value="beacon">Beacon</option>
                              </select>
                            </div>
                            <button onClick={async () => {
                              addTerminalLine("command", `> Generating ${sliverGenConfig.type}: ${sliverGenConfig.name}`);
                              try {
                                const resp = await axios.post(`${API}/sliver/implant/generate`, sliverGenConfig);
                                if (resp.data.error) { addTerminalLine("error", resp.data.error); }
                                else { addTerminalLine("success", `Implant generated: ${resp.data.file_name} (${resp.data.size} bytes)`); }
                              } catch (e) { addTerminalLine("error", e.message); }
                            }} className="matrix-btn w-full justify-center text-[10px] mt-1" style={{ borderColor: "#00F0FF", color: "#00F0FF" }} data-testid="sliver-generate-btn">
                              <Upload size={10} /> GENERATE
                            </button>
                          </div>
                        </div>
                      ) : (
                        <div className="text-[10px] text-[#008F11] space-y-1">
                          <p>{c2Dashboard.sliver?.error}</p>
                          <p className="text-[#FFB000]">Para instalar Sliver en tu Kali:</p>
                          <div className="bg-black/50 p-1 font-mono text-[#00FF41] space-y-0.5">
                            <div>curl https://sliver.sh/install|sudo bash</div>
                            <div>sliver-server</div>
                            <div>new-operator --name redteam --lhost 127.0.0.1</div>
                          </div>
                          <p className="text-[#FFB000] mt-1">Luego configura SLIVER_CONFIG_PATH en backend/.env</p>
                        </div>
                      )}
                    </div>

                    {/* Listener Quick Start */}
                    <div className="p-2 border border-[#008F11]/30">
                      <span className="text-[10px] text-[#008F11] uppercase">Quick Start Listeners</span>
                      <div className="grid grid-cols-2 gap-1 mt-1">
                        <button onClick={async () => {
                          try {
                            const resp = await axios.post(`${API}/sliver/listener/start`, { lhost: "0.0.0.0", lport: 443, protocol: "mtls" });
                            addTerminalLine(resp.data.success ? "success" : "error", resp.data.success ? `mTLS listener on :443` : resp.data.error);
                          } catch (e) { addTerminalLine("error", e.message); }
                        }} className="matrix-btn text-[10px] justify-center" style={{ borderColor: "#00F0FF", color: "#00F0FF" }} data-testid="listener-mtls"><Lock size={10} /> mTLS:443</button>
                        <button onClick={async () => {
                          try {
                            const resp = await axios.post(`${API}/sliver/listener/start`, { lhost: "0.0.0.0", lport: 8443, protocol: "https" });
                            addTerminalLine(resp.data.success ? "success" : "error", resp.data.success ? `HTTPS listener on :8443` : resp.data.error);
                          } catch (e) { addTerminalLine("error", e.message); }
                        }} className="matrix-btn text-[10px] justify-center" style={{ borderColor: "#FFB000", color: "#FFB000" }} data-testid="listener-https"><Globe size={10} /> HTTPS:8443</button>
                      </div>
                    </div>
                  </>
                )}
              </div>
            </TabsContent>
          </Tabs>
        </section>
      </main>

      <footer className="status-bar" style={{ borderColor: "rgba(255,0,60,0.3)" }}>
        <div className="status-indicator"><div className={`status-dot ${isScanning ? 'warning' : ''}`} style={{ background: isScanning ? "#FFB000" : "#00FF41" }} /><span>STATUS: {isScanning ? 'ENGAGING' : 'STANDBY'}</span></div>
        <div className="flex items-center gap-4 text-xs">
          <span className="text-[#FF003C]">TARGET: {target || 'N/A'}</span>
          <span>PHASES: {selectedPhases.length}/14</span>
          {attackTree && <span className="text-[#FFB000]">NODES: {treeStats.total}</span>}
          {c2Dashboard?.metasploit?.connected && <span className="text-[#FF003C]">MSF:ON</span>}
          {c2Dashboard?.sliver?.connected && <span className="text-[#00F0FF]">SLIVER:ON</span>}
          <span className="text-[#FF003C]">MITRE ATT&CK</span>
        </div>
      </footer>
    </div>
  );
}

export default App;
