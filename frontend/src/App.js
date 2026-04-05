import { useState, useEffect, useCallback, useRef } from "react";
import axios from "axios";
import { motion, AnimatePresence } from "framer-motion";
import {
  LayoutDashboard, Crosshair, GitBranch, Link, Radio, Brain, Terminal,
  Play, Square, Plus, Trash2, RefreshCw, ChevronRight, CheckCircle, XCircle,
  Zap, Shield, Wifi, Skull, Eye, Activity, Server, Lock, Globe, Copy,
  Download, Search, Command, MonitorSmartphone, Clock, AlertTriangle, Target
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
  const [scanStatus, setScanStatus] = useState(null);
  const [attackTree, setAttackTree] = useState(null);
  const [history, setHistory] = useState([]);
  const [terminalLines, setTerminalLines] = useState([{ type: "info", text: "RED TEAM FRAMEWORK v5.0 // AUTONOMOUS APT PLATFORM", time: new Date() }]);
  const [logFilter, setLogFilter] = useState("all");

  // Tools & modules
  const [mitreTactics, setMitreTactics] = useState([]);
  const [msfModules, setMsfModules] = useState([]);
  const [recommendedModules, setRecommendedModules] = useState([]);
  const [moduleSearch, setModuleSearch] = useState("");
  const [msfCategory, setMsfCategory] = useState("");

  // MSF execution
  const [msfModule, setMsfModule] = useState(null);
  const [msfPort, setMsfPort] = useState("");
  const [msfLhost, setMsfLhost] = useState("");
  const [msfExecuting, setMsfExecuting] = useState(false);
  const [msfResult, setMsfResult] = useState(null);

  // Chains
  const [attackChains, setAttackChains] = useState([]);
  const [selectedChain, setSelectedChain] = useState(null);
  const [chainExecution, setChainExecution] = useState(null);
  const [chainContext, setChainContext] = useState({ lhost: "", domain: "", user: "", pass: "" });
  const [chainPolling, setChainPolling] = useState(false);
  const [suggestedChains, setSuggestedChains] = useState([]);

  // C2
  const [c2Dashboard, setC2Dashboard] = useState(null);
  const [selectedSession, setSelectedSession] = useState(null);
  const [sessionCmd, setSessionCmd] = useState("");
  const [sessionOutput, setSessionOutput] = useState([]);

  // AI
  const [aiAnalysis, setAiAnalysis] = useState(null);

  // Autonomous mode
  const [autonomousMode, setAutonomousMode] = useState(false);

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
        const [tacticsRes, chainsRes, modulesRes, historyRes] = await Promise.all([
          axios.get(`${API}/mitre/tactics`),
          axios.get(`${API}/chains`),
          axios.get(`${API}/metasploit/modules`),
          axios.get(`${API}/scan/history`)
        ]);
        setMitreTactics(tacticsRes.data.tactics || []);
        setAttackChains(chainsRes.data.chains || []);
        setMsfModules(modulesRes.data.modules || []);
        setHistory(historyRes.data || []);
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
    addLog("cmd", `ENGAGE >> ${target}`);
    try {
      const res = await axios.post(`${API}/scan/start`, { target, scan_phases: selectedPhases, tools: [] });
      setCurrentScanId(res.data.scan_id);
      addLog("success", `OP-ID: ${res.data.scan_id}`);

      // Add to targets
      setTargets(prev => {
        const existing = prev.find(t => t.target === target);
        if (existing) return prev.map(t => t.target === target ? { ...t, status: "scanning", scanId: res.data.scan_id } : t);
        return [...prev, { target, status: "scanning", scanId: res.data.scan_id, addedAt: new Date().toISOString() }];
      });

      pollIntervalRef.current = setInterval(() => pollScan(res.data.scan_id), 2000);
    } catch (e) { addLog("error", e.message); setIsScanning(false); }
  };

  const pollScan = async (scanId) => {
    try {
      const res = await axios.get(`${API}/scan/${scanId}/status`);
      setScanStatus(res.data);

      if (res.data.current_tool) addLog("info", `[${res.data.current_tool}] ${res.data.progress}%`);

      // Adaptive log
      res.data.adaptive_log?.slice(-2).forEach(d => {
        if (d.decision === "SKIP") addLog("warning", `[ADAPT] SKIP: ${d.reason}`);
        else if (d.decision === "ADD") addLog("info", `[ADAPT] +TOOL: ${d.reason}`);
        else if (d.decision === "EXPLOIT") addLog("error", `[ADAPT] AUTO-EXPLOIT: ${d.reason}`);
      });

      if (res.data.status === "completed") {
        clearInterval(pollIntervalRef.current);
        setIsScanning(false);
        addLog("success", "SCAN COMPLETE");
        setAttackTree(res.data.attack_tree);
        setAiAnalysis(res.data.ai_analysis);
        if (res.data.suggested_chains?.length) setSuggestedChains(res.data.suggested_chains);
        if (res.data.recommended_modules?.length) setRecommendedModules(res.data.recommended_modules);

        setTargets(prev => prev.map(t => t.scanId === scanId ? { ...t, status: "exploited", results: res.data } : t));

        if (res.data.vault_summary) {
          const v = res.data.vault_summary;
          addLog("info", `[VAULT] Creds:${v.total_credentials||0} Sessions:${v.sessions||0}`);
        }

        // Auto-chain trigger
        if (autonomousMode && res.data.auto_triggered_chain) {
          addLog("error", `[AUTO] Triggering chain: ${res.data.auto_triggered_chain.chain_id}`);
        }
      }
    } catch (e) { /* polling error, will retry */ }
  };

  const abortScan = async () => {
    if (currentScanId) {
      try { await axios.post(`${API}/scan/${currentScanId}/abort`); } catch (e) {}
    }
    clearInterval(pollIntervalRef.current);
    setIsScanning(false);
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
  const loadC2 = async () => {
    try {
      const res = await axios.get(`${API}/c2/dashboard`);
      setC2Dashboard(res.data);
    } catch (e) { addLog("error", e.message); }
  };

  const runSessionCmd = async () => {
    if (!selectedSession || !sessionCmd) return;
    addLog("cmd", `[${selectedSession.source}] ${sessionCmd}`);
    try {
      const endpoint = selectedSession.source === "msf" ? `${API}/msf/session/command` : `${API}/sliver/session/exec`;
      const res = await axios.post(endpoint, { session_id: selectedSession.id, command: sessionCmd });
      setSessionOutput(prev => [...prev, { cmd: sessionCmd, output: res.data.output || res.data.stdout || "", error: res.data.error || "" }]);
    } catch (e) { addLog("error", e.message); }
    setSessionCmd("");
  };

  // MSF
  const loadMsfModules = async (search, cat) => {
    try {
      const res = await axios.get(`${API}/metasploit/modules`, { params: { search, category: cat } });
      setMsfModules(res.data.modules || []);
    } catch (e) {}
  };

  const executeMsf = async () => {
    if (!msfModule) return;
    setMsfExecuting(true);
    addLog("cmd", `msf > ${msfModule}`);
    try {
      const res = await axios.post(`${API}/metasploit/execute`, { module: msfModule, target: target || "127.0.0.1", port: msfPort ? parseInt(msfPort) : null, options: {}, lhost: msfLhost, lport: 4444 });
      setMsfResult(res.data);
      addLog(res.data.success ? "success" : "error", res.data.success ? "Exploit SUCCESS" : "Exploit FAILED");
    } catch (e) { addLog("error", e.message); }
    setMsfExecuting(false);
  };

  // Filtered logs
  const filteredLogs = logFilter === "all" ? terminalLines : terminalLines.filter(l => l.type === logFilter);

  // NAV ITEMS
  const navItems = [
    { id: "dashboard", icon: LayoutDashboard, label: "Dashboard" },
    { id: "targets", icon: Crosshair, label: "Targets" },
    { id: "graph", icon: GitBranch, label: "Attack Graph" },
    { id: "chains", icon: Link, label: "Chains" },
    { id: "c2", icon: Radio, label: "C2" },
    { id: "ai", icon: Brain, label: "AI" },
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
              <div className="text-[10px] text-[#2F4F38] tracking-wider">APT FRAMEWORK v5.0</div>
            </div>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 py-2">
          {navItems.map(item => (
            <div key={item.id} onClick={() => { setActiveSection(item.id); if (item.id === "c2" && !c2Dashboard) loadC2(); }} className={`nav-item ${activeSection === item.id ? "active" : ""}`} data-testid={`nav-${item.id}`}>
              <item.icon size={14} />
              <span>{item.label}</span>
            </div>
          ))}
        </nav>

        {/* Autonomous Mode Toggle */}
        <div className="p-3 border-t border-[rgba(0,255,65,0.15)]">
          <button onClick={() => { setAutonomousMode(!autonomousMode); addLog(autonomousMode ? "warning" : "error", autonomousMode ? "AUTONOMOUS MODE OFF" : "AUTONOMOUS APT ENGAGED"); }} className={`w-full py-3 text-xs font-bold tracking-[0.15em] uppercase cursor-pointer transition-all ${autonomousMode ? "auto-mode-on" : "auto-mode-off"}`} data-testid="toggle-autonomous-mode">
            {autonomousMode ? <><Activity size={14} className="inline mr-2 animate-pulse" />AUTONOMOUS</> : <><Zap size={14} className="inline mr-2" />ENGAGE AUTO</>}
          </button>
        </div>

        {/* Status */}
        <div className="p-3 border-t border-[rgba(0,255,65,0.15)] text-[10px] space-y-1">
          <div className="flex justify-between"><span className="text-[#2F4F38]">STATUS</span><span className={isScanning ? "text-[#FFB000]" : "text-[#00FF41]"}>{isScanning ? "ENGAGING" : "STANDBY"}</span></div>
          <div className="flex justify-between"><span className="text-[#2F4F38]">TARGETS</span><span>{targets.length}</span></div>
          <div className="flex justify-between"><span className="text-[#2F4F38]">SESSIONS</span><span>{stats.sessions}</span></div>
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
                            {attackTree.nodes?.map((node, i) => (
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
                            {selectedChain.steps?.map(step => {
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
                                    {step.actions?.map((a, ai) => (
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
                              {c.triggers?.map((t, ti) => <span key={ti} className="text-[10px] px-1 border border-[#FFB000]/30 text-[#FFB000]">{t}</span>)}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* ===== C2 ===== */}
                {activeSection === "c2" && (
                  <div className="space-y-3" data-testid="c2-section">
                    {selectedSession ? (
                      <div className="space-y-2" data-testid="session-shell">
                        <div className="flex items-center justify-between">
                          <span className="text-xs text-[#00FF41] font-bold flex items-center gap-2"><Command size={12} /> SESSION: {selectedSession.id}</span>
                          <button onClick={() => { setSelectedSession(null); setSessionOutput([]); }} className="text-[#2F4F38] hover:text-[#FF003C]"><XCircle size={14} /></button>
                        </div>
                        <ScrollArea className="h-64 bg-[#020302] border border-[rgba(0,255,65,0.15)] p-3">
                          {sessionOutput.map((e, i) => (
                            <div key={i} className="mb-2">
                              <div className="text-[10px] text-[#00F0FF] font-mono">$ {e.cmd}</div>
                              {e.output && <pre className="text-[10px] text-[#00FF41] font-mono whitespace-pre-wrap">{e.output}</pre>}
                              {e.error && <pre className="text-[10px] text-[#FF003C] font-mono whitespace-pre-wrap">{e.error}</pre>}
                            </div>
                          ))}
                        </ScrollArea>
                        <div className="flex gap-1">
                          <input type="text" value={sessionCmd} onChange={e => setSessionCmd(e.target.value)} onKeyDown={e => e.key === "Enter" && runSessionCmd()} placeholder="command..." className="tac-input flex-1 text-xs" data-testid="session-cmd-input" />
                          <button onClick={runSessionCmd} className="tac-btn text-[10px]" data-testid="session-cmd-run"><Play size={12} /></button>
                        </div>
                      </div>
                    ) : (
                      <>
                        <div className="flex items-center justify-between">
                          <h3 className="text-xs font-bold tracking-[0.15em] uppercase">Command & Control</h3>
                          <button onClick={loadC2} className="tac-btn text-[10px]" data-testid="c2-refresh-btn"><RefreshCw size={12} /></button>
                        </div>
                        {c2Dashboard ? (
                          <div className="grid grid-cols-2 gap-3">
                            {/* MSF */}
                            <div className="panel" data-testid="msf-status-panel">
                              <div className="panel-header">
                                <h3 className="flex items-center gap-1"><Skull size={12} className="text-[#FF003C]" /> Metasploit RPC</h3>
                                <span className={`text-[10px] ${c2Dashboard.metasploit?.connected ? "text-[#00FF41]" : "text-[#FF003C]"}`}>{c2Dashboard.metasploit?.connected ? "ONLINE" : "OFFLINE"}</span>
                              </div>
                              <div className="p-3">
                                {c2Dashboard.metasploit?.connected ? (
                                  <div className="space-y-2">
                                    <p className="text-[10px] text-[#8BBE95]">v{c2Dashboard.metasploit.version} // Sessions: {c2Dashboard.metasploit.session_count} // Jobs: {c2Dashboard.metasploit.job_count}</p>
                                    {c2Dashboard.metasploit.sessions?.map((s, i) => (
                                      <div key={i} onClick={() => setSelectedSession({ ...s, source: "msf" })} className="session-card" data-testid={`msf-session-${s.id}`}>
                                        <span className="text-[10px] text-[#00FF41]">{s.type} @ {s.target_host}</span>
                                      </div>
                                    ))}
                                  </div>
                                ) : (
                                  <div className="text-[10px] text-[#2F4F38] space-y-1">
                                    <p>Not connected</p>
                                    <code className="block bg-[#020302] p-2 text-[#00FF41]">msfrpcd -P TOKEN -S -a 127.0.0.1</code>
                                  </div>
                                )}
                              </div>
                            </div>
                            {/* Sliver */}
                            <div className="panel" data-testid="sliver-status-panel">
                              <div className="panel-header">
                                <h3 className="flex items-center gap-1"><Wifi size={12} className="text-[#00F0FF]" /> Sliver C2</h3>
                                <span className={`text-[10px] ${c2Dashboard.sliver?.connected ? "text-[#00FF41]" : "text-[#FF003C]"}`}>{c2Dashboard.sliver?.connected ? "ONLINE" : "OFFLINE"}</span>
                              </div>
                              <div className="p-3">
                                {c2Dashboard.sliver?.connected ? (
                                  <div className="space-y-2">
                                    <p className="text-[10px] text-[#8BBE95]">v{c2Dashboard.sliver.version} // Sessions: {c2Dashboard.sliver.session_count}</p>
                                    {c2Dashboard.sliver.sessions?.map((s, i) => (
                                      <div key={i} onClick={() => setSelectedSession({ ...s, source: "sliver" })} className="session-card">
                                        <span className="text-[10px] text-[#00F0FF]">{s.name} @ {s.hostname}</span>
                                      </div>
                                    ))}
                                  </div>
                                ) : (
                                  <div className="text-[10px] text-[#2F4F38] space-y-1">
                                    <p>Not connected</p>
                                    <code className="block bg-[#020302] p-2 text-[#00FF41]">curl https://sliver.sh/install|sudo bash</code>
                                  </div>
                                )}
                              </div>
                            </div>
                          </div>
                        ) : (
                          <div className="text-center py-8 text-[10px] text-[#2F4F38]">Loading C2 status...</div>
                        )}
                      </>
                    )}
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

                    {/* Recommended Modules */}
                    {recommendedModules.length > 0 && (
                      <div className="panel" data-testid="recommended-modules-section">
                        <div className="panel-header"><h3>Recommended Exploits</h3><span className="text-[10px] text-[#2F4F38]">{recommendedModules.length}</span></div>
                        <div className="p-3 space-y-1">
                          {recommendedModules.slice(0, 8).map((mod, i) => (
                            <div key={i} className="flex items-center justify-between py-1 border-b border-[rgba(0,255,65,0.08)] last:border-0">
                              <div className="flex-1 min-w-0">
                                <div className="text-[10px] text-[#FF003C] truncate font-mono">{mod.name}</div>
                                <div className="text-[10px] text-[#2F4F38]">{mod.reasons?.join(", ")}</div>
                              </div>
                              <span className="text-[10px] px-1 border border-[#FFB000]/30 text-[#FFB000] ml-2">{mod.relevance_score}</span>
                            </div>
                          ))}
                        </div>
                      </div>
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
