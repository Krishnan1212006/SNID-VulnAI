import { useState, useEffect } from "react";
import {
  Globe,
  Shield,
  ShieldCheck,
  ShieldAlert,
  Server,
  Lock,
  Layers,
  Terminal,
  Play,
  StopCircle,
  RefreshCw,
  CheckCircle,
  AlertTriangle,
  XCircle,
  Clock,
  ExternalLink,
  ChevronRight,
  Database,
  Search,
  FileText,
  Download,
  Info,
} from "lucide-react";
import StatCard from "../components/StatCard";
import api from "../lib/api";

const ARCH_BADGES = {
  "Static indicators": "border-cyan-500/40 bg-cyan-950/40 text-cyan-300 shadow-[0_0_12px_rgba(0,240,255,0.2)]",
  "Dynamic indicators": "border-emerald-500/40 bg-emerald-950/40 text-emerald-300 shadow-[0_0_12px_rgba(16,185,129,0.2)]",
  "Mixed": "border-yellow-500/40 bg-yellow-950/40 text-yellow-300 shadow-[0_0_12px_rgba(234,179,8,0.2)]",
  "Insufficient evidence": "border-slate-700 bg-slate-900/60 text-slate-400",
};

export default function DomainAssessment() {
  const [targetInput, setTargetInput] = useState("");
  const [isAuthorized, setIsAuthorized] = useState(false);
  const [activeSqli, setActiveSqli] = useState(false);
  const [allowInternal, setAllowInternal] = useState(false);

  // Job & Results state
  const [jobState, setJobState] = useState("IDLE"); // IDLE, RUNNING, COMPLETED, CANCELLED, FAILED
  const [currentJobId, setCurrentJobId] = useState(null);
  const [currentStage, setCurrentStage] = useState("");
  const [progress, setProgress] = useState(0);
  const [report, setReport] = useState(null);
  const [errorMsg, setErrorMsg] = useState("");
  const [activeTab, setActiveTab] = useState("overview");

  // History state
  const [history, setHistory] = useState([]);
  const [loadingHistory, setLoadingHistory] = useState(false);

  // Load past assessments
  const loadHistory = async () => {
    setLoadingHistory(true);
    try {
      const res = await api.get("/domain/history?limit=10");
      setHistory(res.data || []);
    } catch (err) {
      console.error("Failed to load domain history:", err);
    } finally {
      setLoadingHistory(false);
    }
  };

  useEffect(() => {
    loadHistory();
  }, []);

  const handleStartAssessment = async (e) => {
    e.preventDefault();
    if (!targetInput.trim()) return;
    if (!isAuthorized) {
      alert("You must confirm explicit authorization before launching a domain assessment.");
      return;
    }

    setJobState("RUNNING");
    setProgress(15);
    setCurrentStage("Initiating server-side validation & DNS queries...");
    setReport(null);
    setErrorMsg("");

    try {
      const res = await api.post("/domain/assess", {
        target: targetInput.trim(),
        authorized: isAuthorized,
        active_sqli: activeSqli,
        allow_internal: allowInternal,
      });

      setCurrentJobId(res.data.job_id);
      setReport(res.data);
      setProgress(100);
      setJobState(res.data.status || "COMPLETED");
      loadHistory();
    } catch (err) {
      setJobState("FAILED");
      setErrorMsg(err.response?.data?.detail || err.message || "Domain assessment failed.");
    }
  };

  const handleCancel = async () => {
    if (!currentJobId) return;
    try {
      await api.post(`/domain/assess/${currentJobId}/cancel`);
      setJobState("CANCELLED");
    } catch (err) {
      console.error("Failed to cancel assessment:", err);
    }
  };

  const handleSelectHistoryItem = async (jobId) => {
    try {
      const res = await api.get(`/domain/assess/${jobId}`);
      setReport(res.data);
      setTargetInput(res.data.target_input || res.data.domain);
      setJobState(res.data.status || "COMPLETED");
      setActiveTab("overview");
    } catch (err) {
      console.error("Failed to load historical assessment:", err);
    }
  };

  const exportJson = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `domain_assessment_${report.domain || "report"}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="relative min-h-screen text-slate-100 font-sans pb-16 selection:bg-cyan-500 selection:text-black space-y-6">
      {/* Top Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between border-b border-cyan-500/20 pb-5">
        <div className="flex items-center gap-3">
          <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-cyan-400/40 bg-cyan-950/40 text-cyan-400 shadow-[0_0_15px_rgba(0,240,255,0.2)]">
            <Globe size={22} className="animate-pulse" />
          </div>
          <div>
            <h1 className="text-xl font-extrabold tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-slate-100 to-cyan-200 uppercase font-mono">
              SNID // Domain Security Assessment
            </h1>
            <p className="text-[11px] text-slate-400 flex items-center gap-1.5 mt-0.5">
              <Shield size={12} className="text-cyan-400" /> Authorized DNS, HTTP/TLS, Technology Fingerprinting, Nmap & SQLi Security Analysis.
            </p>
          </div>
        </div>

        {report && (
          <div className="flex items-center gap-2">
            <button
              onClick={exportJson}
              className="flex items-center gap-1.5 rounded-xl border border-cyan-500/30 bg-[#070D1B] px-3 py-1.5 text-xs font-bold text-cyan-300 hover:border-cyan-400 hover:bg-cyan-950/40 transition-all"
            >
              <Download size={13} /> Export JSON
            </button>
          </div>
        )}
      </div>

      {/* Target Launch & Scope Form */}
      <div className="rounded-2xl border border-cyan-500/25 bg-[#070D1B]/90 p-5 shadow-[0_0_20px_rgba(0,240,255,0.06)] backdrop-blur-xl space-y-4">
        <form onSubmit={handleStartAssessment} className="space-y-4">
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Globe size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-cyan-400/70" />
              <input
                type="text"
                value={targetInput}
                onChange={(e) => setTargetInput(e.target.value)}
                placeholder="Enter domain or URL (e.g. scanme.nmap.org, https://example.com)..."
                disabled={jobState === "RUNNING"}
                className="w-full rounded-xl border border-cyan-500/30 bg-[#03060D] py-2.5 pl-10 pr-4 text-xs font-mono text-slate-100 placeholder:text-slate-500 focus:border-cyan-400 focus:outline-none focus:ring-1 focus:ring-cyan-400 disabled:opacity-50"
              />
            </div>

            <button
              type="submit"
              disabled={jobState === "RUNNING" || !targetInput.trim() || !isAuthorized}
              className="flex items-center justify-center gap-2 rounded-xl border border-cyan-400 bg-gradient-to-r from-cyan-600 to-cyan-500 px-6 py-2.5 text-xs font-bold text-black uppercase tracking-wider hover:shadow-[0_0_20px_rgba(0,240,255,0.4)] disabled:opacity-40 disabled:pointer-events-none transition-all font-mono"
            >
              {jobState === "RUNNING" ? (
                <>
                  <RefreshCw size={14} className="animate-spin text-black" /> Assessing...
                </>
              ) : (
                <>
                  <Play size={14} className="fill-black" /> Run Assessment
                </>
              )}
            </button>
          </div>

          {/* Authorization & Scope Controls */}
          <div className="flex flex-wrap items-center justify-between gap-4 border-t border-cyan-500/15 pt-3.5 text-xs">
            <div className="flex flex-wrap items-center gap-5">
              <label className="flex items-center gap-2 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={isAuthorized}
                  onChange={(e) => setIsAuthorized(e.target.checked)}
                  className="rounded border-cyan-500/40 bg-[#03060D] text-cyan-500 focus:ring-0"
                />
                <span className="text-cyan-300 font-semibold flex items-center gap-1">
                  <ShieldCheck size={14} className="text-emerald-400" />
                  I confirm authorization to assess this target
                </span>
              </label>

              <label className="flex items-center gap-2 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={activeSqli}
                  onChange={(e) => setActiveSqli(e.target.checked)}
                  className="rounded border-cyan-500/40 bg-[#03060D] text-cyan-500 focus:ring-0"
                />
                <span className="text-slate-300">
                  Enable Active SQLMap Probing <span className="text-[10px] text-amber-400">(Heuristic level 1)</span>
                </span>
              </label>

              <label className="flex items-center gap-2 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={allowInternal}
                  onChange={(e) => setAllowInternal(e.target.checked)}
                  className="rounded border-cyan-500/40 bg-[#03060D] text-cyan-500 focus:ring-0"
                />
                <span className="text-slate-400 text-[11px]">
                  Allow Internal IP / SSRF Bypass (Lab only)
                </span>
              </label>
            </div>

            {jobState === "RUNNING" && (
              <button
                type="button"
                onClick={handleCancel}
                className="flex items-center gap-1.5 rounded-lg border border-rose-500/40 bg-rose-950/30 px-3 py-1 text-xs font-bold text-rose-300 hover:bg-rose-900/40 transition-all"
              >
                <StopCircle size={13} /> Cancel
              </button>
            )}
          </div>
        </form>

        {/* Live Execution Status Banner */}
        {jobState === "RUNNING" && (
          <div className="rounded-xl border border-cyan-500/30 bg-[#03060D] p-3 space-y-2">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="flex items-center gap-2 text-cyan-400">
                <RefreshCw size={12} className="animate-spin" /> {currentStage}
              </span>
              <span className="text-cyan-300 font-bold">{progress}%</span>
            </div>
            <div className="h-1.5 w-full rounded-full bg-slate-900 overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-cyan-500 to-emerald-400 transition-all duration-300"
                style={{ width: `${progress}%` }}
              />
            </div>
          </div>
        )}

        {/* Error Notification */}
        {errorMsg && (
          <div className="rounded-xl border border-rose-500/40 bg-rose-950/30 p-3 text-xs text-rose-300 flex items-start gap-2.5 font-mono">
            <AlertTriangle size={16} className="text-rose-400 shrink-0 mt-0.5" />
            <div>
              <p className="font-bold">Assessment Execution Halted:</p>
              <p className="text-[11px] text-rose-200/80">{errorMsg}</p>
            </div>
          </div>
        )}
      </div>

      {/* Main Results View */}
      {report && (
        <div className="space-y-5">
          {/* Top Scorecard Metrics */}
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-4 font-mono">
            <div className="rounded-2xl border border-cyan-500/25 bg-[#070D1B]/80 p-4 shadow-[0_0_20px_rgba(0,240,255,0.05)] backdrop-blur-xl">
              <StatCard
                label="Target Domain"
                value={report.domain}
                suffix={report.http?.status_code ? `(${report.http.status_code})` : ""}
                icon={Globe}
                accent="blue"
              />
            </div>

            <div className="rounded-2xl border border-cyan-500/25 bg-[#070D1B]/80 p-4 shadow-[0_0_20px_rgba(0,240,255,0.05)] backdrop-blur-xl">
              <p className="text-[10px] font-bold uppercase text-slate-400">Architecture Profile</p>
              <div className="mt-2 flex items-center gap-2">
                <span className={`rounded-lg px-2.5 py-1 text-xs font-bold border ${ARCH_BADGES[report.technology?.architecture_label] || ARCH_BADGES["Insufficient evidence"]}`}>
                  {report.technology?.architecture_label || "Insufficient evidence"}
                </span>
              </div>
              <p className="text-[10px] text-slate-500 mt-2 truncate">
                {report.technology?.architecture_evidence?.[0] || "Heuristic analysis complete"}
              </p>
            </div>

            <div className="rounded-2xl border border-emerald-500/25 bg-[#070D1B]/80 p-4 shadow-[0_0_20px_rgba(16,185,129,0.05)] backdrop-blur-xl">
              <StatCard
                label="TLS Certificate"
                value={report.tls?.is_valid ? "Valid CA" : (report.tls?.available ? "Untrusted" : "No TLS")}
                suffix={report.tls?.days_remaining != null ? `(${report.tls.days_remaining}d left)` : ""}
                icon={Lock}
                accent={report.tls?.is_valid ? "low" : "high"}
              />
            </div>

            <div className="rounded-2xl border border-cyan-500/25 bg-[#070D1B]/80 p-4 shadow-[0_0_20px_rgba(0,240,255,0.05)] backdrop-blur-xl">
              <StatCard
                label="Open Ports (Nmap)"
                value={report.nmap?.open_ports?.length ?? 0}
                suffix="services"
                icon={Server}
                accent="blue"
              />
            </div>
          </div>

          {/* Navigation Tabs for Detailed Results */}
          <div className="flex border-b border-cyan-500/20 text-xs font-mono">
            {[
              { id: "overview", label: "Overview & Scorecard", icon: Shield },
              { id: "dns", label: "DNS & Routing", icon: Globe },
              { id: "http", label: "HTTP & TLS Headers", icon: Lock },
              { id: "tech", label: "Technology Stack", icon: Layers },
              { id: "nmap", label: "Nmap Ports", icon: Server },
              { id: "sqli", label: "SQLi & App Security", icon: Database },
            ].map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                onClick={() => setActiveTab(id)}
                className={`flex items-center gap-1.5 px-4 py-3 font-bold border-b-2 transition-all ${
                  activeTab === id
                    ? "border-cyan-400 text-cyan-300 bg-cyan-950/20 shadow-[0_4px_12px_rgba(0,240,255,0.1)]"
                    : "border-transparent text-slate-400 hover:text-slate-200"
                }`}
              >
                <Icon size={14} className={activeTab === id ? "text-cyan-400" : "text-slate-500"} />
                {label}
              </button>
            ))}
          </div>

          {/* Tab 1: Overview */}
          {activeTab === "overview" && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="rounded-2xl border border-cyan-500/20 bg-[#070D1B]/80 p-5 space-y-3 font-mono text-xs">
                <h3 className="font-bold text-slate-200 text-sm flex items-center gap-2">
                  <Globe size={16} className="text-cyan-400" /> Target Assessment Summary
                </h3>
                <div className="space-y-1.5 text-slate-300">
                  <div className="flex justify-between border-b border-slate-800/80 py-1">
                    <span className="text-slate-500">Domain:</span>
                    <span className="text-cyan-300">{report.domain}</span>
                  </div>
                  <div className="flex justify-between border-b border-slate-800/80 py-1">
                    <span className="text-slate-500">Target URL:</span>
                    <span className="text-cyan-300 truncate max-w-xs">{report.target_url}</span>
                  </div>
                  <div className="flex justify-between border-b border-slate-800/80 py-1">
                    <span className="text-slate-500">Primary IP:</span>
                    <span className="text-emerald-300">{report.resolved_ips?.[0] || "N/A"}</span>
                  </div>
                  <div className="flex justify-between border-b border-slate-800/80 py-1">
                    <span className="text-slate-500">HTTP Response Code:</span>
                    <span className="text-slate-200">{report.http?.status_code || "N/A"} ({report.http?.reason_phrase || ""})</span>
                  </div>
                  <div className="flex justify-between border-b border-slate-800/80 py-1">
                    <span className="text-slate-500">Latency:</span>
                    <span className="text-slate-200">{report.http?.response_time_ms} ms</span>
                  </div>
                  <div className="flex justify-between py-1">
                    <span className="text-slate-500">Assessment Duration:</span>
                    <span className="text-cyan-400">{report.duration_seconds}s</span>
                  </div>
                </div>
              </div>

              <div className="rounded-2xl border border-cyan-500/20 bg-[#070D1B]/80 p-5 space-y-3 font-mono text-xs">
                <h3 className="font-bold text-slate-200 text-sm flex items-center gap-2">
                  <Layers size={16} className="text-cyan-400" /> Architecture Rationale
                </h3>
                <p className="text-slate-300 text-[11px] leading-relaxed">
                  The target was classified as <strong className="text-cyan-300">{report.technology?.architecture_label}</strong> based on evidence-backed criteria:
                </p>
                <ul className="space-y-1.5 list-disc list-inside text-slate-400 text-[11px]">
                  {report.technology?.architecture_evidence?.map((r, i) => (
                    <li key={i} className="text-slate-300">{r}</li>
                  )) || <li>Insufficient response artifacts to establish architecture.</li>}
                </ul>
                <div className="border-t border-slate-800/80 pt-2 text-[10px] text-slate-500">
                  <Info size={11} className="inline mr-1" />
                  Classification reflects observed baseline behavior; dynamic paths may still exist.
                </div>
              </div>
            </div>
          )}

          {/* Tab 2: DNS */}
          {activeTab === "dns" && (
            <div className="rounded-2xl border border-cyan-500/20 bg-[#070D1B]/80 p-5 font-mono text-xs space-y-4">
              <h3 className="font-bold text-slate-200 text-sm flex items-center gap-2">
                <Globe size={16} className="text-cyan-400" /> DNS Records & Resolution
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="rounded-xl border border-slate-800 bg-[#03060D] p-3.5 space-y-2">
                  <span className="text-slate-400 text-[11px] font-bold">IPv4 Address (A Records):</span>
                  {report.dns?.a_records?.length ? (
                    report.dns.a_records.map((ip, i) => (
                      <div key={i} className="text-emerald-400 font-bold">{ip}</div>
                    ))
                  ) : (
                    <div className="text-slate-500">No A records found</div>
                  )}
                </div>

                <div className="rounded-xl border border-slate-800 bg-[#03060D] p-3.5 space-y-2">
                  <span className="text-slate-400 text-[11px] font-bold">IPv6 Address (AAAA Records):</span>
                  {report.dns?.aaaa_records?.length ? (
                    report.dns.aaaa_records.map((ip, i) => (
                      <div key={i} className="text-cyan-400 font-bold">{ip}</div>
                    ))
                  ) : (
                    <div className="text-slate-500">No AAAA records found</div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Tab 3: HTTP & TLS */}
          {activeTab === "http" && (
            <div className="space-y-4 font-mono text-xs">
              {/* Security Headers */}
              <div className="rounded-2xl border border-cyan-500/20 bg-[#070D1B]/80 p-5 space-y-3">
                <h3 className="font-bold text-slate-200 text-sm flex items-center gap-2">
                  <Lock size={16} className="text-cyan-400" /> HTTP Security Headers Check
                </h3>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                  {Object.entries(report.http?.security_headers || {}).map(([hdr, val]) => (
                    <div key={hdr} className="flex items-center justify-between rounded-lg border border-slate-800 bg-[#03060D] p-2.5">
                      <span className="text-slate-300 font-semibold">{hdr}:</span>
                      {val ? (
                        <span className="text-emerald-400 text-[10px] flex items-center gap-1 truncate max-w-xs" title={val}>
                          <CheckCircle size={11} /> {val}
                        </span>
                      ) : (
                        <span className="text-rose-400 text-[10px] flex items-center gap-1">
                          <XCircle size={11} /> Missing
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* TLS Details */}
              <div className="rounded-2xl border border-cyan-500/20 bg-[#070D1B]/80 p-5 space-y-3">
                <h3 className="font-bold text-slate-200 text-sm flex items-center gap-2">
                  <Lock size={16} className="text-cyan-400" /> TLS / SSL Certificate Details
                </h3>
                {report.tls?.available ? (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-slate-300">
                    <div><span className="text-slate-500">Subject CN:</span> {report.tls.subject?.commonName || "N/A"}</div>
                    <div><span className="text-slate-500">Issuer CN:</span> {report.tls.issuer?.commonName || "N/A"}</div>
                    <div><span className="text-slate-500">Protocol Version:</span> {report.tls.version || "N/A"}</div>
                    <div><span className="text-slate-500">Cipher Suite:</span> {report.tls.cipher || "N/A"}</div>
                    <div><span className="text-slate-500">Valid Until:</span> {report.tls.valid_until || "N/A"}</div>
                    <div><span className="text-slate-500">Days Remaining:</span> <strong className="text-emerald-400">{report.tls.days_remaining} days</strong></div>
                  </div>
                ) : (
                  <div className="text-slate-400 text-[11px]">No TLS certificate data available for port 443.</div>
                )}
              </div>
            </div>
          )}

          {/* Tab 4: Technology */}
          {activeTab === "tech" && (
            <div className="rounded-2xl border border-cyan-500/20 bg-[#070D1B]/80 p-5 font-mono text-xs space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="font-bold text-slate-200 text-sm flex items-center gap-2">
                  <Layers size={16} className="text-cyan-400" /> Detected Technology Stack
                </h3>
                <span className="text-[10px] text-slate-500">{report.technology?.whatweb_status}</span>
              </div>

              {report.technology?.technologies?.length ? (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  {report.technology.technologies.map((t, i) => (
                    <div key={i} className="rounded-xl border border-cyan-500/30 bg-[#03060D] p-3 space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-cyan-300 font-bold">{t.name}</span>
                        <span className="rounded bg-cyan-950/60 px-1.5 py-0.5 text-[9px] font-bold text-cyan-400 border border-cyan-500/30">
                          {t.category}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400 truncate">{t.evidence}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-slate-500">No high-confidence software fingerprints identified.</div>
              )}
            </div>
          )}

          {/* Tab 5: Nmap Ports */}
          {activeTab === "nmap" && (
            <div className="rounded-2xl border border-cyan-500/20 bg-[#070D1B]/80 p-5 font-mono text-xs space-y-4">
              <h3 className="font-bold text-slate-200 text-sm flex items-center gap-2">
                <Server size={16} className="text-cyan-400" /> Nmap Service & Port Discovery
              </h3>

              {report.nmap?.open_ports?.length ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-left">
                    <thead>
                      <tr className="border-b border-cyan-500/20 text-[10px] text-slate-400 uppercase">
                        <th className="py-2">Port</th>
                        <th className="py-2">Protocol</th>
                        <th className="py-2">State</th>
                        <th className="py-2">Service</th>
                        <th className="py-2">Detected Version</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {report.nmap.open_ports.map((p, i) => (
                        <tr key={i} className="hover:bg-cyan-950/20">
                          <td className="py-2 text-cyan-300 font-bold">{p.port}</td>
                          <td className="py-2 text-slate-400">{p.protocol}</td>
                          <td className="py-2">
                            <span className="rounded px-2 py-0.5 text-[10px] font-bold bg-emerald-950/50 text-emerald-400 border border-emerald-500/40">
                              {p.state}
                            </span>
                          </td>
                          <td className="py-2 text-slate-200">{p.service}</td>
                          <td className="py-2 text-slate-400">{p.version}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="text-slate-500">No open ports observed within the evaluated port scope ({report.nmap?.scanned_ports}).</div>
              )}

              {report.nmap?.raw_output && (
                <details className="mt-3">
                  <summary className="cursor-pointer text-[11px] text-cyan-400 hover:text-cyan-300 font-bold">
                    View Raw Nmap Command Output
                  </summary>
                  <pre className="mt-2 p-3 rounded-xl bg-black border border-slate-800 text-[10px] text-slate-400 overflow-x-auto">
                    {report.nmap.raw_output}
                  </pre>
                </details>
              )}
            </div>
          )}

          {/* Tab 6: SQLi & App Security */}
          {activeTab === "sqli" && (
            <div className="rounded-2xl border border-cyan-500/20 bg-[#070D1B]/80 p-5 font-mono text-xs space-y-4">
              <h3 className="font-bold text-slate-200 text-sm flex items-center gap-2">
                <Database size={16} className="text-cyan-400" /> SQL-Injection Assessment
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-slate-300">
                <div className="rounded-xl border border-slate-800 bg-[#03060D] p-3 space-y-1">
                  <span className="text-[10px] text-slate-500 uppercase font-bold">Passive Inspection:</span>
                  <div className="text-cyan-300 font-bold">{report.sql_injection?.passive_status}</div>
                </div>

                <div className="rounded-xl border border-slate-800 bg-[#03060D] p-3 space-y-1">
                  <span className="text-[10px] text-slate-500 uppercase font-bold">Active SQLMap Execution:</span>
                  <div className="text-emerald-300 font-bold">{report.sql_injection?.active_status}</div>
                </div>
              </div>

              {report.sql_injection?.evidence?.length > 0 && (
                <div className="space-y-2">
                  <span className="text-slate-400 font-bold">Evidence Snippet:</span>
                  <pre className="p-3 rounded-xl bg-black border border-slate-800 text-[10px] text-slate-400 overflow-x-auto">
                    {report.sql_injection.evidence.join("\n")}
                  </pre>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Historical Assessments Sidebar / Section */}
      {history.length > 0 && (
        <div className="rounded-2xl border border-cyan-500/20 bg-[#070D1B]/60 p-5 space-y-3 font-mono text-xs">
          <h3 className="font-bold text-slate-300 text-sm flex items-center gap-2">
            <Clock size={15} className="text-cyan-400" /> Recent Domain Assessments
          </h3>
          <div className="divide-y divide-slate-800/60">
            {history.map((item) => (
              <div
                key={item.id}
                onClick={() => handleSelectHistoryItem(item.job_id)}
                className="flex items-center justify-between py-2.5 hover:bg-cyan-950/20 px-2 rounded-lg cursor-pointer transition-colors"
              >
                <div className="flex items-center gap-2.5">
                  <Globe size={14} className="text-cyan-400" />
                  <span className="font-bold text-slate-200">{item.domain}</span>
                  <span className={`rounded px-1.5 py-0.5 text-[9px] border ${ARCH_BADGES[item.architecture_label] || ARCH_BADGES["Insufficient evidence"]}`}>
                    {item.architecture_label}
                  </span>
                </div>
                <div className="flex items-center gap-4 text-slate-500 text-[10px]">
                  <span>{item.open_ports_count} ports</span>
                  <span>{item.duration_seconds}s</span>
                  <ChevronRight size={14} className="text-cyan-400" />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
