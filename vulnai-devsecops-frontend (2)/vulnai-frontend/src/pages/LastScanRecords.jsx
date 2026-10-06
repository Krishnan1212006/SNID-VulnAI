import { useState, useEffect, useRef } from "react";
import { Link, useSearchParams } from "react-router-dom";
import {
  History,
  ScanLine,
  ShieldCheck,
  ShieldAlert,
  Clock,
  Calendar,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Timer,
  Cpu,
  Terminal,
  FileText,
  FileJson,
  FileSpreadsheet,
  Download,
  ExternalLink,
  Copy,
  Check,
  ArrowRight,
  GitCompare,
  Layers,
  Sparkles,
  RefreshCw,
  Search,
  Filter,
  Server
} from "lucide-react";
import api from "../lib/api";

const ALL_TOOLS = [
  { key: "nmap", label: "Nmap", desc: "Network & Port Discovery" },
  { key: "nikto", label: "Nikto", desc: "Web Server Vulnerability Scanner" },
  { key: "wapiti", label: "Wapiti", desc: "Web App Vulnerability Auditor" },
  { key: "sqlmap", label: "SQLMap", desc: "Automated SQL Injection Engine" },
  { key: "gobuster", label: "Gobuster", desc: "URI/Directory Brute-Forcer" },
  { key: "wappalyzer", label: "Wappalyzer", desc: "Technology Stack Fingerprinter" },
];

function formatDateTime(dateVal) {
  if (!dateVal) return "N/A";
  try {
    const d = new Date(dateVal);
    if (isNaN(d.getTime())) return String(dateVal);
    return d.toLocaleString(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: true,
    });
  } catch {
    return String(dateVal);
  }
}

function formatDuration(seconds) {
  if (seconds == null || isNaN(seconds) || seconds <= 0) return "0s";
  const s = Math.round(Number(seconds));
  if (s < 60) return `${s}s`;
  const mins = Math.floor(s / 60);
  const remSec = s % 60;
  if (mins < 60) {
    return `${mins}m ${remSec > 0 ? `${remSec}s` : ""}`.trim();
  }
  const hrs = Math.floor(mins / 60);
  const remMins = mins % 60;
  return `${hrs}h ${remMins}m ${remSec > 0 ? `${remSec}s` : ""}`.trim();
}

export default function LastScanRecords() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [scans, setScans] = useState([]);
  const [selectedScan, setSelectedScan] = useState(null);
  const [scanResults, setScanResults] = useState(null);
  const [toolsData, setToolsData] = useState([]);
  const [loadingList, setLoadingList] = useState(true);
  const [loadingDetails, setLoadingDetails] = useState(false);
  const [activeTab, setActiveTab] = useState("all");
  const [searchTerm, setSearchTerm] = useState("");
  const [copied, setCopied] = useState(false);
  const [downloadingKey, setDownloadingKey] = useState(null);
  const [exportNotice, setExportNotice] = useState(null);
  const canvasRef = useRef(null);

  // Background Interactive Canvas Particle Network
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");

    let animationFrameId;
    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    const particles = [];
    const particleCount = Math.floor((width * height) / 16000);

    class Particle {
      constructor() {
        this.x = Math.random() * width;
        this.y = Math.random() * height;
        this.vx = (Math.random() - 0.5) * 0.4;
        this.vy = (Math.random() - 0.5) * 0.4;
        this.radius = Math.random() * 1.5 + 1;
      }

      update() {
        this.x += this.vx;
        this.y += this.vy;
        if (this.x < 0 || this.x > width) this.vx *= -1;
        if (this.y < 0 || this.y > height) this.vy *= -1;
      }

      draw() {
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
        ctx.fillStyle = "rgba(0, 240, 255, 0.5)";
        ctx.fill();
      }
    }

    for (let i = 0; i < particleCount; i++) {
      particles.push(new Particle());
    }

    const animate = () => {
      ctx.clearRect(0, 0, width, height);
      for (let i = 0; i < particles.length; i++) {
        particles[i].update();
        particles[i].draw();
        for (let j = i + 1; j < particles.length; j++) {
          const dx = particles[i].x - particles[j].x;
          const dy = particles[i].y - particles[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 100) {
            ctx.beginPath();
            ctx.strokeStyle = `rgba(0, 240, 255, ${0.2 - dist / 100})`;
            ctx.lineWidth = 0.5;
            ctx.moveTo(particles[i].x, particles[i].y);
            ctx.lineTo(particles[j].x, particles[j].y);
            ctx.stroke();
          }
        }
      }
      animationFrameId = requestAnimationFrame(animate);
    };

    animate();

    const handleResize = () => {
      if (!canvas) return;
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };

    window.addEventListener("resize", handleResize);
    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener("resize", handleResize);
    };
  }, []);

  // Fetch scans list
  const fetchScans = async () => {
    try {
      setLoadingList(true);
      const res = await api.get("/scans/");
      const list = res.data || [];
      setScans(list);

      const requestedId = searchParams.get("id");
      let initial = null;
      if (requestedId) {
        initial = list.find((s) => s.id === requestedId);
      }
      if (!initial && list.length > 0) {
        initial = list[0];
      }
      setSelectedScan(initial);
    } catch (err) {
      console.error("Failed to fetch scan list:", err);
    } finally {
      setLoadingList(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, []);

  // Fetch deep details for selected scan
  useEffect(() => {
    if (!selectedScan?.id) return;

    async function loadScanDetails() {
      setLoadingDetails(true);
      try {
        const [resResults, resTools] = await Promise.allSettled([
          api.get(`/scans/${selectedScan.id}/results`),
          api.get(`/scans/${selectedScan.id}/tools`),
        ]);

        if (resResults.status === "fulfilled") {
          setScanResults(resResults.value.data);
        } else {
          setScanResults(null);
        }

        if (resTools.status === "fulfilled") {
          setToolsData(resTools.value.data || []);
        } else {
          setToolsData([]);
        }
      } catch (err) {
        console.error("Error loading scan details:", err);
      } finally {
        setLoadingDetails(false);
      }
    }

    loadScanDetails();
  }, [selectedScan?.id]);

  const handleSelectScan = (scan) => {
    setSelectedScan(scan);
    setSearchParams({ id: scan.id });
    setActiveTab("all");
    setSearchTerm("");
  };

  const handleCopyTarget = () => {
    const target = selectedScan?.target_urls?.[0] || selectedScan?.target_url || selectedScan?.asset_id || "";
    if (target) {
      navigator.clipboard.writeText(target);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleDownload = async (format) => {
    if (!selectedScan?.id) return;
    const key = `${selectedScan.id}-${format}`;
    setDownloadingKey(key);
    try {
      const res = await api.getBlob(`/reports/${selectedScan.id}/${format}`);
      if (!res.data) throw new Error("No data returned by server");
      
      const filename = `report_${selectedScan.id}.${format}`;
      const blobUrl = URL.createObjectURL(res.data);
      const link = document.createElement("a");
      link.href = blobUrl;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(blobUrl);

      const genTime = new Date().toLocaleTimeString();
      setExportNotice(`${format.toUpperCase()} report generated at ${genTime}`);
      setTimeout(() => setExportNotice(null), 5000);
    } catch (err) {
      console.error(`Download failed:`, err);
      alert(`Error generating ${format.toUpperCase()}: ${err.message || "Failed to download."}`);
    } finally {
      setDownloadingKey(null);
    }
  };

  // Observations aggregations
  const confirmed = scanResults?.confirmed || [];
  const potential = scanResults?.potential || [];
  const informational = scanResults?.informational || [];
  const incomplete = scanResults?.incomplete || [];
  const unverified = scanResults?.unverified || [];

  const allObservations = [
    ...confirmed.map((o) => ({ ...o, categoryType: "confirmed" })),
    ...potential.map((o) => ({ ...o, categoryType: "potential" })),
    ...informational.map((o) => ({ ...o, categoryType: "informational" })),
    ...incomplete.map((o) => ({ ...o, categoryType: "incomplete" })),
    ...unverified.map((o) => ({ ...o, categoryType: "unverified" })),
  ];

  const filteredObservations = allObservations.filter((obs) => {
    if (activeTab === "confirmed" && obs.categoryType !== "confirmed") return false;
    if (activeTab === "potential" && obs.categoryType !== "potential") return false;
    if (activeTab === "informational" && obs.categoryType !== "informational") return false;
    if (activeTab === "incomplete" && obs.categoryType !== "incomplete") return false;

    if (searchTerm) {
      const q = searchTerm.toLowerCase();
      const title = (obs.title || obs.path || obs.message || "").toLowerCase();
      const scanner = (obs.scanner || "").toLowerCase();
      const desc = (obs.description || obs.raw_line || "").toLowerCase();
      return title.includes(q) || scanner.includes(q) || desc.includes(q);
    }
    return true;
  });

  const techDetection =
    scanResults?.technology_detection ||
    selectedScan?.combined_results?.technology_detection;
  const technologies = techDetection?.technologies || [];

  const previousScan = scans.length > 1 ? scans[1] : null;

  return (
    <div className="relative min-h-screen font-mono text-slate-100 p-2 sm:p-6 overflow-hidden bg-[#020408]">
      {/* Background Interactive Canvas Particle Network */}
      <canvas
        ref={canvasRef}
        className="fixed inset-0 z-0 h-screen w-screen pointer-events-none bg-[#020408] opacity-75"
      />

      {/* Cyber Grid Background Overlays */}
      <div className="fixed inset-0 z-0 pointer-events-none bg-[linear-gradient(to_right,#00f0ff08_1px,transparent_1px),linear-gradient(to_bottom,#00f0ff08_1px,transparent_1px)] bg-[size:3rem_3rem]" />
      <div className="fixed -top-24 -right-24 z-0 h-96 w-96 rounded-full bg-cyan-500/10 blur-[150px] pointer-events-none" />
      <div className="fixed top-1/2 -left-24 z-0 h-96 w-96 rounded-full bg-blue-600/10 blur-[150px] pointer-events-none" />

      {/* Main Content Area */}
      <div className="relative z-10 mx-auto max-w-7xl space-y-6">
        {/* Top Header Control Bar */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 rounded-2xl border border-cyan-500/30 bg-[#070D1B]/80 p-5 shadow-[0_0_30px_rgba(0,240,255,0.08)] backdrop-blur-2xl">
          <div className="flex items-center gap-3.5">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-cyan-950/60 border border-cyan-400/60 text-cyan-400 shadow-[0_0_15px_rgba(0,240,255,0.3)]">
              <History size={22} className="animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-lg font-extrabold tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-slate-100 to-blue-300 uppercase">
                  Last Scan Records
                </h1>
                <span className="rounded-md bg-cyan-500/10 border border-cyan-400/30 px-2 py-0.5 text-[10px] font-bold text-cyan-300 uppercase">
                  Telemetry Archive
                </span>
              </div>
              <p className="text-[11px] text-slate-400 flex items-center gap-1 mt-0.5">
                <Cpu size={12} className="text-cyan-400" /> Deep inspection of your last completed security assessments and 6-tool telemetry.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={fetchScans}
              className="flex items-center gap-1.5 rounded-lg border border-cyan-500/30 bg-[#03060D] px-3 py-1.5 text-xs font-bold text-cyan-400 hover:bg-cyan-950/40 transition-all active:scale-95 shadow-inner"
              title="Refresh Records"
            >
              <RefreshCw size={12} className={loadingList ? "animate-spin" : ""} />
              <span>REFRESH</span>
            </button>
            <Link
              to="/scan"
              className="flex items-center gap-1.5 rounded-lg border border-cyan-400 bg-cyan-500 px-3.5 py-1.5 text-xs font-bold text-slate-950 hover:bg-cyan-400 hover:shadow-[0_0_15px_rgba(0,240,255,0.4)] transition-all active:scale-95"
            >
              <ScanLine size={13} />
              <span>NEW SCAN</span>
            </Link>
          </div>
        </div>

        {/* Scan Selector Ribbon */}
        {scans.length > 0 && (
          <div className="rounded-xl border border-cyan-500/20 bg-[#070D1B]/80 p-3 shadow-lg backdrop-blur-xl">
            <div className="flex items-center justify-between mb-2 px-1">
              <div className="flex items-center gap-2 text-[11px] font-bold text-cyan-400 uppercase tracking-wider">
                <Layers size={13} /> Select Scan Record ({scans.length} Total)
              </div>
              <span className="text-[10px] text-slate-400">Click any card to inspect full telemetry</span>
            </div>
            <div className="flex gap-2.5 overflow-x-auto pb-1.5 scrollbar-thin scrollbar-thumb-cyan-500/20">
              {scans.map((s, idx) => {
                const isSelected = selectedScan?.id === s.id;
                const isLatest = idx === 0;
                return (
                  <button
                    key={s.id}
                    onClick={() => handleSelectScan(s)}
                    className={`flex-shrink-0 text-left rounded-xl border p-3 min-w-[240px] max-w-[280px] transition-all duration-200 ${
                      isSelected
                        ? "border-cyan-400 bg-cyan-950/40 shadow-[0_0_15px_rgba(0,240,255,0.2)]"
                        : "border-slate-800 bg-[#03060D]/80 hover:border-cyan-500/40 hover:bg-cyan-950/20"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-1 mb-1.5">
                      {isLatest && (
                        <span className="rounded bg-cyan-500/20 border border-cyan-400/40 px-1.5 py-0.5 text-[9px] font-extrabold text-cyan-300 uppercase">
                          LATEST SCAN
                        </span>
                      )}
                      <span className="text-[10px] font-bold uppercase text-slate-400 ml-auto">
                        {s.status}
                      </span>
                    </div>
                    <div className="font-bold text-xs text-slate-100 truncate mb-1" title={s.target_urls?.[0] || s.asset_id}>
                      {s.target_urls?.[0] || s.asset_id}
                    </div>
                    <div className="flex items-center justify-between text-[10px] text-slate-400 font-mono">
                      <span>{s.started_at ? new Date(s.started_at).toLocaleDateString() : "-"}</span>
                      {s.duration != null && (
                        <span className="text-cyan-300 font-bold">⏱️ {formatDuration(s.duration)}</span>
                      )}
                      <span className="rounded bg-slate-900 border border-slate-700 px-1.5 py-0.5 text-cyan-300 font-extrabold">
                        {s.risk_score?.score ?? s.security_score ?? 0}
                      </span>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {/* Empty State */}
        {!loadingList && scans.length === 0 && (
          <div className="rounded-2xl border border-cyan-500/20 bg-[#070D1B]/80 p-12 text-center backdrop-blur-2xl space-y-4">
            <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl bg-cyan-950/60 border border-cyan-400/40 text-cyan-400 shadow-[0_0_20px_rgba(0,240,255,0.2)]">
              <History size={32} />
            </div>
            <div>
              <h2 className="text-base font-bold uppercase tracking-wider text-slate-200">
                [NO SCAN RECORDS LOGGED]
              </h2>
              <p className="text-xs text-slate-400 max-w-md mx-auto mt-1">
                You haven&apos;t run any web security scans yet. Launch an assessment to record deep vulnerability findings and scanner telemetry.
              </p>
            </div>
            <Link
              to="/scan"
              className="inline-flex items-center gap-2 rounded-xl border border-cyan-400 bg-cyan-500 px-5 py-2.5 text-xs font-bold text-slate-950 hover:bg-cyan-400 shadow-[0_0_20px_rgba(0,240,255,0.3)] transition-all"
            >
              <ScanLine size={15} />
              <span>INITIATE FIRST SCAN</span>
            </Link>
          </div>
        )}

        {/* Selected Scan Deep Telemetry View */}
        {selectedScan && (
          <div className="space-y-6">
            {/* Hero Card: Target & Execution Overview */}
            <div className="rounded-2xl border border-cyan-500/30 bg-[#070D1B]/90 p-5 sm:p-6 shadow-[0_0_35px_rgba(0,240,255,0.06)] backdrop-blur-2xl">
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
                {/* Left: Target and Status */}
                <div className="space-y-3 flex-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`inline-flex items-center gap-1 rounded-md border px-2.5 py-0.5 text-[10px] font-extrabold uppercase tracking-wider ${
                        selectedScan.status === "completed"
                          ? "border-emerald-500/40 bg-emerald-950/40 text-emerald-400 shadow-[0_0_10px_rgba(16,185,129,0.3)]"
                          : selectedScan.status === "running"
                          ? "border-cyan-500/40 bg-cyan-950/40 text-cyan-400 animate-pulse shadow-[0_0_10px_rgba(0,240,255,0.3)]"
                          : selectedScan.status === "failed"
                          ? "border-rose-500/40 bg-rose-950/40 text-rose-400 shadow-[0_0_10px_rgba(244,63,94,0.3)]"
                          : "border-amber-500/40 bg-amber-950/40 text-amber-400"
                      }`}
                    >
                      <span className="h-1.5 w-1.5 rounded-full bg-current" />
                      {selectedScan.status}
                    </span>

                    <span className="text-[11px] text-slate-400 font-mono">
                      ID: <span className="text-cyan-300 font-bold">{selectedScan.id}</span>
                    </span>

                    {selectedScan.id === scans[0]?.id && (
                      <span className="rounded bg-cyan-500/10 border border-cyan-400/30 px-2 py-0.5 text-[10px] font-extrabold text-cyan-300 uppercase">
                        MOST RECENT RECORD
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-3">
                    <h2
                      className="text-base sm:text-xl font-extrabold text-slate-100 truncate tracking-wide"
                      title={selectedScan.target_urls?.[0] || selectedScan.asset_id}
                    >
                      {selectedScan.target_urls?.[0] || selectedScan.asset_id}
                    </h2>
                    <button
                      onClick={handleCopyTarget}
                      className="text-slate-400 hover:text-cyan-300 p-1.5 rounded-lg hover:bg-cyan-500/10 transition-all flex-shrink-0"
                      title="Copy Target URL"
                    >
                      {copied ? <Check size={16} className="text-emerald-400" /> : <Copy size={16} />}
                    </button>
                    {selectedScan.target_urls?.[0]?.startsWith("http") && (
                      <a
                        href={selectedScan.target_urls[0]}
                        target="_blank"
                        rel="noreferrer"
                        className="text-slate-400 hover:text-cyan-300 p-1.5 rounded-lg hover:bg-cyan-500/10 transition-all flex-shrink-0"
                        title="Open Target in New Tab"
                      >
                        <ExternalLink size={16} />
                      </a>
                    )}
                  </div>

                  {/* Timeline Row */}
                  <div className="flex flex-wrap items-center gap-y-2 gap-x-4 text-xs text-slate-400 font-mono">
                    <div className="flex items-center gap-1.5">
                      <Calendar size={13} className="text-cyan-400" />
                      <span>Started: <strong className="text-slate-200">{formatDateTime(selectedScan.started_at)}</strong></span>
                    </div>

                    {selectedScan.completed_at && (
                      <div className="flex items-center gap-1.5">
                        <CheckCircle2 size={13} className="text-emerald-400" />
                        <span>Completed: <strong className="text-slate-200">{formatDateTime(selectedScan.completed_at)}</strong></span>
                      </div>
                    )}

                    {selectedScan.duration != null && (
                      <div className="flex items-center gap-1.5">
                        <Timer size={13} className="text-cyan-400" />
                        <span>
                          Duration:{" "}
                          <strong className="text-cyan-300">
                            {formatDuration(selectedScan.duration)} ({Math.round(selectedScan.duration)}s)
                          </strong>
                        </span>
                      </div>
                    )}
                  </div>
                </div>

                {/* Right: Security Score & Quick Rating */}
                <div className="flex items-center gap-5 border-t lg:border-t-0 lg:border-l border-slate-800/80 pt-4 lg:pt-0 lg:pl-6">
                  <div className="text-center">
                    <span className="block text-[10px] text-slate-400 uppercase tracking-wider font-bold">
                      Security Score
                    </span>
                    <div className="mt-1 flex items-baseline justify-center gap-1">
                      <span className="text-3xl font-extrabold text-cyan-300 font-mono">
                        {selectedScan.risk_score?.score ?? selectedScan.security_score ?? 0}
                      </span>
                      <span className="text-xs text-slate-500 font-mono">/ 100</span>
                    </div>
                    <span
                      className={`mt-1 inline-block rounded border px-2 py-0.5 text-[9px] font-extrabold uppercase ${
                        selectedScan.risk_score?.rating?.toLowerCase() === "high" ||
                        selectedScan.risk_score?.rating?.toLowerCase() === "critical"
                          ? "border-rose-500/40 bg-rose-950/40 text-rose-400"
                          : selectedScan.risk_score?.rating?.toLowerCase() === "medium"
                          ? "border-yellow-500/40 bg-yellow-950/40 text-yellow-400"
                          : "border-emerald-500/40 bg-emerald-950/40 text-emerald-400"
                      }`}
                    >
                      {selectedScan.risk_score?.rating || "SAFE"} RISK
                    </span>
                  </div>

                  {/* Actions Bar */}
                  <div className="space-y-2 border-l border-slate-800/80 pl-5">
                    <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">
                      Export Report
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      <ExportBtn
                        icon={FileText}
                        label="PDF"
                        onClick={() => handleDownload("pdf")}
                        color="cyan"
                        loading={downloadingKey === `${selectedScan.id}-pdf`}
                      />
                      <ExportBtn
                        icon={FileJson}
                        label="JSON"
                        onClick={() => handleDownload("json")}
                        color="blue"
                        loading={downloadingKey === `${selectedScan.id}-json`}
                      />
                      <ExportBtn
                        icon={FileSpreadsheet}
                        label="CSV"
                        onClick={() => handleDownload("csv")}
                        color="purple"
                        loading={downloadingKey === `${selectedScan.id}-csv`}
                      />
                    </div>
                    {exportNotice && (
                      <p className="text-[10px] text-emerald-400 font-mono animate-pulse">
                        ✓ {exportNotice}
                      </p>
                    )}
                  </div>
                </div>
              </div>
            </div>

            {/* Quick Metrics Bar */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="rounded-xl border border-cyan-500/20 bg-[#070D1B]/80 p-3.5 shadow-sm">
                <span className="text-[10px] font-bold text-slate-400 uppercase">Total Findings</span>
                <p className="text-xl font-extrabold text-cyan-300 mt-1">
                  {allObservations.length || selectedScan.total_findings || 0}
                </p>
                <span className="text-[10px] text-slate-500">Across all scanner engines</span>
              </div>

              <div className="rounded-xl border border-cyan-500/20 bg-[#070D1B]/80 p-3.5 shadow-sm">
                <span className="text-[10px] font-bold text-slate-400 uppercase">Confirmed Vulnerabilities</span>
                <p className="text-xl font-extrabold text-rose-400 mt-1">
                  {confirmed.length}
                </p>
                <span className="text-[10px] text-slate-500">Actionable risk items</span>
              </div>

              <div className="rounded-xl border border-cyan-500/20 bg-[#070D1B]/80 p-3.5 shadow-sm">
                <span className="text-[10px] font-bold text-slate-400 uppercase">Detected Technologies</span>
                <p className="text-xl font-extrabold text-blue-300 mt-1">
                  {technologies.length}
                </p>
                <span className="text-[10px] text-slate-500">Fingerprinted by Wappalyzer</span>
              </div>

              <div className="rounded-xl border border-cyan-500/20 bg-[#070D1B]/80 p-3.5 shadow-sm">
                <span className="text-[10px] font-bold text-slate-400 uppercase">Scanner Matrix</span>
                <p className="text-xl font-extrabold text-emerald-400 mt-1">
                  {Object.values(selectedScan.scanner_status || {}).filter(s => s === "completed").length} / 6
                </p>
                <span className="text-[10px] text-slate-500">Engines finished successfully</span>
              </div>
            </div>

            {/* 6 Security Tools Execution Breakdown */}
            <div className="rounded-2xl border border-cyan-500/25 bg-[#070D1B]/80 p-5 shadow-[0_0_30px_rgba(0,240,255,0.05)] backdrop-blur-2xl">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <div className="h-2 w-2 rounded-full bg-cyan-400 shadow-[0_0_8px_#00f0ff]" />
                  <h3 className="text-xs sm:text-sm font-extrabold uppercase tracking-wider text-slate-200 flex items-center gap-2">
                    <Cpu size={14} className="text-cyan-400" />
                    Security Scanner Telemetry Matrix (6 Engines)
                  </h3>
                </div>
                <span className="text-[11px] text-slate-400">Independent Asynchronous Execution</span>
              </div>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
                {ALL_TOOLS.map(({ key, label, desc }) => {
                  const toolObj = toolsData.find((t) => t.tool_name === key);
                  const detail = selectedScan.scanner_details?.[key] || {};
                  const summary =
                    scanResults?.tool_summaries?.[key] ||
                    selectedScan.tool_summaries?.[key] ||
                    {};

                  const status = (
                    toolObj?.status ||
                    detail.status ||
                    selectedScan.scanner_status?.[key] ||
                    "unknown"
                  ).toLowerCase();

                  const duration =
                    toolObj?.duration ??
                    detail.duration ??
                    detail.execution_seconds ??
                    0;
                  const exitCode = toolObj?.exit_code ?? detail.exit_code;
                  const findingsCount =
                    summary.findings_count ?? toolObj?.findings_count ?? 0;
                  const summaryMsg =
                    summary.summary_message || toolObj?.summary_message;

                  let statusBadge = "text-slate-400 border-slate-700 bg-slate-900";
                  if (status === "completed") {
                    statusBadge =
                      "text-emerald-400 border-emerald-500/50 bg-emerald-950/40";
                  } else if (status === "failed") {
                    statusBadge = "text-rose-400 border-rose-500/50 bg-rose-950/40";
                  } else if (status === "running") {
                    statusBadge =
                      "text-cyan-400 border-cyan-500/50 bg-cyan-950/40 animate-pulse";
                  } else if (status === "cancelled") {
                    statusBadge =
                      "text-amber-400 border-amber-500/50 bg-amber-950/40";
                  }

                  return (
                    <div
                      key={key}
                      className="rounded-xl border border-slate-800 bg-[#03060D]/90 p-4 text-xs transition-all hover:border-cyan-500/40"
                    >
                      <div className="flex items-center justify-between">
                        <div>
                          <span className="font-extrabold uppercase tracking-wider text-slate-100">
                            {label}
                          </span>
                          <span className="block text-[10px] text-slate-500 mt-0.5">{desc}</span>
                        </div>
                        <span className={`rounded-md border px-2 py-0.5 text-[10px] font-extrabold ${statusBadge}`}>
                          {status.toUpperCase()}
                        </span>
                      </div>

                      <div className="mt-3 p-2 rounded bg-slate-950/60 border border-slate-800/80 text-[11px] text-slate-300">
                        {summaryMsg || (
                          findingsCount > 0
                            ? `${findingsCount} observation(s) recorded.`
                            : status === "completed"
                            ? "Completed cleanly. No vulnerabilities flagged."
                            : status === "failed"
                            ? `Exited with code ${exitCode ?? -1}: ${detail.error || "Execution failed"}`
                            : `Status: ${status}`
                        )}
                      </div>

                      <div className="mt-3 flex items-center justify-between text-[10px] text-slate-400 font-mono">
                        <span className="text-cyan-300 font-bold">⏱️ {formatDuration(duration)}</span>
                        {exitCode !== undefined && exitCode !== null && (
                          <span className="text-slate-400">Exit Code: {exitCode}</span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Detected Technologies Section */}
            {technologies.length > 0 && (
              <div className="rounded-2xl border border-cyan-500/25 bg-[#070D1B]/80 p-5 shadow-[0_0_30px_rgba(0,240,255,0.05)] backdrop-blur-2xl">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <Server size={14} className="text-cyan-400" />
                    <h3 className="text-xs sm:text-sm font-extrabold uppercase tracking-wider text-slate-200">
                      Detected Technology Stack ({technologies.length})
                    </h3>
                  </div>
                  <span className="text-[10px] text-slate-400">Fingerprinted by Wappalyzer</span>
                </div>

                <div className="flex flex-wrap gap-2">
                  {technologies.map((t, i) => (
                    <div
                      key={`${t.name}-${i}`}
                      className="flex items-center gap-1.5 rounded-lg border border-cyan-500/30 bg-[#03060D]/90 px-3 py-1.5 text-xs text-slate-200"
                    >
                      <span className="font-bold text-cyan-300">{t.name}</span>
                      {t.version && (
                        <span className="rounded bg-cyan-500/20 px-1 py-0.5 text-[9px] text-cyan-200 font-mono">
                          v{t.version}
                        </span>
                      )}
                      <span className="text-[10px] text-slate-400">({t.category})</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Detailed Findings & Observations Section */}
            <div className="rounded-2xl border border-cyan-500/25 bg-[#070D1B]/80 p-5 shadow-[0_0_30px_rgba(0,240,255,0.05)] backdrop-blur-2xl space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <ShieldAlert size={16} className="text-cyan-400" />
                  <h3 className="text-xs sm:text-sm font-extrabold uppercase tracking-wider text-slate-200">
                    Vulnerability Findings & Scanner Observations
                  </h3>
                </div>

                {/* Search Bar */}
                <div className="relative min-w-[220px]">
                  <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                  <input
                    type="text"
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    placeholder="Search findings, paths, CVE..."
                    className="w-full rounded-lg border border-slate-800 bg-[#03060D] pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:border-cyan-400 focus:outline-none"
                  />
                </div>
              </div>

              {/* Tabs */}
              <div className="flex gap-2 border-b border-slate-800 pb-2 overflow-x-auto text-xs">
                {[
                  { key: "all", label: `All (${allObservations.length})` },
                  { key: "confirmed", label: `Confirmed (${confirmed.length})` },
                  { key: "potential", label: `Potential (${potential.length})` },
                  { key: "informational", label: `Informational (${informational.length})` },
                  { key: "incomplete", label: `Incomplete (${incomplete.length})` },
                ].map((tab) => (
                  <button
                    key={tab.key}
                    onClick={() => setActiveTab(tab.key)}
                    className={`px-3 py-1.5 rounded-lg font-bold transition-all whitespace-nowrap ${
                      activeTab === tab.key
                        ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40"
                        : "text-slate-400 hover:text-slate-200 hover:bg-slate-900"
                    }`}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>

              {/* Observation Cards List */}
              {filteredObservations.length === 0 ? (
                <div className="p-8 text-center text-xs text-slate-500 font-mono">
                  No observations match the selected criteria for this scan.
                </div>
              ) : (
                <div className="space-y-3">
                  {filteredObservations.map((obs, idx) => {
                    const sev = (obs.severity || "info").toLowerCase();
                    return (
                      <div
                        key={obs.id || `${obs.scanner}-${idx}`}
                        className="rounded-xl border border-slate-800 bg-[#03060D]/90 p-4 space-y-2 hover:border-cyan-500/30 transition-all"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <span className="rounded bg-cyan-950/70 border border-cyan-500/30 px-2 py-0.5 text-[10px] font-extrabold text-cyan-300 uppercase">
                              {obs.scanner}
                            </span>
                            <span
                              className={`rounded border px-2 py-0.5 text-[10px] font-extrabold uppercase ${
                                sev === "critical" || sev === "high"
                                  ? "border-rose-500/40 bg-rose-950/40 text-rose-400"
                                  : sev === "medium"
                                  ? "border-yellow-500/40 bg-yellow-950/40 text-yellow-400"
                                  : "border-emerald-500/40 bg-emerald-950/40 text-emerald-400"
                              }`}
                            >
                              {sev}
                            </span>
                            <span className="text-[10px] text-slate-400 uppercase">
                              {obs.verification_status || obs.categoryType || "observed"}
                            </span>
                          </div>

                          {obs.status_code != null && (
                            <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/40 px-2 py-0.5 rounded border border-cyan-500/30">
                              HTTP {obs.status_code} ({obs.response_size || 0} bytes)
                            </span>
                          )}
                        </div>

                        <h4 className="font-bold text-xs sm:text-sm text-slate-100 break-words">
                          {obs.title || obs.path || obs.message || "Scanner Observation"}
                        </h4>

                        {(obs.description || obs.raw_line) && (
                          <p className="text-xs text-slate-400 leading-relaxed break-words bg-slate-950/40 p-2.5 rounded-lg border border-slate-800/60 font-mono text-[11px]">
                            {obs.description || obs.raw_line}
                          </p>
                        )}

                        {obs.ai_analysis?.recommendation && (
                          <div className="rounded-lg border border-cyan-500/20 bg-cyan-950/20 p-2.5 text-[11px] text-cyan-200">
                            <strong>AI Recommendation:</strong> {obs.ai_analysis.recommendation}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Bottom Comparison Link */}
            {previousScan && (
              <div className="rounded-2xl border border-cyan-500/20 bg-[#070D1B]/80 p-5 flex flex-col sm:flex-row items-center justify-between gap-4 backdrop-blur-xl">
                <div>
                  <h4 className="font-bold text-xs uppercase tracking-wider text-slate-200 flex items-center gap-2">
                    <GitCompare size={14} className="text-cyan-400" />
                    Compare with Previous Scan
                  </h4>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    Compare this scan with prior execution from {new Date(previousScan.started_at).toLocaleDateString()} to identify newly introduced or resolved vulnerabilities.
                  </p>
                </div>
                <Link
                  to={`/scans/${selectedScan.id}/compare/${previousScan.id}`}
                  className="flex items-center gap-1.5 rounded-xl border border-cyan-500/30 bg-[#03060D] px-4 py-2 text-xs font-bold text-cyan-300 hover:bg-cyan-950/40 hover:border-cyan-400 transition-all active:scale-95 whitespace-nowrap"
                >
                  <span>RUN COMPARISON</span>
                  <ArrowRight size={13} />
                </Link>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function ExportBtn({ icon: Icon, label, onClick, color, loading }) {
  const colorStyles = {
    cyan: "border-cyan-500/30 bg-cyan-950/30 text-cyan-300 hover:bg-cyan-500 hover:text-slate-950",
    blue: "border-blue-500/30 bg-blue-950/30 text-blue-300 hover:bg-blue-500 hover:text-slate-950",
    purple: "border-purple-500/30 bg-purple-950/30 text-purple-300 hover:bg-purple-500 hover:text-slate-950",
  };

  return (
    <button
      onClick={onClick}
      disabled={loading}
      className={`group flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-[11px] font-bold uppercase tracking-wider transition-all duration-200 active:scale-95 disabled:opacity-50 ${
        colorStyles[color] || colorStyles.cyan
      }`}
    >
      {loading ? (
        <Sparkles size={11} className="animate-spin text-cyan-300" />
      ) : (
        <Icon size={11} className="transition-transform group-hover:scale-110" />
      )}
      <span>{loading ? "..." : label}</span>
      <Download size={10} className="opacity-70" />
    </button>
  );
}
