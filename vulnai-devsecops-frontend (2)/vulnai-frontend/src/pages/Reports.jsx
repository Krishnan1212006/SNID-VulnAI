import { useState, useEffect, useRef } from "react";
import { 
  FileJson, 
  FileSpreadsheet, 
  FileText, 
  Download, 
  ShieldCheck, 
  Terminal, 
  Cpu, 
  Sparkles, 
  Database,
  Clock,
  Calendar,
  CheckCircle2,
  Timer,
  Eye,
  X,
  FileCode
} from "lucide-react";
import api from "../lib/api";

function formatDateTime(dateVal) {
  if (!dateVal) return "-";
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

function formatTimeOnly(dateVal) {
  if (!dateVal) return null;
  try {
    const d = new Date(dateVal);
    if (isNaN(d.getTime())) return null;
    return d.toLocaleTimeString(undefined, {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: true,
    });
  } catch {
    return null;
  }
}

function formatDuration(seconds) {
  if (seconds == null || isNaN(seconds)) return null;
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

export default function Reports() {
  const [scanHistory, setScanHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [downloadingKey, setDownloadingKey] = useState(null);
  const [lastExported, setLastExported] = useState({});
  const [currentTime, setCurrentTime] = useState(new Date().toLocaleTimeString());
  const [viewingReport, setViewingReport] = useState(null);
  const [reportLoading, setReportLoading] = useState(false);
  const canvasRef = useRef(null);

  async function handleViewReport(scanId) {
    setReportLoading(true);
    try {
      const res = await api.get(`/reports/${scanId}`);
      setViewingReport(res.data);
    } catch (err) {
      console.error("Failed to load report", err);
      alert("Error loading report details: " + (err.message || "Failed to load"));
    } finally {
      setReportLoading(false);
    }
  }

  // Live Clock ticker
  useEffect(() => {
    const interval = setInterval(() => {
      setCurrentTime(new Date().toLocaleTimeString());
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  // Background Interactive Canvas Particle Network
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");

    let animationFrameId;
    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    const particles = [];
    const particleCount = Math.floor((width * height) / 15000);

    class Particle {
      constructor() {
        this.x = Math.random() * width;
        this.y = Math.random() * height;
        this.vx = (Math.random() - 0.5) * 0.5;
        this.vy = (Math.random() - 0.5) * 0.5;
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
        ctx.fillStyle = "rgba(0, 240, 255, 0.6)";
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
          const distance = Math.sqrt(dx * dx + dy * dy);

          if (distance < 110) {
            ctx.beginPath();
            ctx.strokeStyle = `rgba(0, 240, 255, ${0.25 - distance / 110})`;
            ctx.lineWidth = 0.6;
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

  useEffect(() => {
    async function fetchScans() {
      try {
        const res = await api.get("/scans/");
        setScanHistory(res.data);
      } catch (err) {
        console.error("Failed to fetch scans for reports", err);
      } finally {
        setLoading(false);
      }
    }
    fetchScans();
  }, []);

  async function handleDownload(scanId, format) {
    const key = `${scanId}-${format}`;
    setDownloadingKey(key);
    try {
      const res = await api.getBlob(`/reports/${scanId}/${format}`);
      if (!res.data) {
        throw new Error("No data returned by server");
      }
      const filename = `report_${scanId}.${format}`;
      const blobUrl = URL.createObjectURL(res.data);
      
      const link = document.createElement('a');
      link.href = blobUrl;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      
      document.body.removeChild(link);
      URL.revokeObjectURL(blobUrl);

      const genTime = new Date().toLocaleTimeString();
      setLastExported(prev => ({
        ...prev,
        [scanId]: { format: format.toUpperCase(), time: genTime }
      }));
    } catch (err) {
      console.error(`Failed to download ${format.toUpperCase()} report`, err);
      alert(`Error generating ${format.toUpperCase()} report: ${err.message || 'Please verify the scan has completed.'}`);
    } finally {
      setDownloadingKey(null);
    }
  }

  return (
    <div className="relative min-h-screen font-mono text-slate-100 p-2 sm:p-6 overflow-hidden bg-[#020408]">
      
      {/* Full Screen Interactive Canvas Background */}
      <canvas 
        ref={canvasRef} 
        className="fixed inset-0 z-0 h-screen w-screen pointer-events-none bg-[#020408] opacity-75" 
      />

      {/* Futuristic Cyber Overlay Grid */}
      <div className="fixed inset-0 z-0 pointer-events-none bg-[linear-gradient(to_right,#00f0ff08_1px,transparent_1px),linear-gradient(to_bottom,#00f0ff08_1px,transparent_1px)] bg-[size:3rem_3rem]" />
      <div className="fixed -top-24 -right-24 z-0 h-96 w-96 rounded-full bg-cyan-500/10 blur-[150px] pointer-events-none" />
      <div className="fixed top-1/2 -left-24 z-0 h-96 w-96 rounded-full bg-blue-600/10 blur-[150px] pointer-events-none" />

      {/* Main Content Area */}
      <div className="relative z-10 mx-auto max-w-6xl space-y-6">
        
        {/* Header Control Bar */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 rounded-2xl border border-cyan-500/30 bg-[#070D1B]/80 p-5 shadow-[0_0_30px_rgba(0,240,255,0.08)] backdrop-blur-2xl">
          <div className="flex items-center gap-3.5">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-cyan-950/60 border border-cyan-400/60 text-cyan-400 shadow-[0_0_15px_rgba(0,240,255,0.3)]">
              <ShieldCheck size={22} className="animate-pulse" />
            </div>
            <div>
              <h1 className="text-lg font-extrabold tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-slate-100 to-blue-300 uppercase">
                Security Intelligence Reports
              </h1>
              <p className="text-[11px] text-slate-400 flex items-center gap-1 mt-0.5">
                <Cpu size={12} className="text-cyan-400" /> Export completed scans as PDF, structured JSON, or CSV with full execution & generation timestamps.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="flex items-center gap-1.5 rounded-lg border border-cyan-500/30 bg-[#03060D] px-3 py-1.5 text-[11px] font-bold text-cyan-400 shadow-inner">
              <Clock size={12} className="text-cyan-400 animate-pulse" />
              <span>{currentTime}</span>
            </span>
            <span className="flex items-center gap-1.5 rounded-lg border border-cyan-500/30 bg-[#03060D] px-3 py-1.5 text-[11px] font-bold text-cyan-400 shadow-inner">
              <Terminal size={12} /> TELEMETRY EXPORT
            </span>
          </div>
        </div>

        {/* Reports Table Container */}
        <div className="rounded-2xl border border-cyan-500/25 bg-[#070D1B]/80 shadow-[0_0_40px_rgba(0,240,255,0.05)] backdrop-blur-2xl overflow-hidden">
          
          {/* Table Header */}
          <div className="hidden grid-cols-12 gap-2 border-b border-cyan-500/20 bg-[#03060D]/90 px-6 py-3.5 font-mono text-[11px] uppercase tracking-wider text-cyan-400 font-bold md:grid">
            <div className="col-span-3 flex items-center gap-1.5"><Database size={13}/> Target Host / Asset</div>
            <div className="col-span-2 flex items-center gap-1.5"><Clock size={13}/> Timestamp & Duration</div>
            <div className="col-span-1">Score</div>
            <div className="col-span-1">Risk</div>
            <div className="col-span-1">Findings</div>
            <div className="col-span-1">Status</div>
            <div className="col-span-3 text-right pr-2">Report Actions</div>
          </div>

          {/* Table Rows */}
          <div className="divide-y divide-cyan-500/10">
            {loading ? (
              <div className="p-12 text-center text-xs text-cyan-400/70 font-mono flex items-center justify-center gap-2">
                <Sparkles size={16} className="animate-spin text-cyan-400" /> Initializing Scan Intelligence Repository...
              </div>
            ) : scanHistory.length === 0 ? (
              <div className="p-12 text-center text-xs text-slate-500 font-mono">
                [NO TELEMETRY RECORDED] No completed scans available for report extraction.
              </div>
            ) : (
              scanHistory.map((scan) => {
                const scanExportInfo = lastExported[scan.id];
                const findingsTotal = scan.findings_count ?? scan.total_findings ?? (scan.findings ? scan.findings.length : 0);
                const scanStatus = (scan.status || "completed").toUpperCase();

                return (
                  <div 
                    key={scan.id} 
                    className="grid grid-cols-1 gap-3 px-6 py-4 transition-all duration-300 hover:bg-cyan-950/20 md:grid-cols-12 md:items-center"
                  >
                    {/* Target Column */}
                    <div className="font-mono text-xs font-bold text-slate-100 md:col-span-3 truncate flex items-center gap-2">
                      <span className="h-2 w-2 rounded-full bg-cyan-400 shadow-[0_0_8px_#00f0ff] flex-shrink-0" />
                      <span className="truncate" title={scan.target_urls?.[0] || scan.target || scan.asset_id}>
                        {scan.target_urls?.[0] || scan.target || scan.asset_id}
                      </span>
                    </div>

                    {/* Time & Execution Timeline Column */}
                    <div className="text-xs text-slate-300 md:col-span-2 font-mono space-y-1">
                      <div className="flex items-center gap-1.5 font-medium text-slate-200">
                        <Calendar size={12} className="text-cyan-400 flex-shrink-0" />
                        <span className="text-[11px] text-slate-200">{formatDateTime(scan.started_at)}</span>
                      </div>
                      
                      <div className="flex flex-wrap items-center gap-2 text-[10px]">
                        {scan.duration != null && scan.duration > 0 && (
                          <span className="inline-flex items-center gap-1 rounded bg-cyan-950/60 border border-cyan-500/30 px-1.5 py-0.5 text-[10px] font-bold text-cyan-300 shadow-[0_0_8px_rgba(0,240,255,0.15)]">
                            <Timer size={10} className="text-cyan-400" />
                            {formatDuration(scan.duration)}
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Score Column */}
                    <div className="text-xs font-extrabold text-cyan-300 md:col-span-1 font-mono">
                      <span className="rounded-md bg-cyan-950/60 border border-cyan-500/30 px-2 py-0.5 text-cyan-300 text-[11px] shadow-[0_0_10px_rgba(0,240,255,0.15)]">
                        {scan.risk_score?.score ?? scan.security_score ?? scan.score ?? 0}/100
                      </span>
                    </div>

                    {/* Rating Badge */}
                    <div className="text-xs md:col-span-1">
                      <span className={`inline-block rounded-md border px-2 py-0.5 text-[10px] font-extrabold uppercase tracking-wider ${
                        (scan.risk_score?.rating || scan.risk_level || "").toLowerCase() === 'high' || (scan.risk_score?.rating || scan.risk_level || "").toLowerCase() === 'critical'
                          ? 'border-rose-500/40 bg-rose-950/40 text-rose-400 shadow-[0_0_10px_rgba(244,63,94,0.3)]'
                          : (scan.risk_score?.rating || scan.risk_level || "").toLowerCase() === 'medium'
                          ? 'border-yellow-500/40 bg-yellow-950/40 text-yellow-400 shadow-[0_0_10px_rgba(234,179,8,0.3)]'
                          : 'border-emerald-500/40 bg-emerald-950/40 text-emerald-400 shadow-[0_0_10px_rgba(16,185,129,0.3)]'
                      }`}>
                        {scan.risk_score?.rating || scan.risk_level || "SAFE"}
                      </span>
                    </div>

                    {/* Finding Count Column */}
                    <div className="text-xs md:col-span-1 font-mono">
                      <span className="text-slate-300 font-bold">{findingsTotal}</span>
                      <span className="text-[10px] text-slate-500 ml-1">issues</span>
                    </div>

                    {/* Status Column */}
                    <div className="text-xs md:col-span-1">
                      <span className={`inline-block rounded px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider border ${
                        scanStatus === 'COMPLETED'
                          ? 'border-emerald-500/30 bg-emerald-950/30 text-emerald-300'
                          : scanStatus === 'RUNNING'
                          ? 'border-cyan-500/30 bg-cyan-950/30 text-cyan-300 animate-pulse'
                          : 'border-rose-500/30 bg-rose-950/30 text-rose-300'
                      }`}>
                        {scanStatus}
                      </span>
                    </div>

                    {/* Export Buttons & Report Generated Feedback Container */}
                    <div className="flex flex-col items-start md:items-end gap-1 md:col-span-3">
                      <div className="flex flex-wrap items-center justify-start md:justify-end gap-1.5">
                        <button
                          onClick={() => handleViewReport(scan.id)}
                          className="flex items-center gap-1 rounded-lg border border-cyan-500/40 bg-cyan-950/40 px-2.5 py-1.5 text-xs font-bold text-cyan-300 hover:bg-cyan-400 hover:text-black transition-all duration-200 shadow-[0_0_10px_rgba(0,240,255,0.2)]"
                          title="View Comprehensive 17-Section Report in UI"
                        >
                          <Eye size={12} />
                          <span>VIEW</span>
                        </button>
                        <ExportButton 
                          icon={FileText} 
                          label="PDF" 
                          onClick={() => handleDownload(scan.id, "pdf")} 
                          color="cyan"
                          isDownloading={downloadingKey === `${scan.id}-pdf`}
                        />
                        <ExportButton 
                          icon={FileCode} 
                          label="MD" 
                          onClick={() => handleDownload(scan.id, "markdown")} 
                          color="emerald"
                          isDownloading={downloadingKey === `${scan.id}-markdown`}
                        />
                        <ExportButton 
                          icon={FileJson} 
                          label="JSON" 
                          onClick={() => handleDownload(scan.id, "json")} 
                          color="blue"
                          isDownloading={downloadingKey === `${scan.id}-json`}
                        />
                      </div>
                      {scanExportInfo && (
                        <div className="text-[10px] text-emerald-400/90 font-mono flex items-center gap-1 mt-0.5 animate-fadeIn">
                          <CheckCircle2 size={10} className="text-emerald-400" />
                          <span>{scanExportInfo.format} generated at {scanExportInfo.time}</span>
                        </div>
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </div>

        </div>

      </div>

      {/* Interactive Cyber Report Modal */}
      {viewingReport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fadeIn">
          <div className="relative w-full max-w-4xl max-h-[90vh] overflow-y-auto rounded-3xl border border-cyan-500/40 bg-[#070D1B] p-6 shadow-[0_0_60px_rgba(0,240,255,0.2)] text-slate-100 font-mono space-y-6">
            
            {/* Modal Header */}
            <div className="flex items-start justify-between border-b border-cyan-500/20 pb-4">
              <div>
                <div className="flex items-center gap-2">
                  <ShieldCheck size={20} className="text-cyan-400" />
                  <h2 className="text-base font-extrabold uppercase tracking-wider text-cyan-300">
                    Security Assessment Report
                  </h2>
                </div>
                <p className="text-xs text-slate-400 mt-1">
                  Target: <span className="text-cyan-200 font-bold">{viewingReport.target || viewingReport.executive_summary?.target}</span> · Scan ID: <span className="text-slate-500">{viewingReport.scan_id}</span>
                </p>
              </div>
              <button
                onClick={() => setViewingReport(null)}
                className="rounded-xl border border-slate-700 p-2 text-slate-400 hover:border-rose-500 hover:text-rose-400 hover:bg-rose-950/30 transition-all"
              >
                <X size={18} />
              </button>
            </div>

            {/* Quick Summary Cards */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
              <div className="p-3 rounded-xl border border-cyan-500/20 bg-[#03060D]">
                <p className="text-[10px] text-slate-400 uppercase">Risk Score</p>
                <p className="text-lg font-extrabold text-cyan-300 mt-1">{viewingReport.executive_summary?.score_display || `${viewingReport.risk_score_calculation?.final_score}/100`}</p>
                <p className="text-[10px] text-slate-500 mt-0.5">Rating: {viewingReport.executive_summary?.risk_level || viewingReport.risk_score_calculation?.risk_level}</p>
              </div>
              <div className="p-3 rounded-xl border border-cyan-500/20 bg-[#03060D]">
                <p className="text-[10px] text-slate-400 uppercase">Assessment Status</p>
                <p className="text-sm font-bold text-emerald-400 mt-2 uppercase">{viewingReport.executive_summary?.status || "COMPLETED"}</p>
              </div>
              <div className="p-3 rounded-xl border border-cyan-500/20 bg-[#03060D]">
                <p className="text-[10px] text-slate-400 uppercase">Confirmed / Potential</p>
                <p className="text-sm font-bold text-slate-200 mt-2">
                  <span className="text-rose-400">{viewingReport.executive_summary?.confirmed_count || 0}</span> confirmed · <span className="text-amber-400">{viewingReport.executive_summary?.potential_count || 0}</span> potential
                </p>
              </div>
              <div className="p-3 rounded-xl border border-cyan-500/20 bg-[#03060D]">
                <p className="text-[10px] text-slate-400 uppercase">Informational</p>
                <p className="text-sm font-bold text-cyan-300 mt-2">{viewingReport.executive_summary?.informational_count || 0} observations</p>
              </div>
            </div>

            {/* Section: Transparent Score Calculation */}
            {viewingReport.risk_score_calculation && (
              <div className="p-4 rounded-2xl border border-cyan-500/25 bg-[#03060D]/90 space-y-3">
                <h3 className="text-xs font-extrabold uppercase text-cyan-300 flex items-center gap-1.5">
                  <Cpu size={14} className="text-cyan-400" /> Transparent VulnAI Project Risk Score Calculation
                </h3>
                <p className="text-[11px] text-slate-400">
                  Starting Base Score: <span className="text-slate-200 font-bold">100 points</span>. Configurable deductions applied per verified evidence.
                </p>
                
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
                  {Object.entries(viewingReport.risk_score_calculation.summary || {}).map(([sev, data]) => (
                    <div key={sev} className="p-2.5 rounded-lg border border-slate-800 bg-[#070D1B]">
                      <p className="text-[10px] uppercase text-slate-400 font-bold">{sev}</p>
                      <p className="text-xs text-slate-200 font-mono mt-0.5">
                        {data.count} × {data.points_each} = <span className="text-rose-400 font-bold">-{data.total} pts</span>
                      </p>
                    </div>
                  ))}
                </div>

                <div className="flex flex-wrap items-center justify-between border-t border-slate-800 pt-2 text-xs">
                  <span className="text-slate-400">Mathematical Formula:</span>
                  <span className="font-bold text-cyan-300">{viewingReport.risk_score_calculation.formula}</span>
                </div>
              </div>
            )}

            {/* Section: Scanner Matrix */}
            <div className="space-y-2">
              <h3 className="text-xs font-bold uppercase text-slate-300">Tool Execution Matrix</h3>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs">
                {(viewingReport.tool_execution_summary || []).map((t) => (
                  <div key={t.tool} className="p-2.5 rounded-xl border border-cyan-500/15 bg-[#03060D] flex items-center justify-between">
                    <div>
                      <p className="font-bold capitalize text-slate-200">{t.tool}</p>
                      <p className="text-[10px] text-slate-500">{t.duration_seconds}s</p>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                      t.status === 'completed' ? 'bg-emerald-950/60 text-emerald-300 border border-emerald-500/30' : 'bg-amber-950/60 text-amber-300 border border-amber-500/30'
                    }`}>
                      {t.status}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Download Buttons inside modal */}
            <div className="flex flex-wrap items-center justify-end gap-2 border-t border-cyan-500/20 pt-4">
              <ExportButton icon={FileText} label="DOWNLOAD PDF" onClick={() => handleDownload(viewingReport.scan_id, "pdf")} color="cyan" />
              <ExportButton icon={FileCode} label="DOWNLOAD MARKDOWN" onClick={() => handleDownload(viewingReport.scan_id, "markdown")} color="emerald" />
              <ExportButton icon={FileJson} label="DOWNLOAD JSON" onClick={() => handleDownload(viewingReport.scan_id, "json")} color="blue" />
            </div>

          </div>
        </div>
      )}
    </div>
  );
}

function ExportButton({ icon: Icon, label, onClick, color, isDownloading }) {
  const colorStyles = {
    cyan: "border-cyan-500/30 bg-cyan-950/30 text-cyan-300 hover:bg-cyan-500 hover:text-slate-950 hover:shadow-[0_0_15px_rgba(0,240,255,0.5)]",
    blue: "border-blue-500/30 bg-blue-950/30 text-blue-300 hover:bg-blue-500 hover:text-slate-950 hover:shadow-[0_0_15px_rgba(59,130,246,0.5)]",
    purple: "border-purple-500/30 bg-purple-950/30 text-purple-300 hover:bg-purple-500 hover:text-slate-950 hover:shadow-[0_0_15px_rgba(168,85,247,0.5)]",
    emerald: "border-emerald-500/30 bg-emerald-950/30 text-emerald-300 hover:bg-emerald-500 hover:text-slate-950 hover:shadow-[0_0_15px_rgba(16,185,129,0.5)]"
  };

  return (
    <button
      onClick={onClick}
      disabled={isDownloading}
      className={`group flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-bold uppercase tracking-wider transition-all duration-300 active:scale-95 disabled:opacity-50 disabled:pointer-events-none ${colorStyles[color] || colorStyles.cyan}`}
    >
      {isDownloading ? (
        <Sparkles size={13} className="animate-spin text-cyan-300" />
      ) : (
        <Icon size={13} className="transition-transform group-hover:scale-110" />
      )}
      <span>{isDownloading ? "SAVING..." : label}</span>
      <Download size={11} className="opacity-70 transition-transform group-hover:translate-y-0.5" />
    </button>
  );
}