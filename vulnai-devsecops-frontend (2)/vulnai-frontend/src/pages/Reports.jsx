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
  Timer
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
  const canvasRef = useRef(null);

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
          <div className="hidden grid-cols-12 gap-3 border-b border-cyan-500/20 bg-[#03060D]/90 px-6 py-3.5 font-mono text-[11px] uppercase tracking-wider text-cyan-400 font-bold md:grid">
            <div className="col-span-3 flex items-center gap-1.5"><Database size={13}/> Target Host / Asset</div>
            <div className="col-span-3 flex items-center gap-1.5"><Clock size={13}/> Scan Time & Duration</div>
            <div className="col-span-2">Security Score</div>
            <div className="col-span-1">Risk Level</div>
            <div className="col-span-3 text-right pr-4">Export Options</div>
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
                return (
                  <div 
                    key={scan.id} 
                    className="grid grid-cols-1 gap-3 px-6 py-4 transition-all duration-300 hover:bg-cyan-950/20 md:grid-cols-12 md:items-center"
                  >
                    {/* Target Column */}
                    <div className="font-mono text-xs font-bold text-slate-100 md:col-span-3 truncate flex items-center gap-2">
                      <span className="h-2 w-2 rounded-full bg-cyan-400 shadow-[0_0_8px_#00f0ff] flex-shrink-0" />
                      <span className="truncate" title={scan.target_urls?.[0] || scan.asset_id}>
                        {scan.target_urls?.[0] || scan.asset_id}
                      </span>
                    </div>

                    {/* Time & Execution Timeline Column */}
                    <div className="text-xs text-slate-300 md:col-span-3 font-mono space-y-1">
                      <div className="flex items-center gap-1.5 font-medium text-slate-200">
                        <Calendar size={12} className="text-cyan-400 flex-shrink-0" />
                        <span className="text-[11px] text-slate-200">{formatDateTime(scan.started_at)}</span>
                      </div>
                      
                      <div className="flex flex-wrap items-center gap-2 text-[10px]">
                        {scan.completed_at && (
                          <span className="flex items-center gap-1 text-slate-400">
                            <CheckCircle2 size={10} className="text-emerald-400 flex-shrink-0" />
                            <span>Done: {formatTimeOnly(scan.completed_at)}</span>
                          </span>
                        )}
                        
                        {scan.duration != null && scan.duration > 0 && (
                          <span className="inline-flex items-center gap-1 rounded bg-cyan-950/60 border border-cyan-500/30 px-1.5 py-0.5 text-[10px] font-bold text-cyan-300 shadow-[0_0_8px_rgba(0,240,255,0.15)]">
                            <Timer size={10} className="text-cyan-400" />
                            {formatDuration(scan.duration)}
                            <span className="text-[9px] text-cyan-400/60 font-normal">({Math.round(scan.duration)}s)</span>
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Score Column */}
                    <div className="text-xs font-extrabold text-cyan-300 md:col-span-2 font-mono">
                      <span className="rounded-md bg-cyan-950/60 border border-cyan-500/30 px-2.5 py-1 text-cyan-300 shadow-[0_0_10px_rgba(0,240,255,0.15)]">
                        {scan.risk_score?.score ?? scan.security_score ?? 0} / 100
                      </span>
                    </div>

                    {/* Rating Badge */}
                    <div className="text-xs md:col-span-1">
                      <span className={`inline-block rounded-md border px-2 py-0.5 text-[10px] font-extrabold uppercase tracking-wider ${
                        scan.risk_score?.rating?.toLowerCase() === 'high' || scan.risk_score?.rating?.toLowerCase() === 'critical'
                          ? 'border-rose-500/40 bg-rose-950/40 text-rose-400 shadow-[0_0_10px_rgba(244,63,94,0.3)]'
                          : scan.risk_score?.rating?.toLowerCase() === 'medium'
                          ? 'border-yellow-500/40 bg-yellow-950/40 text-yellow-400 shadow-[0_0_10px_rgba(234,179,8,0.3)]'
                          : 'border-emerald-500/40 bg-emerald-950/40 text-emerald-400 shadow-[0_0_10px_rgba(16,185,129,0.3)]'
                      }`}>
                        {scan.risk_score?.rating || "SAFE"}
                      </span>
                    </div>

                    {/* Export Buttons & Report Generated Feedback Container */}
                    <div className="flex flex-col items-start md:items-end gap-1 md:col-span-3">
                      <div className="flex flex-wrap items-center justify-start md:justify-end gap-2">
                        <ExportButton 
                          icon={FileText} 
                          label="PDF" 
                          onClick={() => handleDownload(scan.id, "pdf")} 
                          color="cyan"
                          isDownloading={downloadingKey === `${scan.id}-pdf`}
                        />
                        <ExportButton 
                          icon={FileJson} 
                          label="JSON" 
                          onClick={() => handleDownload(scan.id, "json")} 
                          color="blue"
                          isDownloading={downloadingKey === `${scan.id}-json`}
                        />
                        <ExportButton 
                          icon={FileSpreadsheet} 
                          label="CSV" 
                          onClick={() => handleDownload(scan.id, "csv")} 
                          color="purple"
                          isDownloading={downloadingKey === `${scan.id}-csv`}
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
    </div>
  );
}

function ExportButton({ icon: Icon, label, onClick, color, isDownloading }) {
  const colorStyles = {
    cyan: "border-cyan-500/30 bg-cyan-950/30 text-cyan-300 hover:bg-cyan-500 hover:text-slate-950 hover:shadow-[0_0_15px_rgba(0,240,255,0.5)]",
    blue: "border-blue-500/30 bg-blue-950/30 text-blue-300 hover:bg-blue-500 hover:text-slate-950 hover:shadow-[0_0_15px_rgba(59,130,246,0.5)]",
    purple: "border-purple-500/30 bg-purple-950/30 text-purple-300 hover:bg-purple-500 hover:text-slate-950 hover:shadow-[0_0_15px_rgba(168,85,247,0.5)]"
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