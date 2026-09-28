import { useState, useEffect, useRef } from "react";
import { GitMerge, Layers, CheckCircle2, ShieldAlert, Terminal, Sparkles, Cpu, Activity } from "lucide-react";
import api from "../lib/api";

const LEVEL_STYLES = {
  high: { text: "text-rose-400 drop-shadow-[0_0_12px_rgba(244,63,94,0.4)]", ring: "stroke-rose-400", badge: "border-rose-500/40 bg-rose-950/40 text-rose-300 shadow-[0_0_15px_rgba(244,63,94,0.3)]" },
  medium: { text: "text-yellow-400 drop-shadow-[0_0_12px_rgba(234,179,8,0.4)]", ring: "stroke-yellow-400", badge: "border-yellow-500/40 bg-yellow-950/40 text-yellow-300 shadow-[0_0_15px_rgba(234,179,8,0.3)]" },
  low: { text: "text-emerald-400 drop-shadow-[0_0_12px_rgba(16,185,129,0.4)]", ring: "stroke-emerald-400", badge: "border-emerald-500/40 bg-emerald-950/40 text-emerald-300 shadow-[0_0_15px_rgba(16,185,129,0.3)]" },
};

const FORMULA_LABELS = {
  S: "Severity score",
  E: "Security events",
  A: "AI anomaly score",
  I: "Incident correlation",
  R: "Asset / device risk",
};
const FORMULA_WEIGHTS = { S: 0.35, E: 0.2, A: 0.2, I: 0.15, R: 0.1 };

export default function Incidents() {
  const [incidentsList, setIncidentsList] = useState([]);
  const [loading, setLoading] = useState(true);
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
    async function fetchIncidents() {
      try {
        const res = await api.get("/incidents/");
        setIncidentsList(res.data);
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    }
    fetchIncidents();
    const interval = setInterval(fetchIncidents, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleResolve = async (id) => {
    try {
      await api.post(`/incidents/${id}/status`, { status: "RESOLVED" });
      setIncidentsList(prev => prev.map(inc => inc.id === id ? { ...inc, status: "RESOLVED" } : inc));
    } catch (e) {
      console.error(e);
    }
  };

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
      <div className="fixed top-1/2 -left-24 z-0 h-96 w-96 rounded-full bg-rose-600/10 blur-[150px] pointer-events-none" />

      {/* Main Content Area */}
      <div className="relative z-10 mx-auto max-w-6xl space-y-6">

        {/* Top Header Banner */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 rounded-2xl border border-cyan-500/30 bg-[#070D1B]/80 p-5 shadow-[0_0_30px_rgba(0,240,255,0.08)] backdrop-blur-2xl">
          <div className="flex items-center gap-3.5">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-cyan-950/60 border border-cyan-400/60 text-cyan-400 shadow-[0_0_15px_rgba(0,240,255,0.3)]">
              <ShieldAlert size={22} className="animate-pulse" />
            </div>
            <div>
              <h1 className="text-lg font-extrabold tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-slate-100 to-blue-300 uppercase">
                Threat & Incident Matrix
              </h1>
              <p className="text-[11px] text-slate-400 flex items-center gap-1 mt-0.5">
                <Cpu size={12} className="text-cyan-400" /> Real-time threat correlation powered by IsolationForest & telemetry feeds.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="flex items-center gap-1.5 rounded-lg border border-cyan-500/30 bg-[#03060D] px-3 py-1.5 text-[11px] font-bold text-cyan-400 shadow-inner">
              <Terminal size={12} /> LIVE SYNC: 5S INTERVAL
            </span>
          </div>
        </div>

        {/* Risk Score Formula Bar */}
        <div className="rounded-2xl border border-cyan-500/25 bg-[#070D1B]/80 p-5 shadow-[0_0_25px_rgba(0,240,255,0.05)] backdrop-blur-2xl">
          <div className="flex items-center gap-3.5">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-purple-500/40 bg-purple-950/40 text-purple-400 shadow-[0_0_10px_rgba(168,85,247,0.3)]">
              <GitMerge size={18} strokeWidth={1.75} />
            </div>
            <div>
              <h3 className="font-display text-sm font-bold text-slate-100 uppercase tracking-wider">Risk Score Mathematical Formula</h3>
              <p className="font-mono text-xs text-cyan-300 mt-0.5 bg-[#03060D] px-3 py-1 rounded-lg border border-cyan-500/20 shadow-inner inline-block">
                Risk = 0.35·S + 0.20·E + 0.20·A + 0.15·I + 0.10·R
              </p>
            </div>
          </div>
        </div>

        {/* Incidents List Container */}
        <div className="space-y-4">
          {loading ? (
            <div className="rounded-2xl border border-cyan-500/25 bg-[#070D1B]/80 p-12 text-center text-xs text-cyan-400 font-mono flex items-center justify-center gap-2.5 backdrop-blur-2xl">
              <Sparkles size={18} className="animate-spin text-cyan-400" /> Initializing Threat Intelligence Feeds...
            </div>
          ) : incidentsList.length === 0 ? (
            <div className="rounded-2xl border border-cyan-500/25 bg-[#070D1B]/80 p-12 text-center text-xs text-slate-400 font-mono backdrop-blur-2xl">
              [NO ACTIVE THREATS] No incidents found. Simulator must spawn events.
            </div>
          ) : null}

          {incidentsList.map((inc) => {
            const style = LEVEL_STYLES[inc.severity?.toLowerCase()] || LEVEL_STYLES.high;
            const isResolved = inc.status === "RESOLVED";
            return (
              <div 
                key={inc.id} 
                className={`rounded-2xl border bg-[#070D1B]/80 p-6 shadow-[0_0_30px_rgba(0,240,255,0.05)] backdrop-blur-2xl transition-all duration-300 hover:border-cyan-500/40 ${
                  isResolved ? 'opacity-50 border-slate-700/40 bg-[#03060D]/60' : 'border-cyan-500/30'
                }`}
              >
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div>
                    <div className="mb-2 flex items-center gap-2.5">
                      <Layers size={14} className="text-cyan-400" />
                      <span className={`font-mono text-xs uppercase tracking-wider font-bold px-2.5 py-0.5 rounded border ${
                        isResolved 
                          ? 'border-slate-600 bg-slate-900 text-slate-400' 
                          : 'border-cyan-500/40 bg-cyan-950/40 text-cyan-300 shadow-[0_0_10px_rgba(0,240,255,0.2)]'
                      }`}>
                        {inc.status}
                      </span>
                      {!isResolved && (
                        <button 
                          onClick={() => handleResolve(inc.id)} 
                          className="ml-2 flex items-center gap-1.5 px-3 py-1 border border-emerald-500/40 text-emerald-300 bg-emerald-950/40 rounded-lg text-[11px] uppercase font-mono font-bold tracking-wider hover:bg-emerald-500 hover:text-slate-950 hover:shadow-[0_0_15px_rgba(16,185,129,0.5)] transition-all duration-300 active:scale-95"
                        >
                          <CheckCircle2 size={13} /> Mark Resolved
                        </button>
                      )}
                    </div>
                    <h4 className="font-display text-base font-bold text-slate-100 tracking-wide">{inc.title}</h4>
                    <p className="mt-1 font-mono text-xs text-cyan-300">{inc.source_ip || inc.asset}</p>
                  </div>
                  
                  <div className="text-right">
                    <p className={`font-display text-3xl font-extrabold ${style.text}`}>
                      {inc.severity?.toUpperCase() || "HIGH"}
                    </p>
                    <p className="font-mono text-[10px] uppercase tracking-wider text-slate-400 mt-0.5">RISK LEVEL</p>
                  </div>
                </div>

                {/* Merged signals */}
                <div className="mt-5 border-t border-cyan-500/15 pt-4">
                  <p className="mb-2 text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                    <Activity size={13} className="text-cyan-400" /> Merged Trace ({inc.description})
                  </p>
                  <div className="flex flex-wrap gap-2 max-h-[80px] overflow-y-auto">
                    <div className="flex items-center gap-2 border border-cyan-500/20 bg-[#03060D] px-3.5 py-2 rounded-xl text-xs shadow-inner">
                      <span className="font-mono font-bold text-cyan-400">Events Captured:</span>
                      <span className="text-slate-300">{inc.related_events?.length || 0} unique items mapped across IsolationForest & IDS traces.</span>
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>

      </div>
    </div>
  );
}