import { useMemo, useState, useEffect, useRef } from "react";
import { Radio, ShieldAlert, Cpu, Eye, ScanLine, Play, Terminal, Sparkles, Activity } from "lucide-react";
import SeverityBadge from "../components/SeverityBadge";
import api from "../lib/api";

const SOURCE_ICONS = {
  Suricata: ShieldAlert,
  Zeek: Radio,
  "WiFi Guard": Eye,
  "AI Engine": Cpu,
  Wazuh: ShieldAlert,
  Scanner: ScanLine,
};

export default function Events() {
  const [source, setSource] = useState("All");
  const [securityEvents, setSecurityEvents] = useState([]);
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

  const fetchEvents = async () => {
    try {
      const res = await api.get("/events/");
      setSecurityEvents(res.data);
    } catch (err) {
      console.error("Failed to fetch events", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents();
    const interval = setInterval(fetchEvents, 5000);
    return () => clearInterval(interval);
  }, []);

  const triggerMockEvent = async () => {
    try {
      await api.post("/events/ingest", {
        source: "Zeek",
        source_ip: "10.0.0.210",
        type: "Anomalous Traffic Burst",
        detail: "Sudden spike in outbound traffic detected from IoT Subnet",
        bytes_out: 70000,
        protocol: "TCP"
      });
      fetchEvents();
    } catch (e) {
      console.error(e);
    }
  };

  const filtered = useMemo(
    () => (source === "All" ? securityEvents : securityEvents.filter((e) => e.source === source)),
    [source, securityEvents]
  );
  
  const sourcesList = ["All", ...new Set(securityEvents.map((e) => e.source))];

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
      <div className="fixed top-1/2 -left-24 z-0 h-96 w-96 rounded-full bg-purple-600/10 blur-[150px] pointer-events-none" />

      {/* Main Content Area */}
      <div className="relative z-10 mx-auto max-w-6xl space-y-6">

        {/* Top Header Banner */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 rounded-2xl border border-cyan-500/30 bg-[#070D1B]/80 p-5 shadow-[0_0_30px_rgba(0,240,255,0.08)] backdrop-blur-2xl">
          <div className="flex items-center gap-3.5">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-cyan-950/60 border border-cyan-400/60 text-cyan-400 shadow-[0_0_15px_rgba(0,240,255,0.3)]">
              <Activity size={22} className="animate-pulse" />
            </div>
            <div>
              <h1 className="text-lg font-extrabold tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-slate-100 to-blue-300 uppercase">
                Security Events & Telemetry Stream
              </h1>
              <p className="text-[11px] text-slate-400 flex items-center gap-1 mt-0.5">
                <Cpu size={12} className="text-cyan-400" /> Real-time packet inspection, Suricata alerts, and AI anomaly detection.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="flex items-center gap-1.5 rounded-lg border border-cyan-500/30 bg-[#03060D] px-3 py-1.5 text-[11px] font-bold text-cyan-400 shadow-inner">
              <Terminal size={12} /> FEED SYNC: LIVE
            </span>
          </div>
        </div>

        {/* Controls & Simulators Bar */}
        <div className="flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-cyan-500/25 bg-[#070D1B]/80 p-4 shadow-[0_0_25px_rgba(0,240,255,0.05)] backdrop-blur-2xl">
          <div className="flex flex-wrap gap-2">
            {sourcesList.map((s) => (
              <button
                key={s}
                onClick={() => setSource(s)}
                className={`rounded-xl border px-3.5 py-2 text-xs font-mono font-bold uppercase tracking-wider transition-all duration-300 ${
                  source === s
                    ? "border-cyan-500/60 bg-cyan-950/50 text-cyan-300 shadow-[0_0_15px_rgba(0,240,255,0.3)]"
                    : "border-cyan-500/20 bg-[#03060D] text-slate-400 hover:border-cyan-500/40 hover:text-slate-200"
                }`}
              >
                {s}
              </button>
            ))}
          </div>
          <button
            onClick={triggerMockEvent}
            className="flex items-center gap-2 rounded-xl border border-purple-500/40 bg-purple-950/40 px-4 py-2 text-xs font-mono font-bold uppercase tracking-wider text-purple-300 shadow-[0_0_15px_rgba(168,85,247,0.2)] transition-all duration-300 hover:bg-purple-500 hover:text-slate-950 hover:shadow-[0_0_20px_rgba(168,85,247,0.6)] active:scale-95"
          >
            <Play size={14} /> Simulate ML Anomaly Burst
          </button>
        </div>

        {/* Timeline Events Feed */}
        <div className="relative space-y-4 border-l-2 border-cyan-500/30 pl-6 ml-3 my-4">
          {loading ? (
            <div className="rounded-2xl border border-cyan-500/25 bg-[#070D1B]/80 p-12 text-center text-xs text-cyan-400 font-mono flex items-center justify-center gap-2.5 backdrop-blur-2xl">
              <Sparkles size={18} className="animate-spin text-cyan-400" /> Connecting to Security Telemetry Stream...
            </div>
          ) : filtered.length === 0 ? (
            <div className="rounded-2xl border border-cyan-500/25 bg-[#070D1B]/80 p-12 text-center text-xs text-slate-400 font-mono backdrop-blur-2xl">
              [NO EVENTS FOUND] No security telemetry events match the active filter.
            </div>
          ) : null}

          {filtered.map((ev) => {
            const Icon = SOURCE_ICONS[ev.source] || Radio;
            return (
              <div key={ev.id} className="relative pb-2 group">
                {/* Timeline node glowing dot */}
                <div className="absolute -left-[35px] top-4 flex h-7 w-7 items-center justify-center rounded-full border border-cyan-400/60 bg-[#03060D] text-cyan-400 shadow-[0_0_10px_#00f0ff] transition-all duration-300 group-hover:scale-110 group-hover:border-cyan-300">
                  <Icon size={13} className="text-cyan-300" />
                </div>
                
                {/* Event Card */}
                <div className="rounded-2xl border border-cyan-500/25 bg-[#070D1B]/80 p-5 shadow-[0_0_30px_rgba(0,240,255,0.05)] backdrop-blur-2xl transition-all duration-300 hover:border-cyan-500/50 hover:shadow-[0_0_35px_rgba(0,240,255,0.12)]">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <p className="text-sm font-bold text-slate-100 tracking-wide font-display">
                        {ev.event_type || ev.type}
                      </p>
                      <p className="mt-1 font-mono text-xs text-cyan-300 bg-[#03060D] px-2.5 py-1 rounded-lg border border-cyan-500/20 shadow-inner inline-block">
                        {ev.source} · {ev.source_ip} {ev.destination_ip ? `-> ${ev.destination_ip}` : ""}
                      </p>
                    </div>
                    <SeverityBadge level={ev.severity} />
                  </div>
                  
                  <p className="mt-3 text-xs text-slate-300 leading-relaxed font-mono">
                    {ev.message || ev.detail}
                  </p>
                  
                  <p className="mt-3 font-mono text-[11px] text-slate-400 flex items-center gap-1.5 border-t border-cyan-500/15 pt-2.5">
                    <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-pulse" />
                    {new Date(ev.timestamp).toLocaleString()}
                  </p>
                </div>
              </div>
            );
          })}
        </div>

      </div>
    </div>
  );
}