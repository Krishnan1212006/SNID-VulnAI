import { useState, useEffect, useRef } from "react";
import { Cpu, Camera, Router as RouterIcon, Plug, HelpCircle, Wifi, WifiOff, ShieldCheck, Terminal, Sparkles, Server } from "lucide-react";
import StatCard from "../components/StatCard";
import api from "../lib/api";

const ICONS = {
  "IoT Sensor": Cpu,
  "Edge Compute": RouterIcon,
  Camera,
  "IoT Actuator": Plug,
  Unclassified: HelpCircle,
};

const RISK_STYLES = {
  low: "border-emerald-500/40 bg-emerald-950/40 text-emerald-400 shadow-[0_0_10px_rgba(16,185,129,0.2)]",
  medium: "border-yellow-500/40 bg-yellow-950/40 text-yellow-400 shadow-[0_0_10px_rgba(234,179,8,0.2)]",
  high: "border-rose-500/40 bg-rose-950/40 text-rose-400 shadow-[0_0_15px_rgba(244,63,94,0.3)]",
};

export default function Devices() {
  const [devices, setDevices] = useState([]);
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
    async function fetchDevices() {
      try {
        const res = await api.get("/devices/");
        setDevices(res.data);
      } catch (err) {
        console.error("Failed to fetch devices", err);
      } finally {
        setLoading(false);
      }
    }
    fetchDevices();
  }, []);

  if (loading) {
    return (
      <div className="relative min-h-screen font-mono text-slate-100 p-6 flex items-center justify-center bg-[#020408]">
        <div className="flex items-center gap-2.5 text-xs text-cyan-400 font-mono">
          <Sparkles size={18} className="animate-spin text-cyan-400" /> Scanning IoT Network Topology...
        </div>
      </div>
    );
  }

  const online = devices.filter((d) => d.status === "online").length;
  const unknown = devices.filter((d) => d.risk === "high" || d.risk === "unknown").length;
  const highRisk = devices.filter((d) => d.risk === "high").length;

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
        
        {/* Header Bar */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 rounded-2xl border border-cyan-500/30 bg-[#070D1B]/80 p-5 shadow-[0_0_30px_rgba(0,240,255,0.08)] backdrop-blur-2xl">
          <div className="flex items-center gap-3.5">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-cyan-950/60 border border-cyan-400/60 text-cyan-400 shadow-[0_0_15px_rgba(0,240,255,0.3)]">
              <Server size={22} className="animate-pulse" />
            </div>
            <div>
              <h1 className="text-lg font-extrabold tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-slate-100 to-blue-300 uppercase">
                IoT Edge & Network Devices
              </h1>
              <p className="text-[11px] text-slate-400 flex items-center gap-1 mt-0.5">
                <Cpu size={12} className="text-cyan-400" /> Real-time telemetry monitoring of connected smart infrastructure.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="flex items-center gap-1.5 rounded-lg border border-cyan-500/30 bg-[#03060D] px-3 py-1.5 text-[11px] font-bold text-cyan-400 shadow-inner">
              <Terminal size={12} /> NODES ONLINE: {online}/{devices.length}
            </span>
          </div>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <div className="rounded-2xl border border-cyan-500/25 bg-[#070D1B]/80 p-4 shadow-[0_0_20px_rgba(0,240,255,0.05)] backdrop-blur-xl">
            <StatCard label="Devices Online" value={online} suffix={`/ ${devices.length}`} icon={Wifi} accent="blue" />
          </div>
          <div className="rounded-2xl border border-yellow-500/25 bg-[#070D1B]/80 p-4 shadow-[0_0_20px_rgba(234,179,8,0.05)] backdrop-blur-xl">
            <StatCard label="Unknown Devices" value={unknown} icon={HelpCircle} accent="high" />
          </div>
          <div className="rounded-2xl border border-rose-500/25 bg-[#070D1B]/80 p-4 shadow-[0_0_20px_rgba(244,63,94,0.05)] backdrop-blur-xl">
            <StatCard label="High Risk" value={highRisk} icon={RouterIcon} accent="critical" />
          </div>
        </div>

        {/* Devices Table Container */}
        <div className="rounded-2xl border border-cyan-500/25 bg-[#070D1B]/80 shadow-[0_0_40px_rgba(0,240,255,0.05)] backdrop-blur-2xl overflow-hidden">
          
          {/* Table Header */}
          <div className="hidden grid-cols-12 gap-3 border-b border-cyan-500/20 bg-[#03060D]/90 px-6 py-3.5 font-mono text-[11px] uppercase tracking-wider text-cyan-400 font-bold md:grid">
            <div className="col-span-3">Device Node</div>
            <div className="col-span-2">IP Address</div>
            <div className="col-span-3">MAC Address</div>
            <div className="col-span-2">Telemetry Status</div>
            <div className="col-span-2">Risk Assessment</div>
          </div>

          {/* Table Rows */}
          <div className="divide-y divide-cyan-500/10">
            {devices.map((d) => {
              const Icon = ICONS[d.device_type] || HelpCircle;
              const risk_level = d.status === "warning" ? "high" : "low";
              return (
                <div 
                  key={d.id} 
                  className="grid grid-cols-1 gap-2 px-6 py-4 transition-all duration-300 hover:bg-cyan-950/20 md:grid-cols-12 md:items-center md:gap-3"
                >
                  <div className="flex items-center gap-3 md:col-span-3">
                    <div className={`rounded-xl border p-2.5 shadow-md ${d.status === "active" ? "border-cyan-500/40 bg-cyan-950/40 text-cyan-400" : "border-rose-500/40 bg-rose-950/40 text-rose-400"}`}>
                      <Icon size={16} />
                    </div>
                    <div>
                      <p className="text-xs font-bold text-slate-100">{d.name}</p>
                      <p className="text-[11px] text-slate-400">{d.device_type}</p>
                    </div>
                  </div>

                  <div className="font-mono text-xs text-cyan-300 md:col-span-2">
                    {d.ip_address}
                  </div>

                  <div className="font-mono text-xs text-slate-400 md:col-span-3">
                    {d.mac_address || "-"}
                  </div>

                  <div className="flex items-center gap-1.5 text-xs md:col-span-2">
                    {d.status === "active" ? (
                      <Wifi size={13} className="text-emerald-400 drop-shadow-[0_0_6px_#10b981]" />
                    ) : (
                      <WifiOff size={13} className="text-slate-500" />
                    )}
                    <span className={d.status === "active" ? "text-emerald-400 font-bold" : "text-slate-500"}>
                      {d.status}
                    </span>
                  </div>

                  <div className="md:col-span-2">
                    <span className={`inline-flex rounded-md border px-2.5 py-1 font-mono text-[10px] uppercase tracking-wider font-extrabold ${RISK_STYLES[risk_level]}`}>
                      {risk_level}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>

        </div>

      </div>
    </div>
  );
}