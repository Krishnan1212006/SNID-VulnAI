import React, { useRef, useState, useEffect } from "react";
import { motion, useScroll, useTransform, useSpring, useMotionValue } from "framer-motion";
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  Lock,
  ArrowRight,
  Sparkles,
  Terminal,
  Activity,
  Cpu,
  Globe,
  Radio,
  Code2,
  TrendingUp,
  Eye,
  Crosshair,
  Server,
  Zap,
  Wifi
} from "lucide-react";

// ==========================================
// DATA & HIGH-RES CYBER ASSETS
// ==========================================
const CYBER_IMAGES = {
  threatMap: "https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?q=80&w=1200&auto=format&fit=crop",
  socHUD: "https://images.unsplash.com/photo-1558494949-ef010cbdcc31?q=80&w=1200&auto=format&fit=crop",
  aiNeural: "https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?q=80&w=1200&auto=format&fit=crop",
  cyberCore: "https://images.unsplash.com/photo-1563986768609-322da13575f3?q=80&w=1200&auto=format&fit=crop"
};

const TRUST_POINTS = [
  "Strict Scope Verification",
  "Evidence-Driven Findings",
  "AI Remediation Engine",
  "Continuous SOC Telemetry",
];

const HOW_IT_WORKS = [
  { step: "01", title: "Asset Discovery", desc: "Register target domain and establish encrypted authorization tokens." },
  { step: "02", title: "Safe Perimeter Assessment", desc: "Non-intrusive auditor inspects TLS/SSL, HTTP headers, & CORS." },
  { step: "03", title: "Threat Correlation", desc: "Maps network events and IDS alerts to OWASP Top 10 & CWE standards." },
  { step: "04", title: "AI Explainability", desc: "Translates complex risk vectors into actionable source code patches." },
  { step: "05", title: "DevSecOps Integration", desc: "Automate security controls inside GitHub Actions CI/CD pipelines." },
];

const FEATURES = [
  { id: "01", icon: Globe, title: "Targeted Asset Auditor", desc: "Conduct non-disruptive, evidence-based security auditing.", tags: ["Headers", "TLS/SSL", "Cookies"], img: CYBER_IMAGES.socHUD },
  { id: "02", icon: Sparkles, title: "AI Code Fix Generator", desc: "Auto-generate plain language patches and remediation commands.", tags: ["Gemini AI", "Auto-Fix"], img: CYBER_IMAGES.aiNeural },
  { id: "03", icon: Activity, title: "Dynamic OWASP Scoring", desc: "Quantify risk exposure through multi-vector severity weightings.", tags: ["Dynamic Score", "Risk Matrix"], img: CYBER_IMAGES.threatMap },
  { id: "04", icon: Radio, title: "Incident Correlation", desc: "Correlate device telemetry with Suricata IDS event streams.", tags: ["Suricata IDS", "Zeek Logs"], img: CYBER_IMAGES.cyberCore },
  { id: "05", icon: Cpu, title: "Live SOC Monitor HUD", desc: "Monitor network traffic flows and connected IoT nodes live.", tags: ["IoT Health", "Live Traffic"], img: CYBER_IMAGES.socHUD },
  { id: "06", icon: ShieldCheck, title: "CI/CD Pipeline Gate", desc: "Enforce automated deployment blocking policies via GitHub Actions.", tags: ["Semgrep", "Trivy", "ZAP"], img: CYBER_IMAGES.threatMap },
];

const MODULES = [
  { name: "Security Dashboard", desc: "Centralized threat posture & risk metrics" },
  { name: "Website Vulnerability Assessment", desc: "Passive HTTP/TLS/Header auditor" },
  { name: "IoT Device Monitoring", desc: "Network device discovery & inventory" },
  { name: "Network Traffic Analysis", desc: "Deep packet inspection & flow metrics" },
  { name: "Security Event Detection", desc: "Suricata IDS & system event logs" },
  { name: "AI/ML Anomaly Engine", desc: "Unsupervised Isolation Forest engine" },
  { name: "Risk Aggregator", desc: "Multi-vector threat aggregator" },
  { name: "AI Report Generator", desc: "Actionable executive & dev reports" },
  { name: "DevSecOps Security Gate", desc: "CI/CD pipeline policy enforcement" },
  { name: "Cloud Posture Guard", desc: "Infrastructure configuration check" },
];

const TECH_STACK = [
  { name: "React", category: "Frontend" },
  { name: "Vite", category: "Build Tool" },
  { name: "FastAPI", category: "Backend Engine" },
  { name: "MongoDB", category: "Database" },
  { name: "Python", category: "Core Runtime" },
  { name: "Gemini AI", category: "AI Engine" },
  { name: "GitHub Actions", category: "DevSecOps" },
  { name: "Suricata", category: "IDS Engine" }
];

export default function LandingPage() {
  const containerRef = useRef(null);
  const [scanUrl, setScanUrl] = useState("");
  const [isConfirmed, setIsConfirmed] = useState(false);
  const [showAuthModal, setShowAuthModal] = useState(false);

  // ==========================================
  // SCROLLCRAFT PARALLAX HOOKS
  // ==========================================
  const { scrollYProgress } = useScroll({
    target: containerRef,
    offset: ["start start", "end end"],
  });

  const smoothScroll = useSpring(scrollYProgress, {
    stiffness: 70,
    damping: 20,
    restDelta: 0.001,
  });

  const heroOpacity = useTransform(smoothScroll, [0, 0.15], [1, 0]);
  const heroScale = useTransform(smoothScroll, [0, 0.15], [1, 0.85]);
  const heroRotateX = useTransform(smoothScroll, [0, 0.15], [0, -15]);

  const imgBannerScale = useTransform(smoothScroll, [0.12, 0.35], [0.85, 1]);
  const imgBannerRotateX = useTransform(smoothScroll, [0.12, 0.35], [25, 0]);

  const dashRotateX = useTransform(smoothScroll, [0.28, 0.5], [35, 0]);
  const dashScale = useTransform(smoothScroll, [0.28, 0.5], [0.82, 1]);

  const handleScanSubmit = (e) => {
    e.preventDefault();
    if (!isConfirmed) {
      alert("Verification required: Please confirm permission before proceeding.");
      return;
    }
    setShowAuthModal(true);
  };

  return (
    <div
      ref={containerRef}
      className="relative min-h-screen bg-[#020617] text-slate-100 font-sans selection:bg-cyan-400 selection:text-slate-950 overflow-x-hidden"
    >
      {/* Background Interactive Scrollcraft Canvas */}
      <ScrollcraftCanvas scrollYProgress={smoothScroll} />

      {/* Top Scroll Indicator */}
      <motion.div
        style={{ scaleX: smoothScroll }}
        className="fixed top-0 left-0 right-0 z-50 h-1 origin-left bg-gradient-to-r from-cyan-400 via-emerald-400 to-indigo-500 shadow-[0_0_20px_rgba(6,182,212,1)]"
      />

      {/* HERO SECTION */}
      <section className="relative z-10 mx-auto max-w-7xl px-6 pt-24 pb-20 [perspective:1200px]">
        <motion.div
          style={{ opacity: heroOpacity, scale: heroScale, rotateX: heroRotateX }}
          className="grid grid-cols-1 items-center gap-12 lg:grid-cols-12 transform-gpu"
        >
          {/* Hero Left Content */}
          <div className="lg:col-span-7">
            <div className="inline-flex items-center gap-2 rounded-full border border-cyan-500/40 bg-cyan-950/30 px-4 py-1.5 font-mono text-xs text-cyan-300 backdrop-blur-xl shadow-[0_0_25px_rgba(6,182,212,0.25)]">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-500"></span>
              </span>
              AI-POWERED CYBER DEFENSE ENGINE
            </div>

            <h1 className="mt-6 text-4xl font-black leading-[1.1] tracking-tight text-white sm:text-6xl">
              Next-Gen Cyber Security &{" "}
              <span className="bg-gradient-to-r from-cyan-400 via-emerald-300 to-indigo-400 bg-clip-text text-transparent drop-shadow-[0_0_30px_rgba(6,182,212,0.4)]">
                Threat Telemetry
              </span>
            </h1>

            <p className="mt-6 text-base leading-relaxed text-slate-300 sm:text-lg">
              Automated perimeter auditing, ML anomaly detection, and explainable AI remediation built directly for modern DevSecOps architectures.
            </p>

            <div className="mt-8 flex flex-wrap gap-4">
              <a
                href="#scan-cta"
                className="group relative overflow-hidden rounded-xl bg-gradient-to-r from-cyan-500 via-teal-400 to-blue-600 p-[1px] shadow-lg shadow-cyan-500/30 transition-all hover:shadow-cyan-500/50 hover:scale-105"
              >
                <div className="flex items-center gap-2 rounded-xl bg-slate-950 px-6 py-3.5 font-mono text-xs font-bold text-cyan-300 transition-colors group-hover:bg-transparent group-hover:text-slate-950">
                  <span>[ INITIALIZE SECURITY AUDIT ]</span>
                  <ArrowRight size={16} className="transition-transform group-hover:translate-x-1" />
                </div>
              </a>
            </div>

            <div className="mt-10 grid grid-cols-1 gap-3 sm:grid-cols-2">
              {TRUST_POINTS.map((pt) => (
                <div key={pt} className="flex items-center gap-2.5 font-mono text-xs text-slate-300">
                  <CheckCircle2 size={15} className="shrink-0 text-cyan-400" />
                  <span>{pt}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Hero Right Interactive HUD Card */}
          <div className="lg:col-span-5">
            <InteractiveTiltCard className="rounded-2xl border border-cyan-500/40 bg-slate-900/80 p-3.5 shadow-[0_0_50px_rgba(6,182,212,0.2)] backdrop-blur-2xl">
              <div className="relative h-72 sm:h-80 w-full overflow-hidden rounded-xl border border-slate-800">
                <img src={CYBER_IMAGES.cyberCore} alt="Core Engine" className="h-full w-full object-cover" />
                <div className="absolute inset-0 bg-gradient-to-t from-[#020617] via-[#020617]/50 to-transparent" />

                {/* Animated HUD Overlay Elements */}
                <div className="absolute top-3 left-3 flex items-center gap-2 rounded-lg border border-cyan-500/40 bg-slate-950/90 px-3 py-1.5 backdrop-blur-md">
                  <Activity size={14} className="text-cyan-400 animate-pulse" />
                  <span className="font-mono text-[10px] font-bold text-cyan-300">ACTIVE IDS MONITOR</span>
                </div>

                <div className="absolute top-3 right-3 rounded-lg border border-emerald-500/40 bg-slate-950/90 px-2.5 py-1 font-mono text-[10px] text-emerald-400">
                  SYSTEM ONLINE
                </div>

                <div className="absolute bottom-4 left-4 right-4 rounded-xl border border-slate-800/90 bg-slate-950/90 p-4 backdrop-blur-xl font-mono text-xs">
                  <div className="flex items-center justify-between text-cyan-300">
                    <span className="flex items-center gap-1.5 font-bold">
                      <Terminal size={14} /> LIVE EVENT FEED
                    </span>
                    <span className="text-[10px] text-slate-400">PORT 443</span>
                  </div>
                  <p className="mt-2 text-[11px] text-slate-300 font-mono">
                    <span className="text-emerald-400">&gt; PASS:</span> TLS 1.3 Cipher Suite Verified
                  </p>
                  <p className="text-[11px] text-slate-400 font-mono">
                    <span className="text-amber-400">&gt; WARN:</span> HSTS Header Missing Max-Age
                  </p>
                </div>
              </div>
            </InteractiveTiltCard>
          </div>
        </motion.div>
      </section>

      {/* 3D SCROLLCRAFT CYBER BANNER */}
      <section className="relative z-20 mx-auto max-w-7xl px-6 py-12 [perspective:1200px]">
        <motion.div
          style={{ scale: imgBannerScale, rotateX: imgBannerRotateX }}
          className="relative overflow-hidden rounded-3xl border border-cyan-500/30 bg-slate-900/80 p-8 sm:p-12 shadow-[0_0_80px_rgba(6,182,212,0.15)] transform-gpu backdrop-blur-2xl"
        >
          <div className="absolute inset-0 -z-10 opacity-30">
            <img src={CYBER_IMAGES.threatMap} alt="Threat Grid" className="h-full w-full object-cover" />
            <div className="absolute inset-0 bg-gradient-to-r from-[#020617] via-[#020617]/80 to-transparent" />
          </div>

          <div className="max-w-2xl">
            <span className="font-mono text-xs font-bold text-cyan-400 tracking-widest">[ REALTIME THREAT MAP ]</span>
            <h2 className="mt-3 text-2xl sm:text-4xl font-extrabold text-white">Full Attack Surface Visibility</h2>
            <p className="mt-4 text-xs sm:text-sm text-slate-300 leading-relaxed font-mono">
              Aggregate microservice logs, network packet traces, and web exposure metrics inside a unified SOC dashboard.
            </p>
          </div>
        </motion.div>
      </section>

      {/* QUICK SCAN CTA SECTION WITH BEAM ANIMATION */}
      <section id="scan-cta" className="relative z-20 border-y border-slate-800/80 bg-slate-950/80 py-20 backdrop-blur-2xl">
        <div className="mx-auto max-w-4xl px-6">
          <div className="text-center">
            <span className="font-mono text-xs font-bold tracking-widest text-cyan-400">[ PERIMETER AUDIT GATEWAY ]</span>
            <h2 className="mt-2 text-2xl font-bold text-white sm:text-4xl">Start Authorized Asset Scan</h2>
          </div>

          <form onSubmit={handleScanSubmit} className="relative mt-8 overflow-hidden rounded-2xl border border-cyan-500/40 bg-slate-900/90 p-6 sm:p-8 shadow-2xl backdrop-blur-2xl">
            {/* Animated Laser Beam Visual */}
            <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-cyan-400 to-transparent animate-pulse" />

            <label className="block font-mono text-xs text-slate-300">Target Website Domain:</label>
            <div className="mt-2 flex flex-col gap-3 sm:flex-row">
              <div className="relative flex-1">
                <Globe size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  type="url"
                  required
                  placeholder="https://authorized-domain.com"
                  value={scanUrl}
                  onChange={(e) => setScanUrl(e.target.value)}
                  className="w-full rounded-xl border border-slate-700 bg-slate-950/90 py-3.5 pl-10 pr-4 font-mono text-xs text-slate-100 placeholder-slate-600 focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 focus:outline-none transition-all"
                />
              </div>
              <button
                type="submit"
                className="shrink-0 rounded-xl bg-cyan-400 px-6 py-3.5 font-mono text-xs font-bold text-slate-950 shadow-lg shadow-cyan-400/20 hover:bg-cyan-300 transition-colors"
              >
                [ Launch Scan ]
              </button>
            </div>

            <div className="mt-5 flex items-start gap-3 border-t border-slate-800/80 pt-4">
              <input
                type="checkbox"
                id="permissionCheck"
                checked={isConfirmed}
                onChange={(e) => setIsConfirmed(e.target.checked)}
                className="mt-0.5 h-4 w-4 rounded border-slate-700 bg-slate-950 text-cyan-400 focus:ring-cyan-400 cursor-pointer"
              />
              <label htmlFor="permissionCheck" className="font-mono text-xs text-slate-400 cursor-pointer">
                I confirm explicit legal ownership or written authorization to perform passive security evaluation on this domain.
              </label>
            </div>
          </form>
        </div>
      </section>

      {/* 3D DASHBOARD PREVIEW */}
      <section className="relative z-20 mx-auto max-w-7xl px-6 py-28 [perspective:1200px]">
        <div className="text-center">
          <span className="font-mono text-xs font-bold tracking-widest text-cyan-400">[ COMMAND CENTER ]</span>
          <h2 className="mt-2 text-3xl font-extrabold text-white sm:text-4xl">Security Command Console</h2>
        </div>

        <motion.div
          style={{ rotateX: dashRotateX, scale: dashScale }}
          className="mt-16 rounded-2xl border border-cyan-500/40 bg-slate-900/90 p-6 shadow-[0_0_100px_rgba(6,182,212,0.15)] backdrop-blur-2xl sm:p-8 transform-gpu"
        >
          <div className="flex flex-col gap-4 border-b border-slate-800 pb-5 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-center gap-2 font-mono text-xs text-slate-200">
              <Terminal size={18} className="text-cyan-400" />
              <span className="font-bold">SYSTEM THREAT POSTURE</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-emerald-400 animate-ping" />
              <span className="rounded bg-emerald-500/20 px-2.5 py-1 font-mono text-xs text-emerald-400">STATUS: PROTECTED</span>
            </div>
          </div>

          <div className="mt-8 grid grid-cols-1 gap-8 lg:grid-cols-12">
            <div className="lg:col-span-5 space-y-6">
              <div className="grid grid-cols-2 gap-4">
                <div className="rounded-xl border border-slate-800 bg-slate-950/90 p-4">
                  <span className="font-mono text-[10px] text-slate-400">SECURITY POSTURE</span>
                  <p className="mt-1 font-mono text-3xl font-black text-cyan-400">88/100</p>
                </div>
                <div className="rounded-xl border border-amber-500/30 bg-amber-950/20 p-4">
                  <span className="font-mono text-[10px] text-slate-400">RISK INDEX</span>
                  <p className="mt-1 font-mono text-2xl font-bold text-amber-400">Low Risk</p>
                </div>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950/90 p-4 font-mono text-xs">
                <div className="flex items-center justify-between text-slate-400">
                  <span>TELEMETRY GRAPH</span>
                  <TrendingUp size={14} className="text-cyan-400" />
                </div>
                <div className="mt-4 flex h-24 items-end justify-between gap-2 border-b border-slate-800 pb-2">
                  {[40, 55, 68, 62, 78, 88].map((val, idx) => (
                    <div key={idx} className="flex flex-1 flex-col items-center gap-1">
                      <div style={{ height: `${val}%` }} className="w-full rounded-t bg-gradient-to-t from-cyan-600 to-cyan-400" />
                      <span className="text-[9px] text-slate-500">T{idx + 1}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="lg:col-span-7 space-y-3 font-mono text-xs">
              <span className="text-slate-400 text-[11px] uppercase tracking-wider">LIVE TELEMETRY FEED</span>

              <div className="space-y-3">
                <div className="flex items-center justify-between rounded-xl border border-emerald-500/30 bg-emerald-950/20 p-3.5">
                  <div className="flex items-center gap-3">
                    <span className="rounded bg-emerald-500/20 px-2 py-0.5 text-[10px] font-bold text-emerald-400">SECURE</span>
                    <span className="text-slate-200">SSL/TLS Certificate Chain Valid</span>
                  </div>
                  <span className="text-[10px] text-slate-500">Port 443</span>
                </div>

                <div className="flex items-center justify-between rounded-xl border border-amber-500/30 bg-amber-950/20 p-3.5">
                  <div className="flex items-center gap-3">
                    <span className="rounded bg-amber-500/20 px-2 py-0.5 text-[10px] font-bold text-amber-400">WARN</span>
                    <span className="text-slate-200">Content-Security-Policy Header Missing</span>
                  </div>
                  <span className="text-[10px] text-slate-500">HTTP Audit</span>
                </div>
              </div>
            </div>
          </div>
        </motion.div>
      </section>

      {/* HOW IT WORKS PIPELINE */}
      <section className="relative z-20 mx-auto max-w-7xl px-6 py-24">
        <div className="text-center">
          <span className="font-mono text-xs font-bold tracking-widest text-cyan-400">[ WORKFLOW ]</span>
          <h2 className="mt-2 text-3xl font-extrabold text-white sm:text-4xl">Security Assessment Pipeline</h2>
        </div>

        <div className="mt-16 grid grid-cols-1 gap-6 md:grid-cols-3 lg:grid-cols-5">
          {HOW_IT_WORKS.map((hw) => (
            <div
              key={hw.step}
              className="flex flex-col justify-between rounded-2xl border border-slate-800/80 bg-slate-900/60 p-5 backdrop-blur-md hover:border-cyan-500/40 transition-colors"
            >
              <div>
                <span className="font-mono text-2xl font-black text-cyan-400">{hw.step}</span>
                <h3 className="mt-3 font-mono text-sm font-bold text-white">{hw.title}</h3>
                <p className="mt-2 text-xs leading-relaxed text-slate-400">{hw.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* FEATURE CARDS WITH HOVER LIGHTING */}
      <section className="relative z-20 border-t border-slate-800/80 bg-slate-950/40 py-24">
        <div className="mx-auto max-w-7xl px-6">
          <div className="text-center">
            <span className="font-mono text-xs font-bold tracking-widest text-purple-400">[ CAPABILITIES ]</span>
            <h2 className="mt-2 text-3xl font-extrabold text-white sm:text-4xl">Engine Modules</h2>
          </div>

          <div className="mt-16 grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3">
            {FEATURES.map((f) => {
              const IconComp = f.icon;
              return (
                <InteractiveTiltCard
                  key={f.id}
                  className="group relative overflow-hidden rounded-2xl border border-slate-800/90 bg-slate-900/80 p-6 backdrop-blur-xl hover:border-cyan-500/50 transition-all"
                >
                  <div className="absolute inset-0 -z-10 opacity-10 transition-opacity duration-500 group-hover:opacity-25">
                    <img src={f.img} alt={f.title} className="h-full w-full object-cover" />
                  </div>

                  <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-cyan-500/30 bg-cyan-950/50 text-cyan-400">
                    <IconComp size={22} />
                  </div>
                  <h3 className="mt-5 font-mono text-base font-bold text-white">{f.title}</h3>
                  <p className="mt-3 text-xs leading-relaxed text-slate-400">{f.desc}</p>
                  <div className="mt-6 flex flex-wrap gap-1.5">
                    {f.tags.map((t) => (
                      <span key={t} className="rounded border border-slate-800 bg-slate-950/80 px-2 py-0.5 font-mono text-[10px] text-slate-400">
                        {t}
                      </span>
                    ))}
                  </div>
                </InteractiveTiltCard>
              );
            })}
          </div>
        </div>
      </section>

      {/* MODULES GRID */}
      <section className="relative z-20 border-t border-slate-800/80 bg-slate-950/60 py-24">
        <div className="mx-auto max-w-7xl px-6">
          <div className="text-center">
            <span className="font-mono text-xs font-bold tracking-widest text-cyan-400">[ PLATFORM SPEC ]</span>
            <h2 className="mt-2 text-3xl font-extrabold text-white sm:text-4xl">10 Integrated Subsystems</h2>
          </div>

          <div className="mt-16 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
            {MODULES.map((m, idx) => (
              <div key={m.name} className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 hover:border-cyan-500/40 transition-colors">
                <span className="font-mono text-[10px] text-cyan-400">SUB_0{idx + 1}</span>
                <h3 className="mt-2 font-mono text-xs font-bold text-slate-200">✓ {m.name}</h3>
                <p className="mt-2 text-[11px] text-slate-400">{m.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* TECH STACK CHIPS */}
      <section className="relative z-20 mx-auto max-w-7xl px-6 py-20">
        <div className="flex flex-wrap justify-center gap-3">
          {TECH_STACK.map((st) => (
            <div key={st.name} className="flex items-center gap-2 rounded-xl border border-slate-800 bg-slate-900/80 px-4 py-2 font-mono text-xs">
              <Code2 size={14} className="text-cyan-400" />
              <span className="font-bold text-white">{st.name}</span>
            </div>
          ))}
        </div>
      </section>

      {/* AUTH MODAL */}
      {showAuthModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-md p-4">
          <div className="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-900 p-6 text-center font-mono">
            <Lock size={32} className="mx-auto text-cyan-400" />
            <h3 className="mt-4 text-lg font-bold text-white">Authentication Gateway</h3>
            <p className="mt-2 text-xs text-slate-400">Security scan requested for:</p>
            <p className="mt-1 text-xs text-cyan-400 font-bold break-all">{scanUrl}</p>
            <button
              onClick={() => setShowAuthModal(false)}
              className="mt-6 rounded-lg bg-cyan-400 px-5 py-2.5 text-xs font-bold text-slate-950 hover:bg-cyan-300"
            >
              Close
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// ==========================================
// INTERACTIVE 3D TILT CARD COMPONENT
// ==========================================
function InteractiveTiltCard({ children, className }) {
  const x = useMotionValue(0);
  const y = useMotionValue(0);

  const rotateX = useTransform(y, [-100, 100], [10, -10]);
  const rotateY = useTransform(x, [-100, 100], [-10, 10]);

  const handleMouseMove = (e) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const width = rect.width;
    const height = rect.height;
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;
    x.set(mouseX - width / 2);
    y.set(mouseY - height / 2);
  };

  const handleMouseLeave = () => {
    x.set(0);
    y.set(0);
  };

  return (
    <motion.div
      style={{ rotateX, rotateY, transformStyle: "preserve-3d" }}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      className={className}
    >
      {children}
    </motion.div>
  );
}

// ==========================================
// SCROLLCRAFT DYNAMIC CANVAS BACKGROUND
// ==========================================
function ScrollcraftCanvas({ scrollYProgress }) {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");

    let animationFrameId;
    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    const handleResize = () => {
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };

    window.addEventListener("resize", handleResize);

    const particleCount = Math.floor((width * height) / 20000);
    const particles = Array.from({ length: particleCount }, () => ({
      x: Math.random() * width,
      y: Math.random() * height,
      z: Math.random() * 2 + 0.5,
      vx: (Math.random() - 0.5) * 0.5,
      vy: (Math.random() - 0.5) * 0.5,
      size: Math.random() * 2 + 0.5,
    }));

    const render = () => {
      ctx.clearRect(0, 0, width, height);
      const scrollVal = scrollYProgress.get();

      // Dynamic Grid Lines
      ctx.strokeStyle = `rgba(6, 182, 212, ${0.03 + scrollVal * 0.03})`;
      ctx.lineWidth = 1;
      const gridSize = 60;

      for (let x = 0; x < width; x += gridSize) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
        ctx.stroke();
      }
      for (let y = 0; y < height; y += gridSize) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
      }

      // Animated Particles
      particles.forEach((p) => {
        p.x += p.vx * p.z;
        p.y += p.vy * p.z + scrollVal * 0.4;

        if (p.x < 0) p.x = width;
        if (p.x > width) p.x = 0;
        if (p.y < 0) p.y = height;
        if (p.y > height) p.y = 0;

        ctx.fillStyle = scrollVal > 0.4 ? "#818cf8" : "#06b6d4";
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.size * p.z, 0, Math.PI * 2);
        ctx.fill();
      });

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      window.removeEventListener("resize", handleResize);
      cancelAnimationFrame(animationFrameId);
    };
  }, [scrollYProgress]);

  return (
    <div className="pointer-events-none fixed inset-0 z-0 bg-[#020617]">
      <div className="absolute top-1/4 left-1/2 h-[600px] w-[600px] -translate-x-1/2 -translate-y-1/2 rounded-full bg-cyan-500/10 blur-[180px]" />
      <div className="absolute bottom-1/4 right-10 h-[500px] w-[500px] rounded-full bg-indigo-600/10 blur-[180px]" />
      <canvas ref={canvasRef} className="block h-full w-full opacity-70" />
    </div>
  );
}