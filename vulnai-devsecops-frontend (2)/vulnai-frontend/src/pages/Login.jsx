import React, { useState, useEffect, useRef } from "react";
import { useNavigate, Link } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { 
  ShieldHalf, 
  Mail, 
  Lock, 
  User, 
  ArrowRight, 
  ScanEye, 
  X, 
  Terminal, 
  Cpu, 
  AlertTriangle,
  Timer,
  Lock as LockIcon,
  Activity,
  Fingerprint,
  Zap,
  KeyRound,
  UserPlus,
  Radio,
  Sparkles,
  CheckCircle2
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import api from "../lib/api";

const LOG_MESSAGES = [
  "[SYS_INIT]: QUANTUM_ENCRYPTION_ACTIVE",
  "[PORT_SCAN]: ANALYZING_THREAT_VECTORS...",
  "[FIREWALL]: ZERO_TRUST_RULESET_LOADED",
  "[AI_ENGINE]: CORRELATING_CVE_DATABASE..."
];

function formatAuthError(error) {
  const detail = error?.data?.detail;
  if (Array.isArray(detail)) {
    return detail.map((issue) => {
      const field = Array.isArray(issue.loc)
        ? issue.loc.filter((part) => part !== "body").join(".")
        : "";
      return [field, issue.msg || "Invalid value"].filter(Boolean).join(": ");
    }).join("; ");
  }
  if (typeof detail === "string") return detail;
  if (detail && typeof detail === "object") {
    return detail.message || detail.error || "Authentication request failed.";
  }
  return error?.message || "Authentication request failed.";
}

export default function Login() {
  const [mode, setMode] = useState("login"); // "login" | "register"
  const [direction, setDirection] = useState(1);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [error, setError] = useState("");

  // Rate Limiting (5 Attempts -> 5 Mins Lockout)
  const [attempts, setAttempts] = useState(0);
  const [lockoutTime, setLockoutTime] = useState(0);

  // Typewriter Log Effect State
  const [currentLogIndex, setCurrentLogIndex] = useState(0);

  const { login } = useAuth();
  const navigate = useNavigate();
  const canvasRef = useRef(null);

  // 1. Lockout Timer Countdown
  useEffect(() => {
    let timerInterval = null;
    if (lockoutTime > 0) {
      timerInterval = setInterval(() => {
        setLockoutTime((prev) => {
          if (prev <= 1) {
            setAttempts(0);
            return 0;
          }
          return prev - 1;
        });
      }, 1000);
    }
    return () => clearInterval(timerInterval);
  }, [lockoutTime]);

  // 2. Cycling Cyber Terminal Log Messages
  useEffect(() => {
    const logInterval = setInterval(() => {
      setCurrentLogIndex((prev) => (prev + 1) % LOG_MESSAGES.length);
    }, 3500);
    return () => clearInterval(logInterval);
  }, []);

  // 3. High-Tech Cyber Grid & Cursor Trail Canvas Effect
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    let animationFrameId;
    let particles = [];

    const resizeCanvas = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    };
    resizeCanvas();
    window.addEventListener("resize", resizeCanvas);

    class Particle {
      constructor(x, y) {
        this.x = x;
        this.y = y;
        this.size = Math.random() * 2 + 0.8;
        this.speedX = (Math.random() - 0.5) * 1.5;
        this.speedY = (Math.random() - 0.5) * 1.5;
        this.life = 1;
        this.decay = Math.random() * 0.02 + 0.008;
      }
      update() {
        this.x += this.speedX;
        this.y += this.speedY;
        this.life -= this.decay;
      }
      draw() {
        ctx.fillStyle = mode === "login" 
          ? `rgba(16, 185, 129, ${this.life * 0.8})` 
          : `rgba(6, 182, 212, ${this.life * 0.8})`;
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
        ctx.fill();
      }
    }

    const handleMouseMove = (e) => {
      for (let i = 0; i < 2; i++) {
        particles.push(new Particle(e.clientX, e.clientY));
      }
    };

    window.addEventListener("mousemove", handleMouseMove);

    const render = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      particles.forEach((particle, index) => {
        particle.update();
        particle.draw();
        if (particle.life <= 0) particles.splice(index, 1);
      });
      animationFrameId = requestAnimationFrame(render);
    };
    render();

    return () => {
      window.removeEventListener("resize", resizeCanvas);
      window.removeEventListener("mousemove", handleMouseMove);
      cancelAnimationFrame(animationFrameId);
    };
  }, [mode]);

  const formatTime = (seconds) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  };

  const handleModeSwitch = (newMode) => {
    if (newMode === mode || lockoutTime > 0) return;
    setDirection(newMode === "register" ? 1 : -1);
    setMode(newMode);
    setError("");
  };

  async function handleSubmit(e) {
    e.preventDefault();
    if (lockoutTime > 0) return;

    if (!email || !password || password.length < 8 || (mode === "register" && !name)) {
      const nextAttempts = attempts + 1;
      setAttempts(nextAttempts);

      if (nextAttempts >= 5) {
        setLockoutTime(300); // 5 Mins Lockout
        setError("SECURITY_ALERT: Maximum failed attempts reached! Lockout initiated.");
      } else {
        setError(`AUTH_ERROR: Email, name, and password (8+ characters) are required. (${5 - nextAttempts} attempts remaining)`);
      }
      return;
    }

    try {
      setError("");
      if (mode === "register") {
        await api.post("/auth/register", { name, email, password });
      }
      await login(email, password);
      navigate("/dashboard");
    } catch (err) {
      setError(`AUTH_ERROR: ${formatAuthError(err)}`);
    }
  }

  const formVariants = {
    initial: (dir) => ({
      opacity: 0,
      x: dir > 0 ? 60 : -60,
      filter: "blur(6px)",
    }),
    animate: {
      opacity: 1,
      x: 0,
      filter: "blur(0px)",
      transition: { duration: 0.35, ease: "easeOut" }
    },
    exit: (dir) => ({
      opacity: 0,
      x: dir > 0 ? -60 : 60,
      filter: "blur(6px)",
      transition: { duration: 0.25, ease: "easeIn" }
    })
  };

  return (
    <div className="relative flex min-h-screen items-center justify-center bg-[#020617] p-4 sm:p-6 text-slate-100 overflow-hidden font-sans selection:bg-emerald-500 selection:text-slate-950">
      
      {/* Cyber Grid Pattern */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#0f172a20_1px,transparent_1px),linear-gradient(to_bottom,#0f172a20_1px,transparent_1px)] bg-[size:3.5rem_3.5rem] [mask-image:radial-gradient(ellipse_70%_60%_at_50%_50%,#000_80%,transparent_100%)] pointer-events-none" />

      {/* Interactive Cursor Canvas */}
      <canvas ref={canvasRef} className="absolute inset-0 pointer-events-none z-0" />

      {/* Ambient Cyber Orbs */}
      <div className={`absolute top-1/4 left-1/3 -translate-x-1/2 w-[700px] h-[350px] blur-[160px] pointer-events-none rounded-full transition-colors duration-700 ${mode === 'login' ? 'bg-emerald-500/15' : 'bg-cyan-500/15'}`} />
      <div className="absolute bottom-10 right-10 w-[450px] h-[450px] bg-cyan-500/10 blur-[140px] pointer-events-none rounded-full" />

      {/* MAIN TRANSPARENT GLASS CARD CONTAINER */}
      <motion.div 
        initial={{ opacity: 0, scale: 0.94, y: 15 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        transition={{ duration: 0.45, ease: "easeOut" }}
        className="relative z-10 grid w-full max-w-4xl grid-cols-1 border border-emerald-500/30 bg-slate-950/40 backdrop-blur-3xl rounded-3xl shadow-[0_0_80px_rgba(16,185,129,0.15)] lg:grid-cols-5 overflow-hidden ring-1 ring-white/10"
      >
        
        {/* TOP RIGHT CLOSE BUTTON */}
        <Link 
          to="/" 
          className="absolute top-5 right-5 z-50 p-2.5 rounded-xl bg-slate-900/80 border border-slate-800 text-slate-400 hover:text-emerald-400 hover:border-emerald-500/50 hover:bg-slate-900 transition-all group backdrop-blur-md"
          aria-label="Close Console"
        >
          <X size={18} className="group-hover:rotate-90 transition-transform duration-300" />
        </Link>

        {/* LEFT PANEL: Security Operations Center HUD */}
        <div className="hidden flex-col justify-between border-r border-slate-800/80 bg-slate-950/50 p-8 lg:col-span-2 lg:flex relative overflow-hidden backdrop-blur-md">
          
          <div className="space-y-6">
            {/* Brand Title */}
            <div className="flex items-center gap-3">
              <div className={`flex h-11 w-11 items-center justify-center rounded-xl border transition-all duration-500 ${mode === 'login' ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-400 shadow-[0_0_20px_rgba(16,185,129,0.25)]' : 'bg-cyan-500/10 border-cyan-500/40 text-cyan-400 shadow-[0_0_20px_rgba(6,182,212,0.25)]'}`}>
                <ShieldHalf size={24} strokeWidth={2} />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-display text-xl font-extrabold tracking-wider text-slate-100">VULNAI</span>
                  <span className="px-1.5 py-0.5 text-[9px] font-mono font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 rounded uppercase">SOC</span>
                </div>
                <span className="block text-[10px] font-mono tracking-widest text-emerald-400/90 uppercase">DevSecOps Engine</span>
              </div>
            </div>

            {/* Dynamic Text Switching */}
            <AnimatePresence mode="wait">
              <motion.div
                key={mode}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                transition={{ duration: 0.2 }}
                className="space-y-3"
              >
                <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-slate-900/80 border border-slate-800 text-[10px] font-mono text-emerald-400 uppercase tracking-widest">
                  <Radio size={12} className="animate-pulse text-emerald-400" />
                  <span>{mode === "login" ? "Gateway Active" : "Provisioning Agent"}</span>
                </div>
                
                <h2 className="text-2xl font-bold text-slate-100 leading-snug">
                  {mode === "login" 
                    ? "Unified Attack Surface Telemetry" 
                    : "Zero-Trust Account Setup"}
                </h2>
                
                <p className="text-xs text-slate-400 leading-relaxed font-sans">
                  {mode === "login"
                    ? "Real-time vulnerability correlation, automated scans, and AI-explained risk assessments."
                    : "Initialize an authorized operator profile to start scanning target assets."}
                </p>
              </motion.div>
            </AnimatePresence>
          </div>

          {/* Animated Diagnostics Terminal Card */}
          <div className="mt-6 rounded-2xl border border-slate-800/80 bg-slate-950/80 p-4 font-mono space-y-3 relative overflow-hidden backdrop-blur-md shadow-inner">
            <div className="flex items-center justify-between text-[11px] text-slate-400 border-b border-slate-900 pb-2">
              <span className="flex items-center gap-1.5 text-emerald-400 font-bold">
                <Terminal size={12} /> SEC_DIAGNOSTICS.LOG
              </span>
              <span className="text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 px-2 py-0.5 rounded font-mono">200 OK</span>
            </div>

            <div className="space-y-2 text-[11px]">
              <AnimatePresence mode="wait">
                <motion.p 
                  key={currentLogIndex}
                  initial={{ opacity: 0, x: -5 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: 5 }}
                  transition={{ duration: 0.25 }}
                  className="text-slate-300 flex items-center gap-1.5"
                >
                  <Activity size={12} className="text-emerald-400 shrink-0 animate-pulse" />
                  <span className="truncate">{LOG_MESSAGES[currentLogIndex]}</span>
                </motion.p>
              </AnimatePresence>

              <div className="h-1.5 w-full bg-slate-900 rounded-full overflow-hidden border border-slate-800/80">
                <motion.div 
                  animate={{ x: ["-100%", "100%"] }}
                  transition={{ repeat: Infinity, duration: 1.8, ease: "linear" }}
                  className="h-full w-1/3 bg-gradient-to-r from-transparent via-emerald-400 to-transparent"
                />
              </div>
            </div>

            <div className="flex items-center justify-between pt-2 text-[10px] border-t border-slate-900">
              <span className="text-amber-400 font-bold flex items-center gap-1">
                <Zap size={11} /> CVE-2026-X801
              </span>
              <span className="text-slate-500">Confidence 96%</span>
            </div>
          </div>

        </div>

        {/* RIGHT PANEL: Form & Capsule Switcher */}
        <div className="col-span-1 p-8 sm:p-10 lg:col-span-3 flex flex-col justify-center bg-slate-900/20 backdrop-blur-md relative">
          
          {/* Mobile View Title */}
          <div className="mb-6 flex items-center gap-2.5 lg:hidden">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
              <ShieldHalf size={18} />
            </div>
            <span className="font-display text-base font-bold text-slate-100">VULNAI SOC</span>
          </div>

          {/* FUTURISTIC SEGMENTED CAPSULE SWITCHER */}
          <div className="mb-8 p-1.5 rounded-2xl bg-slate-950/80 border border-slate-800/80 backdrop-blur-lg flex items-center justify-between relative shadow-inner">
            {[
              { id: "login", label: "01 // SYSTEM LOGIN", icon: KeyRound },
              { id: "register", label: "02 // REGISTER ACCESS", icon: UserPlus }
            ].map((tab) => {
              const IconComponent = tab.icon;
              const isActive = mode === tab.id;
              
              return (
                <button
                  key={tab.id}
                  disabled={lockoutTime > 0}
                  onClick={() => handleModeSwitch(tab.id)}
                  className={`relative flex-1 py-3 px-3 rounded-xl text-xs font-mono transition-all flex items-center justify-center gap-2 z-10 ${
                    isActive 
                      ? "text-slate-950 font-bold" 
                      : "text-slate-400 hover:text-slate-200"
                  } ${lockoutTime > 0 ? "opacity-50 cursor-not-allowed" : ""}`}
                >
                  <IconComponent size={15} className={isActive ? "text-slate-950" : "text-slate-500"} />
                  <span className="tracking-wider">{tab.label}</span>

                  {/* Animated Capsule Background Glow */}
                  {isActive && (
                    <motion.div
                      layoutId="activeTabPill"
                      transition={{ type: "spring", stiffness: 400, damping: 30 }}
                      className="absolute inset-0 bg-emerald-400 rounded-xl shadow-[0_0_20px_rgba(16,185,129,0.5)] -z-10"
                    />
                  )}
                </button>
              );
            })}
          </div>

          {/* DIRECTIONAL FORM SLIDE ANIMATION */}
          <AnimatePresence mode="wait" custom={direction}>
            <motion.div
              key={mode}
              custom={direction}
              variants={formVariants}
              initial="initial"
              animate="animate"
              exit="exit"
            >
              {/* Header Text */}
              <div className="space-y-1 mb-6">
                <h3 className="text-2xl font-bold text-slate-100 flex items-center gap-2">
                  {mode === "login" ? "Authenticate Session" : "Provision Security Key"}
                  <Fingerprint size={20} className="text-emerald-400" />
                </h3>
                <p className="text-xs text-slate-400">
                  {mode === "login" 
                    ? "Enter authorized credentials to proceed to the console." 
                    : "Setup operator parameters to evaluate authorized targets."}
                </p>
              </div>

              {/* 5-MIN LOCKOUT BANNER */}
              {lockoutTime > 0 && (
                <motion.div 
                  initial={{ opacity: 0, scale: 0.95 }}
                  animate={{ opacity: 1, scale: 1 }}
                  className="mb-6 p-4 rounded-2xl bg-amber-500/10 border border-amber-500/30 text-amber-400 space-y-2 backdrop-blur-md"
                >
                  <div className="flex items-center justify-between font-mono text-xs font-bold">
                    <span className="flex items-center gap-2">
                      <LockIcon size={16} className="animate-bounce" /> SYSTEM LOCKED
                    </span>
                    <span className="flex items-center gap-1 text-sm bg-amber-500/20 px-2.5 py-0.5 rounded-lg border border-amber-500/30">
                      <Timer size={14} /> {formatTime(lockoutTime)}
                    </span>
                  </div>
                  <p className="text-[11px] text-amber-300/80 leading-relaxed font-sans">
                    Maximum failed attempts threshold reached (5/5). Cooldown protocol active. Please wait for the timer to expire.
                  </p>
                </motion.div>
              )}

              {/* Input Form Controls */}
              <form onSubmit={handleSubmit} className="space-y-4">
                {mode === "login" && (
                  <div className="flex items-center justify-between p-2.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-xs">
                    <div className="flex items-center gap-2 text-emerald-300">
                      <Sparkles size={14} className="text-emerald-400 shrink-0" />
                      <span className="font-mono text-[11px]">
                        Demo: <strong className="text-white">student@example.com</strong> / <strong className="text-white">abikrishna</strong>
                      </span>
                    </div>
                    <button
                      type="button"
                      onClick={() => {
                        setEmail("student@example.com");
                        setPassword("abikrishna");
                        setError("");
                      }}
                      className="px-2.5 py-1 rounded-lg bg-emerald-500 text-slate-950 font-bold text-[10px] uppercase font-mono hover:bg-emerald-400 transition-all shadow-sm cursor-pointer"
                    >
                      Auto-Fill
                    </button>
                  </div>
                )}

                {mode === "register" && (
                  <Field 
                    icon={User} 
                    label="Operator Name" 
                    value={name} 
                    onChange={setName} 
                    disabled={lockoutTime > 0}
                    placeholder="e.g. MRA Security Operator" 
                  />
                )}

                <Field 
                  icon={Mail} 
                  label="Corporate Email" 
                  value={email} 
                  onChange={setEmail} 
                  disabled={lockoutTime > 0}
                  placeholder="operator@vulnai.io" 
                  type="email" 
                />
                
                <Field 
                  icon={Lock} 
                  label="Access Password" 
                  value={password} 
                  onChange={setPassword} 
                  disabled={lockoutTime > 0}
                  placeholder="••••••••••••" 
                  type="password" 
                />

                {/* Error Banner */}
                {error && lockoutTime === 0 && (
                  <motion.div 
                    initial={{ opacity: 0, y: 5 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-xs font-mono text-red-400 flex items-center gap-2"
                  >
                    <AlertTriangle size={15} className="shrink-0" />
                    <span>{error}</span>
                  </motion.div>
                )}

                {/* Action Button */}
                <motion.button
                  whileHover={{ scale: lockoutTime > 0 ? 1 : 1.01 }}
                  whileTap={{ scale: lockoutTime > 0 ? 1 : 0.98 }}
                  disabled={lockoutTime > 0}
                  type="submit"
                  className={`w-full py-3.5 px-4 rounded-xl font-bold text-sm transition-all flex items-center justify-center gap-2 mt-3 group ${
                    lockoutTime > 0 
                      ? "bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700" 
                      : "bg-emerald-500 hover:bg-emerald-400 text-slate-950 shadow-[0_0_25px_rgba(16,185,129,0.35)] hover:shadow-[0_0_35px_rgba(16,185,129,0.5)]"
                  }`}
                >
                  <span>
                    {lockoutTime > 0 
                      ? "Gateway Locked" 
                      : mode === "login" ? "Initialize Gateway" : "Provision Operator Key"}
                  </span>
                  {lockoutTime === 0 && (
                    <ArrowRight size={16} className="group-hover:translate-x-1 transition-transform" />
                  )}
                </motion.button>
              </form>
            </motion.div>
          </AnimatePresence>

          {/* Compliance Protocol Note */}
          <div className="mt-6 flex items-start gap-2.5 rounded-xl border border-slate-800/80 bg-slate-950/60 p-3.5 backdrop-blur-sm">
            <ScanEye size={16} className="mt-0.5 shrink-0 text-emerald-400" />
            <p className="text-[11px] leading-relaxed text-slate-400">
              <strong className="text-slate-300">Compliance Protocol:</strong> Active security telemetry strictly applies to endpoints under direct ownership or explicit authorization.
            </p>
          </div>

        </div>
      </motion.div>
    </div>
  );
}

function Field({ icon: Icon, label, value, onChange, placeholder, disabled, type = "text" }) {
  return (
    <label className="block space-y-1.5">
      <div className="flex items-center justify-between">
        <span className="block text-[11px] font-mono text-slate-400 uppercase tracking-wider">{label}</span>
        <span className="text-[9px] font-mono text-emerald-500/70 uppercase flex items-center gap-1">
          <CheckCircle2 size={10} /> SEC_VERIFIED
        </span>
      </div>
      <div className="relative">
        <Icon size={16} className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" />
        <input
          type={type}
          disabled={disabled}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          className="w-full rounded-xl border border-slate-800/80 bg-slate-950/80 py-2.5 pl-10 pr-3.5 text-sm text-slate-100 placeholder:text-slate-600 focus:border-emerald-500 focus:bg-slate-950 focus:outline-none focus:ring-1 focus:ring-emerald-500 transition-all disabled:opacity-40 disabled:cursor-not-allowed font-sans"
        />
      </div>
    </label>
  );
}