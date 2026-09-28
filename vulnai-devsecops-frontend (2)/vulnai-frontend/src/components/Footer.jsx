import { Link } from "react-router-dom";
import { 
  ShieldHalf, 
  Code, 
  Terminal, 
  ShieldAlert, 
  ArrowUpRight, 
  Lock, 
  Cpu, 
  Activity, 
  ExternalLink 
} from "lucide-react";

export default function Footer() {
  return (
    <footer className="border-t border-emerald-500/20 bg-slate-950/95 backdrop-blur-xl relative overflow-hidden text-slate-300">
      {/* Decorative Cybernetic Background Elements */}
      <div className="absolute top-0 left-1/4 w-96 h-96 bg-emerald-500/5 blur-[120px] pointer-events-none rounded-full" />
      <div className="absolute bottom-0 right-1/4 w-80 h-80 bg-cyan-500/5 blur-[100px] pointer-events-none rounded-full" />
      <div className="absolute top-0 left-0 right-0 h-[1px] bg-gradient-to-r from-transparent via-emerald-500/40 to-transparent" />

      <div className="mx-auto max-w-7xl px-6 py-14 lg:px-8 relative z-10">
        <div className="grid grid-cols-1 gap-12 lg:grid-cols-12">
          
          {/* Brand & Platform Mission (Col 1-5) */}
          <div className="lg:col-span-5 space-y-5">
            <Link to="/" className="flex items-center gap-3 group w-fit">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-emerald-500/20 to-slate-900 border border-emerald-500/40 text-emerald-400 group-hover:border-emerald-400 group-hover:scale-105 transition-all shadow-[0_0_20px_rgba(16,185,129,0.2)]">
                <ShieldHalf size={20} strokeWidth={2} />
              </div>
              <div className="leading-tight">
                <div className="flex items-center gap-2">
                  <span className="font-display text-xl font-extrabold tracking-wider text-slate-100">VULNAI</span>
                  <span className="px-1.5 py-0.5 text-[9px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 rounded uppercase">AI Core</span>
                </div>
                <span className="block text-[10px] font-mono tracking-widest text-slate-400 uppercase">DevSecOps Intelligence</span>
              </div>
            </Link>

            <p className="max-w-md text-sm leading-relaxed text-slate-400 font-sans">
              Next-generation AI-assisted web vulnerability assessment, real-time security telemetry, and automated risk-correlation pipeline for modern DevSecOps workflows.
            </p>

            {/* Live Status Badge Grid */}
            <div className="flex flex-wrap items-center gap-3 pt-1">
              <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900/80 border border-slate-800 text-xs font-mono text-slate-300 shadow-inner">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                </span>
                <span>Engine: <strong className="text-emerald-400">Online</strong></span>
              </div>

              <div className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900/80 border border-slate-800 text-xs font-mono text-slate-400">
                <Cpu size={13} className="text-cyan-400" />
                <span>Model v2.4</span>
              </div>
            </div>
          </div>

          {/* Quick Navigation (Col 6-8) */}
          <div className="lg:col-span-3 space-y-4">
            <p className="text-xs font-mono font-bold text-emerald-400 uppercase tracking-widest flex items-center gap-2">
              <Activity size={14} /> Navigation
            </p>
            <ul className="grid grid-cols-1 gap-2.5 text-sm">
              {[
                { to: "/", label: "Home" },
                { to: "/features", label: "Features" },
                { to: "/how-it-works", label: "How It Works" },
                { to: "/modules", label: "Modules" },
                { to: "/about", label: "About Project" },
              ].map((link) => (
                <li key={link.to}>
                  <Link 
                    to={link.to} 
                    className="text-slate-400 hover:text-emerald-400 transition-all duration-200 flex items-center justify-between group py-1 border-b border-slate-900/50 hover:border-emerald-500/30"
                  >
                    <span>{link.label}</span>
                    <ArrowUpRight size={14} className="opacity-0 -translate-x-2 group-hover:opacity-100 group-hover:translate-x-0 transition-all text-emerald-400" />
                  </Link>
                </li>
              ))}
            </ul>
          </div>

          {/* Ethics & Legal Guidelines Card (Col 9-12) */}
          <div className="lg:col-span-4 space-y-4">
            <p className="text-xs font-mono font-bold text-emerald-400 uppercase tracking-widest flex items-center gap-2">
              <ShieldAlert size={14} /> Ethical Framework
            </p>
            
            <div className="p-5 rounded-2xl bg-gradient-to-b from-slate-900/90 to-slate-950 border border-slate-800/80 shadow-xl space-y-3 relative group">
              <div className="absolute top-3 right-3 text-slate-700 group-hover:text-emerald-500/40 transition-colors">
                <Lock size={18} />
              </div>

              <p className="text-xs leading-relaxed text-slate-400 font-sans">
                Scanning must only be performed against assets you own or have explicit written authorization to audit. Unauthorized testing is strictly prohibited.
              </p>

              <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 pt-3 border-t border-slate-800/80">
                <span className="flex items-center gap-1.5 text-emerald-400">
                  <Terminal size={12} /> Safe Passive Checks
                </span>
                <span className="text-slate-500">RFC 2350 Compliance</span>
              </div>
            </div>
          </div>

        </div>

        {/* Sub-Footer Divider & Metadata Bar */}
        <div className="mt-14 pt-8 border-t border-slate-800/80 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between text-xs font-mono text-slate-500">
          <div className="flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-4">
            <p>© 2026 VULNAI DevSecOps Platform.</p>
            <span className="hidden sm:inline text-slate-700">•</span>
            <p className="text-slate-400">Final-Year Academic Build</p>
          </div>
          
          <div className="flex items-center gap-6">
            <span className="text-slate-500 flex items-center gap-1">
              <Lock size={12} className="text-emerald-500" /> Authorized Auditing Only
            </span>
            <a 
              href="https://github.com" 
              target="_blank" 
              rel="noreferrer"
              className="text-slate-400 hover:text-emerald-400 transition-colors flex items-center gap-1.5 group"
            >
              <Code size={14} />
              <span>GitHub</span>
              <ExternalLink size={10} className="opacity-0 group-hover:opacity-100 transition-opacity" />
            </a>
          </div>
        </div>
      </div>
    </footer>
  );
}