import { Menu, Bell, Search, ShieldCheck, Terminal, Cpu } from "lucide-react";

const today = new Date().toLocaleDateString(undefined, { weekday: "long", month: "long", day: "numeric" });

export default function Topbar({ title, subtitle, onMenuClick }) {
  return (
    <header className="sticky top-0 z-30 border-b border-cyan-500/30 bg-[#070D1B]/90 backdrop-blur-2xl shadow-[0_4px_30px_rgba(0,240,255,0.05)] font-mono">
      <div className="flex items-center justify-between gap-4 px-5 py-4 lg:px-8">
        
        {/* Left Section: Menu & Titles */}
        <div className="flex items-center gap-3.5">
          <button
            onClick={onMenuClick}
            className="flex h-10 w-10 items-center justify-center rounded-xl border border-cyan-500/30 bg-[#03060D] text-cyan-400 hover:border-cyan-400 hover:bg-cyan-950/40 transition-all duration-300 lg:hidden shadow-inner"
          >
            <Menu size={18} />
          </button>
          <div>
            <p className="font-mono text-[10px] uppercase tracking-widest text-cyan-400 mb-0.5 hidden sm:flex items-center gap-1.5">
              <Cpu size={11} className="text-cyan-400 animate-pulse" /> {today} // SECURE_GRID_ACTIVE
            </p>
            <h1 className="font-display text-lg font-extrabold text-slate-100 tracking-wider sm:text-2xl uppercase">
              {title}
            </h1>
            {subtitle && <p className="mt-0.5 text-xs text-slate-400 sm:text-xs font-mono">{subtitle}</p>}
          </div>
        </div>

        {/* Right Section: Search, Notifications & Lab Badge */}
        <div className="flex items-center gap-3">
          
          {/* Cyber Search Bar */}
          <div className="relative hidden md:block">
            <Search size={14} className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-cyan-400" />
            <input
              type="text"
              placeholder="Search findings, IPs, CVEs..."
              className="w-64 rounded-xl border border-cyan-500/30 bg-[#03060D] py-2 pl-10 pr-3 text-xs font-mono text-slate-200 placeholder:text-slate-500 focus:border-cyan-400 focus:outline-none focus:ring-1 focus:ring-cyan-400 shadow-inner transition-all duration-300"
            />
          </div>

          {/* Notification Button */}
          <button className="relative flex h-10 w-10 items-center justify-center rounded-xl border border-cyan-500/30 bg-[#03060D] text-cyan-400 hover:border-cyan-400 hover:bg-cyan-950/40 transition-all duration-300 shadow-inner">
            <Bell size={16} strokeWidth={1.75} />
            <span className="absolute right-2 top-2 h-2 w-2 rounded-full bg-rose-500 shadow-[0_0_8px_#f43f5e] animate-ping" />
            <span className="absolute right-2 top-2 h-2 w-2 rounded-full bg-rose-500 shadow-[0_0_8px_#f43f5e]" />
          </button>

          {/* Lab Mode Badge */}
          <div className="hidden items-center gap-1.5 rounded-xl border border-emerald-500/40 bg-emerald-950/40 px-3 py-2 font-mono text-[11px] font-bold uppercase tracking-wider text-emerald-300 shadow-[0_0_15px_rgba(16,185,129,0.2)] sm:flex">
            <ShieldCheck size={13} strokeWidth={1.75} className="text-emerald-400" />
            Lab Mode
          </div>

        </div>

      </div>
    </header>
  );
}