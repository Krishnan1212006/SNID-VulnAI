import { NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  ScanLine,
  ShieldAlert,
  FileText,
  Router,
  Activity,
  GitMerge,
  Workflow,
  Cloud,
  ShieldHalf,
  LogOut,
  X,
  ClipboardList,
  Cpu
} from "lucide-react";
import { useAuth } from "../context/AuthContext";

const NAV_SECTIONS = [
  {
    label: "Overview",
    items: [{ to: "/dashboard", label: "Dashboard", icon: LayoutDashboard }],
  },
  {
    label: "Web Security",
    items: [
      { to: "/scan", label: "New Scan", icon: ScanLine },
      { to: "/vulnerabilities", label: "Vulnerabilities", icon: ShieldAlert },
      { to: "/reports", label: "Reports", icon: FileText },
    ],
  },
  {
    label: "Network & IoT (SNID)",
    items: [
      { to: "/devices", label: "Devices", icon: Router },
      { to: "/events", label: "Security Events", icon: Activity },
      { to: "/incidents", label: "Incidents", icon: GitMerge },
    ],
  },
  {
    label: "Operations",
    items: [
      { to: "/devsecops", label: "DevSecOps", icon: Workflow },
      { to: "/monitoring", label: "Cloud Monitoring", icon: Cloud },
      { to: "/audit", label: "Audit Logs", icon: ClipboardList },
    ],
  },
];

export default function Sidebar({ open, onClose }) {
  const { user, logout } = useAuth();

  return (
    <>
      {/* Mobile Backdrop with Blur */}
      {open && (
        <div 
          className="fixed inset-0 z-30 bg-black/80 backdrop-blur-md lg:hidden transition-opacity duration-300" 
          onClick={onClose} 
        />
      )}

      <aside
        className={`fixed inset-y-0 left-0 z-40 flex w-64 flex-col border-r border-cyan-500/20 bg-[#040812]/95 backdrop-blur-2xl font-mono text-slate-200 transition-all duration-300 ease-in-out lg:static lg:translate-x-0 ${
          open ? "translate-x-0 shadow-[0_0_50px_rgba(0,240,255,0.15)]" : "-translate-x-full"
        }`}
      >
        {/* Top Header Logo Banner */}
        <div className="relative flex items-center justify-between gap-2 border-b border-cyan-500/20 px-5 py-5 bg-[#070D1B]/50">
          {/* Subtle Top Glow */}
          <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-cyan-400 to-transparent opacity-50" />

          <div className="flex items-center gap-3">
            <div className="relative flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-950/40 border border-cyan-400/50 text-cyan-400 shadow-[0_0_15px_rgba(0,240,255,0.3)] group">
              <ShieldHalf size={22} strokeWidth={2} className="animate-pulse" />
              {/* Corner Sci-Fi Accent Dot */}
              <span className="absolute top-1 right-1 h-1.5 w-1.5 rounded-full bg-cyan-400 shadow-[0_0_6px_#00f0ff]" />
            </div>
            <div className="leading-tight">
              <p className="font-extrabold text-base tracking-widest text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-slate-100 to-cyan-200 uppercase">
                VulnAI
              </p>
              <p className="text-[10px] uppercase font-bold tracking-wider text-cyan-500/80 flex items-center gap-1">
                <Cpu size={10} /> SOC DEVSECOPS
              </p>
            </div>
          </div>

          <button 
            onClick={onClose} 
            className="text-slate-400 hover:text-cyan-400 hover:bg-cyan-500/10 p-1.5 rounded-lg transition-all lg:hidden"
          >
            <X size={20} />
          </button>
        </div>

        {/* Navigation Section */}
        <nav className="flex-1 overflow-y-auto px-3 py-6 space-y-6 scrollbar-thin scrollbar-thumb-cyan-500/20">
          {NAV_SECTIONS.map((section) => (
            <div key={section.label} className="space-y-1">
              <div className="flex items-center gap-2 px-3 mb-2">
                <p className="text-[10px] font-bold uppercase tracking-widest text-cyan-400/70">
                  {section.label}
                </p>
                <div className="h-px flex-1 bg-gradient-to-r from-cyan-500/20 to-transparent" />
              </div>

              <div className="space-y-1">
                {section.items.map(({ to, label, icon: Icon }) => (
                  <NavLink
                    key={to}
                    to={to}
                    onClick={onClose}
                    className={({ isActive }) =>
                      `group relative flex items-center gap-3 rounded-xl px-3 py-2.5 text-xs font-semibold tracking-wide transition-all duration-300 ${
                        isActive
                          ? "bg-gradient-to-r from-cyan-500/20 via-cyan-500/10 to-transparent border-l-2 border-cyan-400 text-cyan-300 shadow-[0_0_15px_rgba(0,240,255,0.15)]"
                          : "border-l-2 border-transparent text-slate-400 hover:bg-cyan-500/5 hover:text-slate-100 hover:border-cyan-500/40"
                      }`
                    }
                  >
                    {({ isActive }) => (
                      <>
                        <Icon
                          size={17}
                          strokeWidth={2}
                          className={`transition-colors duration-300 ${
                            isActive 
                              ? "text-cyan-400 drop-shadow-[0_0_8px_rgba(0,240,255,0.8)] animate-pulse" 
                              : "text-slate-500 group-hover:text-cyan-300"
                          }`}
                        />
                        <span className="truncate">{label}</span>
                        {isActive && (
                          <span className="ml-auto h-1.5 w-1.5 rounded-full bg-cyan-400 shadow-[0_0_8px_#00f0ff]" />
                        )}
                      </>
                    )}
                  </NavLink>
                ))}
              </div>
            </div>
          ))}
        </nav>

        {/* User Account / Sign Out Section */}
        <div className="border-t border-cyan-500/20 p-4 bg-[#070D1B]/60 relative">
          <div className="mb-3 flex items-center gap-3 rounded-xl border border-cyan-500/30 bg-[#03060D] p-2.5 shadow-[0_0_15px_rgba(0,0,0,0.5)]">
            <div className="relative flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-cyan-400/50 bg-cyan-950/40 font-mono text-xs font-bold text-cyan-300 shadow-[0_0_10px_rgba(0,240,255,0.2)]">
              {user?.initials || "SU"}
              <span className="absolute bottom-0 right-0 h-2 w-2 rounded-full bg-emerald-400 ring-2 ring-[#03060D]" />
            </div>
            <div className="min-w-0 leading-tight">
              <p className="truncate text-xs font-bold text-slate-100">{user?.name || "Student User"}</p>
              <p className="truncate text-[10px] text-cyan-400/80 font-medium">{user?.role || "Security Analyst"}</p>
            </div>
          </div>

          <button
            onClick={logout}
            className="group flex w-full items-center justify-center gap-2 rounded-xl border border-rose-500/30 bg-rose-950/20 px-3 py-2 text-xs font-bold text-rose-300 transition-all duration-300 hover:bg-rose-500 hover:text-black hover:shadow-[0_0_15px_rgba(244,63,94,0.4)]"
          >
            <LogOut size={15} strokeWidth={2} className="transition-transform group-hover:-translate-x-0.5" />
            Sign out
          </button>
        </div>
      </aside>
    </>
  );
}