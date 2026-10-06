import { useState, useRef, useEffect } from "react";
import { Menu, Bell, Search, ShieldCheck, Terminal, Cpu, CheckCircle2, AlertTriangle, ExternalLink, Trash2 } from "lucide-react";
import { useNotifications } from "../context/NotificationContext";
import { useNavigate } from "react-router-dom";

const today = new Date().toLocaleDateString(undefined, { weekday: "long", month: "long", day: "numeric" });

function formatTimeAgo(isoString) {
  if (!isoString) return "just now";
  const seconds = Math.floor((new Date() - new Date(isoString)) / 1000);
  if (seconds < 60) return `${Math.max(1, seconds)}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

export default function Topbar({ title, subtitle, onMenuClick }) {
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const dropdownRef = useRef(null);
  const navigate = useNavigate();
  const {
    notifications,
    unreadCount,
    markAsRead,
    markAllAsRead,
    clearNotifications,
    requestNotificationPermission,
  } = useNotifications();

  // Close dropdown on outside click
  useEffect(() => {
    function handleClickOutside(e) {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
        setDropdownOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const handleOpenDropdown = () => {
    setDropdownOpen((prev) => !prev);
    requestNotificationPermission();
  };

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

          {/* Notification Button & Interactive Cyber Dropdown */}
          <div className="relative" ref={dropdownRef}>
            <button
              onClick={handleOpenDropdown}
              aria-label="Toggle notifications"
              className="relative flex h-10 w-10 items-center justify-center rounded-xl border border-cyan-500/30 bg-[#03060D] text-cyan-400 hover:border-cyan-400 hover:bg-cyan-950/40 transition-all duration-300 shadow-inner focus:outline-none"
            >
              <Bell size={16} strokeWidth={1.75} />
              {unreadCount > 0 && (
                <>
                  <span className="absolute -top-1 -right-1 flex h-4 w-4 items-center justify-center rounded-full bg-rose-500 text-[9px] font-bold text-white shadow-[0_0_8px_#f43f5e] animate-pulse">
                    {unreadCount > 9 ? "9+" : unreadCount}
                  </span>
                  <span className="absolute right-2 top-2 h-2 w-2 rounded-full bg-rose-500 shadow-[0_0_8px_#f43f5e] animate-ping" />
                </>
              )}
            </button>

            {/* Dropdown Panel */}
            {dropdownOpen && (
              <div className="absolute right-0 mt-3 w-80 sm:w-96 rounded-2xl border border-cyan-500/40 bg-[#070D1B]/95 p-3 text-slate-200 shadow-[0_15px_50px_rgba(0,0,0,0.8),0_0_20px_rgba(0,240,255,0.15)] backdrop-blur-2xl z-50 animate-in fade-in zoom-in-95 duration-200">
                {/* Header */}
                <div className="flex items-center justify-between border-b border-cyan-500/20 pb-2.5 px-2">
                  <div className="flex items-center gap-2">
                    <span className="relative flex h-2 w-2">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-500"></span>
                    </span>
                    <span className="text-xs font-extrabold uppercase tracking-wider text-cyan-300">
                      Live Notifications
                    </span>
                    {unreadCount > 0 && (
                      <span className="rounded-full bg-cyan-950 px-2 py-0.5 text-[10px] font-bold text-cyan-400 border border-cyan-500/30">
                        {unreadCount} NEW
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    {unreadCount > 0 && (
                      <button
                        onClick={markAllAsRead}
                        className="text-[10px] text-slate-400 hover:text-cyan-300 transition"
                      >
                        Mark Read
                      </button>
                    )}
                    {notifications.length > 0 && (
                      <button
                        onClick={clearNotifications}
                        title="Clear all"
                        className="text-slate-500 hover:text-rose-400 transition"
                      >
                        <Trash2 size={12} />
                      </button>
                    )}
                  </div>
                </div>

                {/* Notifications List */}
                <div className="mt-2 max-h-80 overflow-y-auto space-y-1.5 pr-1 divide-y divide-slate-800/40">
                  {notifications.length === 0 ? (
                    <div className="py-8 text-center text-xs text-slate-500">
                      <Terminal size={22} className="mx-auto mb-2 text-slate-600 opacity-60" />
                      No notifications recorded // SECURE_GRID_IDLE
                    </div>
                  ) : (
                    notifications.map((n) => (
                      <div
                        key={n.id}
                        onClick={() => {
                          markAsRead(n.id);
                          setDropdownOpen(false);
                          navigate(n.scanId ? `/reports` : `/scan`);
                        }}
                        className={`group relative flex flex-col gap-1 rounded-xl p-2.5 transition cursor-pointer pt-2.5 ${
                          n.read
                            ? "bg-slate-900/30 hover:bg-slate-900/60 text-slate-400"
                            : "bg-cyan-950/30 hover:bg-cyan-950/50 text-slate-200 border-l-2 border-cyan-400"
                        }`}
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div className="flex items-center gap-1.5">
                            {n.status === "completed" ? (
                              <CheckCircle2 size={13} className="text-emerald-400 shrink-0" />
                            ) : (
                              <AlertTriangle size={13} className="text-amber-400 shrink-0" />
                            )}
                            <span className="text-xs font-bold text-slate-100 group-hover:text-cyan-300 transition truncate max-w-[200px]">
                              {n.title}
                            </span>
                          </div>
                          <span className="text-[10px] text-slate-500 shrink-0">
                            {formatTimeAgo(n.timestamp)}
                          </span>
                        </div>

                        <p className="text-[11px] text-slate-300 truncate pl-4">
                          {n.target}
                        </p>

                        {n.riskScore != null && (
                          <div className="flex items-center gap-2 pl-4 text-[10px]">
                            <span className="text-cyan-400 font-bold">
                              Score: {n.riskScore}/100
                            </span>
                            <span className="text-slate-600">•</span>
                            <span className="text-amber-400 font-bold uppercase">
                              {n.riskRating}
                            </span>
                            <span className="text-slate-600">•</span>
                            <span className="text-slate-400">
                              {n.findingsCount} findings
                            </span>
                          </div>
                        )}
                      </div>
                    ))
                  )}
                </div>

                {/* Footer action */}
                <div className="mt-2.5 pt-2 border-t border-cyan-500/20 text-center">
                  <button
                    onClick={() => {
                      setDropdownOpen(false);
                      navigate("/reports");
                    }}
                    className="w-full text-center text-[11px] font-bold text-cyan-400 hover:text-cyan-300 transition py-1 rounded-lg hover:bg-cyan-950/40 flex items-center justify-center gap-1.5"
                  >
                    View All Scan Reports <ExternalLink size={11} />
                  </button>
                </div>
              </div>
            )}
          </div>

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