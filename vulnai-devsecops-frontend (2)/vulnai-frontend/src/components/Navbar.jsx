import { NavLink, Link } from "react-router-dom";
import { useState } from "react";
import { ShieldHalf, Menu, X, User, LogOut, LayoutDashboard, FileText, PlusCircle, ChevronDown } from "lucide-react";

const PUBLIC_LINKS = [
  { to: "/", label: "Home", end: true },
  { to: "/features", label: "Features" },
  { to: "/how-it-works", label: "How It Works" },
  { to: "/modules", label: "Modules" },
  { to: "/about", label: "About Project" },
];

const AUTH_LINKS = [
  { to: "/dashboard", label: "Dashboard", icon: <LayoutDashboard size={16} /> },
  { to: "/scan", label: "New Scan", icon: <PlusCircle size={16} /> },
  { to: "/reports", label: "Reports", icon: <FileText size={16} /> },
  { to: "/profile", label: "Profile", icon: <User size={16} /> },
];

export default function Navbar() {
  const [open, setOpen] = useState(false);
  // Toggle this state or pass as prop to check both logged-in and logged-out views
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [dropdownOpen, setDropdownOpen] = useState(false);

  return (
    <header className="sticky top-0 z-50 border-b border-emerald-500/20 bg-slate-950/80 backdrop-blur-md">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-5 py-3.5 lg:px-8">
        
        {/* Logo Section */}
        <Link to="/" className="flex items-center gap-3 group">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 group-hover:border-emerald-400 transition-all shadow-[0_0_15px_rgba(16,185,129,0.15)]">
            <ShieldHalf size={18} strokeWidth={2} />
          </div>
          <div className="leading-tight">
            <span className="font-display text-lg font-bold tracking-wider text-slate-100">VULNAI</span>
            <span className="block text-[10px] font-mono tracking-widest text-emerald-400 uppercase">DevSecOps</span>
          </div>
        </Link>

        {/* Desktop Navigation Links */}
        <nav className="hidden items-center gap-6 lg:flex">
          {PUBLIC_LINKS.map((l) => (
            <NavLink
              key={l.to}
              to={l.to}
              end={l.end}
              className={({ isActive }) =>
                `text-sm font-medium transition-colors relative py-1 ${
                  isActive 
                    ? "text-emerald-400 font-semibold after:absolute after:bottom-0 after:left-0 after:right-0 after:h-0.5 after:bg-emerald-400 after:shadow-[0_0_8px_#10b981]" 
                    : "text-slate-400 hover:text-slate-200"
                }`
              }
            >
              {l.label}
            </NavLink>
          ))}
        </nav>

        {/* Right Side Actions (Auth / Unauth States) */}
        <div className="hidden items-center gap-3 md:flex">
          {/* Demo State Switcher Button (Remove in production) */}
          <button 
            onClick={() => setIsAuthenticated(!isAuthenticated)} 
            className="text-[10px] font-mono px-2 py-1 rounded bg-slate-900 border border-slate-800 text-slate-400 hover:text-emerald-400 transition-colors mr-2"
            title="Click to toggle logged in/out state demo"
          >
            {isAuthenticated ? "Mode: Logged In" : "Mode: Guest"}
          </button>

          {isAuthenticated ? (
            <div className="relative">
              <button
                onClick={() => setDropdownOpen(!dropdownOpen)}
                className="flex items-center gap-2.5 py-1.5 px-3 rounded-lg bg-slate-900 border border-emerald-500/30 hover:border-emerald-500/60 transition-all"
              >
                <div className="w-7 h-7 rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center font-bold text-xs">
                  MR
                </div>
                <span className="text-sm font-medium text-slate-200">MRA</span>
                <ChevronDown size={14} className="text-slate-400" />
              </button>

              {dropdownOpen && (
                <div className="absolute right-0 mt-2 w-48 rounded-xl bg-slate-900 border border-slate-800 shadow-xl py-1.5 z-50">
                  {AUTH_LINKS.map((item) => (
                    <Link
                      key={item.to}
                      to={item.to}
                      onClick={() => setDropdownOpen(false)}
                      className="flex items-center gap-2.5 px-4 py-2 text-sm text-slate-300 hover:bg-slate-800/80 hover:text-emerald-400 transition-colors"
                    >
                      {item.icon}
                      {item.label}
                    </Link>
                  ))}
                  <div className="h-px bg-slate-800 my-1" />
                  <button
                    onClick={() => {
                      setIsAuthenticated(false);
                      setDropdownOpen(false);
                    }}
                    className="w-full flex items-center gap-2.5 px-4 py-2 text-sm text-red-400 hover:bg-red-500/10 transition-colors"
                  >
                    <LogOut size={16} />
                    Logout
                  </button>
                </div>
              )}
            </div>
          ) : (
            <div className="flex items-center gap-2.5">
              <Link 
                to="/login" 
                className="px-4 py-2 text-sm font-medium text-slate-300 hover:text-slate-100 transition-colors"
              >
                Log in
              </Link>
              <Link 
                to="/login" 
                className="px-4 py-2 text-sm font-semibold rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 transition-all shadow-[0_0_15px_rgba(16,185,129,0.3)] hover:shadow-[0_0_20px_rgba(16,185,129,0.5)]"
              >
                Get started
              </Link>
            </div>
          )}
        </div>

        {/* Mobile Menu Trigger */}
        <button 
          onClick={() => setOpen(true)} 
          className="border border-slate-800 bg-slate-900 p-2 rounded-lg text-slate-300 md:hidden hover:border-emerald-500/40"
        >
          <Menu size={20} />
        </button>
      </div>

      {/* Mobile Fullscreen Menu Drawer */}
      {open && (
        <div className="fixed inset-0 z-50 bg-slate-950/95 backdrop-blur-xl md:hidden flex flex-col">
          <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800">
            <div className="flex items-center gap-2.5">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                <ShieldHalf size={16} />
              </div>
              <span className="font-display text-base font-bold text-slate-100">VULNAI</span>
            </div>
            <button 
              onClick={() => setOpen(false)} 
              className="border border-slate-800 bg-slate-900 p-2 rounded-lg text-slate-300"
            >
              <X size={18} />
            </button>
          </div>

          <nav className="flex flex-col px-6 py-6 gap-2 overflow-y-auto flex-1">
            <p className="text-xs font-mono text-slate-500 uppercase tracking-wider mb-2">Navigation</p>
            {PUBLIC_LINKS.map((l) => (
              <NavLink
                key={l.to}
                to={l.to}
                end={l.end}
                onClick={() => setOpen(false)}
                className={({ isActive }) =>
                  `py-3 text-base font-medium border-b border-slate-900 transition-colors ${
                    isActive ? "text-emerald-400 font-semibold" : "text-slate-300"
                  }`
                }
              >
                {l.label}
              </NavLink>
            ))}

            {isAuthenticated && (
              <>
                <p className="text-xs font-mono text-slate-500 uppercase tracking-wider mt-6 mb-2">Account Dashboard</p>
                {AUTH_LINKS.map((item) => (
                  <Link
                    key={item.to}
                    to={item.to}
                    onClick={() => setOpen(false)}
                    className="flex items-center gap-3 py-3 text-base font-medium text-slate-300 border-b border-slate-900"
                  >
                    <span className="text-emerald-400">{item.icon}</span>
                    {item.label}
                  </Link>
                ))}
              </>
            )}

            <div className="mt-auto pt-6 flex flex-col gap-3">
              {isAuthenticated ? (
                <button
                  onClick={() => {
                    setIsAuthenticated(false);
                    setOpen(false);
                  }}
                  className="w-full py-3 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 font-semibold text-center text-sm flex items-center justify-center gap-2"
                >
                  <LogOut size={16} /> Logout
                </button>
              ) : (
                <>
                  <Link 
                    to="/login" 
                    onClick={() => setOpen(false)} 
                    className="w-full py-3 rounded-xl bg-slate-900 border border-slate-800 text-center text-sm font-medium text-slate-200"
                  >
                    Log in
                  </Link>
                  <Link 
                    to="/login" 
                    onClick={() => setOpen(false)} 
                    className="w-full py-3 rounded-xl bg-emerald-500 text-slate-950 text-center text-sm font-semibold shadow-[0_0_15px_rgba(16,185,129,0.3)]"
                  >
                    Get started
                  </Link>
                </>
              )}
            </div>
          </nav>
        </div>
      )}
    </header>
  );
}