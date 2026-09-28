import { useMemo, useState, useEffect } from "react";
import { Search, ShieldAlert, Filter, Terminal, Cpu } from "lucide-react";
import VulnerabilityTable from "../components/VulnerabilityTable";
import { severityColors } from "../data/mockData";
import api from "../lib/api";

const LEVELS = ["critical", "high", "medium", "low"];

// Cyberpunk Neon Palette Map
const CYBER_NEON = {
  critical: { bg: "rgba(255, 0, 85, 0.15)", border: "#FF0055", text: "#FF0055", shadow: "0 0 15px rgba(255, 0, 85, 0.4)" },
  high: { bg: "rgba(255, 107, 0, 0.15)", border: "#FF6B00", text: "#FF6B00", shadow: "0 0 15px rgba(255, 107, 0, 0.4)" },
  medium: { bg: "rgba(255, 199, 0, 0.15)", border: "#FFC700", text: "#FFC700", shadow: "0 0 15px rgba(255, 199, 0, 0.4)" },
  low: { bg: "rgba(0, 229, 255, 0.15)", border: "#00E5FF", text: "#00E5FF", shadow: "0 0 15px rgba(0, 229, 255, 0.4)" },
};

export default function Vulnerabilities() {
  const [query, setQuery] = useState("");
  const [activeLevels, setActiveLevels] = useState([]);
  const [vulnerabilities, setVulnerabilities] = useState([]);

  useEffect(() => {
    async function fetchVulns() {
      try {
        const res = await api.get("/vulnerabilities/");
        setVulnerabilities(res.data);
      } catch (err) {
        console.error("Failed to load vulnerabilities:", err);
      }
    }
    fetchVulns();
  }, []);

  function toggleLevel(level) {
    setActiveLevels((prev) => (prev.includes(level) ? prev.filter((l) => l !== level) : [...prev, level]));
  }

  const filtered = useMemo(() => {
    return vulnerabilities.filter((v) => {
      const matchesQuery =
        !query ||
        v.title.toLowerCase().includes(query.toLowerCase()) ||
        v.category.toLowerCase().includes(query.toLowerCase()) ||
        v.target_url.toLowerCase().includes(query.toLowerCase());
      const matchesLevel = activeLevels.length === 0 || activeLevels.includes(v.severity);
      return matchesQuery && matchesLevel;
    });
  }, [query, activeLevels]);

  const counts = LEVELS.reduce((acc, level) => {
    acc[level] = vulnerabilities.filter((v) => v.severity === level).length;
    return acc;
  }, {});

  return (
    <div className="relative space-y-6 font-mono text-slate-100 p-2 sm:p-4">
      
      {/* Visual Sci-Fi Background Glows */}
      <div className="pointer-events-none absolute -top-20 -right-20 h-96 w-96 rounded-full bg-cyan-500/10 blur-[120px]" />
      <div className="pointer-events-none absolute top-1/2 -left-20 h-96 w-96 rounded-full bg-rose-500/10 blur-[120px]" />

      {/* Cyberpunk Header Bar */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between border-b border-cyan-500/20 pb-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-950/40 border border-cyan-400/50 text-cyan-400 shadow-[0_0_15px_rgba(0,240,255,0.3)]">
            <ShieldAlert size={20} className="animate-pulse" />
          </div>
          <div>
            <h1 className="text-lg font-extrabold tracking-widest text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-slate-100 to-cyan-200 uppercase">
              Vulnerability Telemetry
            </h1>
            <p className="text-[11px] text-slate-400 flex items-center gap-1.5 mt-0.5">
              <Cpu size={12} className="text-cyan-500" /> Active Threat Database & Remediation Registry
            </p>
          </div>
        </div>

        {/* Live Finding Badge */}
        <div className="flex items-center gap-2 self-start sm:self-auto bg-[#03060D] px-3.5 py-1.5 rounded-xl border border-cyan-500/30 text-xs shadow-[0_0_15px_rgba(0,240,255,0.1)]">
          <Terminal size={13} className="text-cyan-400 animate-pulse" />
          <span className="text-slate-400">Total Findings:</span>
          <span className="font-bold text-cyan-300">{vulnerabilities.length}</span>
        </div>
      </div>

      {/* Control Panel: Search & Severity Filters */}
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between rounded-2xl bg-[#070D1B]/80 p-4 border border-cyan-500/25 shadow-[0_0_30px_rgba(0,0,0,0.5)] backdrop-blur-2xl">
        
        {/* Holographic Search Bar */}
        <div className="relative w-full lg:max-w-md group">
          <Search size={16} className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-cyan-400/70 group-focus-within:text-cyan-400 group-focus-within:drop-shadow-[0_0_8px_#00f0ff] transition-all" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search title, category or target..."
            className="w-full rounded-xl border border-cyan-500/30 bg-[#03060D]/90 py-2.5 pl-10 pr-4 text-xs text-slate-100 placeholder:text-slate-500 focus:border-cyan-400 focus:bg-[#03060D] focus:outline-none focus:ring-1 focus:ring-cyan-400/50 shadow-inner transition-all duration-300"
          />
        </div>

        {/* Severity Filter Pills */}
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[11px] font-bold uppercase text-slate-400 flex items-center gap-1 mr-1">
            <Filter size={12} className="text-cyan-400" /> Severity:
          </span>
          {LEVELS.map((level) => {
            const isActive = activeLevels.includes(level);
            const neonStyle = CYBER_NEON[level] || { border: severityColors[level], text: severityColors[level] };

            return (
              <button
                key={level}
                onClick={() => toggleLevel(level)}
                className={`group relative rounded-xl border px-3.5 py-1.5 font-mono text-[11px] font-bold uppercase tracking-wider transition-all duration-300 ${
                  isActive
                    ? "scale-105"
                    : "border-slate-800 bg-[#03060D]/80 text-slate-400 hover:border-slate-700 hover:text-slate-200"
                }`}
                style={
                  isActive
                    ? {
                        backgroundColor: neonStyle.bg,
                        borderColor: neonStyle.border,
                        color: neonStyle.text,
                        boxShadow: neonStyle.shadow,
                      }
                    : {}
                }
              >
                {level}
                <span className={`ml-1.5 rounded-md px-1.5 py-0.5 text-[10px] ${isActive ? "bg-black/40 text-white" : "bg-slate-800/80 text-slate-400 group-hover:text-slate-200"}`}>
                  {counts[level]}
                </span>
              </button>
            );
          })}
        </div>

      </div>

      {/* Results Telemetry Status */}
      <div className="flex items-center justify-between px-1 text-xs">
        <p className="text-slate-400 flex items-center gap-2">
          <span className="h-2 w-2 rounded-full bg-cyan-400 animate-ping" />
          Showing <span className="font-bold text-cyan-300">{filtered.length}</span> of <span className="font-bold text-slate-300">{vulnerabilities.length}</span> findings
        </p>
      </div>

      {/* Vulnerabilities Table Container */}
      <div className="rounded-2xl border border-cyan-500/20 bg-[#070D1B]/60 shadow-[0_0_40px_rgba(0,0,0,0.6)] backdrop-blur-2xl overflow-hidden">
        <VulnerabilityTable items={filtered} />
      </div>

    </div>
  );
}