import { useMemo, useState, useEffect } from "react";
import { Search, ShieldAlert, Filter, Terminal, Cpu } from "lucide-react";
import VulnerabilityTable from "../components/VulnerabilityTable";
import { severityColors } from "../data/mockData";
import api from "../lib/api";

const LEVELS = ["critical", "high", "medium", "low", "info"];

// Cyberpunk Neon Palette Map
const CYBER_NEON = {
  critical: { bg: "rgba(255, 0, 85, 0.15)", border: "#FF0055", text: "#FF0055", shadow: "0 0 15px rgba(255, 0, 85, 0.4)" },
  high: { bg: "rgba(255, 107, 0, 0.15)", border: "#FF6B00", text: "#FF6B00", shadow: "0 0 15px rgba(255, 107, 0, 0.4)" },
  medium: { bg: "rgba(255, 199, 0, 0.15)", border: "#FFC700", text: "#FFC700", shadow: "0 0 15px rgba(255, 199, 0, 0.4)" },
  low: { bg: "rgba(0, 229, 255, 0.15)", border: "#00E5FF", text: "#00E5FF", shadow: "0 0 15px rgba(0, 229, 255, 0.4)" },
  info: { bg: "rgba(168, 85, 247, 0.15)", border: "#A855F7", text: "#A855F7", shadow: "0 0 15px rgba(168, 85, 247, 0.4)" },
};

export default function Vulnerabilities() {
  const [query, setQuery] = useState("");
  const [activeLevels, setActiveLevels] = useState([]);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [niktoFindings, setNiktoFindings] = useState([]);
  const [niktoError, setNiktoError] = useState("");
  const [gobusterObservations, setGobusterObservations] = useState([]);
  const [gobusterError, setGobusterError] = useState("");
  const [unifiedObservations, setUnifiedObservations] = useState(null);
  const [unifiedObservationsError, setUnifiedObservationsError] = useState("");

  useEffect(() => {
    async function fetchVulns() {
      try {
        const res = await api.get("/findings").catch(() => api.get("/vulnerabilities/"));
        setVulnerabilities(res.data);
      } catch (err) {
        console.error("Failed to load vulnerabilities:", err);
      }
    }
    fetchVulns();

    async function fetchNiktoFindings() {
      try {
        const res = await api.get("/scans/nikto");
        setNiktoFindings(res.data.flatMap((scan) => scan.normalized_findings || []));
      } catch (err) {
        setNiktoError(err.message || "Failed to load Nikto findings");
      }
    }
    fetchNiktoFindings();

    async function fetchGobusterObservations() {
      try {
        const res = await api.get("/scans/gobuster");
        setGobusterObservations(res.data.observations || []);
      } catch (err) {
        setGobusterError(err.message || "Failed to load Gobuster observations");
      }
    }
    fetchGobusterObservations();

    async function fetchUnifiedObservations() {
      try {
        const res = await api.get("/vulnerabilities/unified-observations");
        setUnifiedObservations(res.data);
      } catch (err) {
        setUnifiedObservationsError(err.message || "Failed to load unified assessment observations");
      }
    }
    fetchUnifiedObservations();
  }, []);

  const [activeClassification, setActiveClassification] = useState("all");

  function toggleLevel(level) {
    setActiveLevels((prev) => (prev.includes(level) ? prev.filter((l) => l !== level) : [...prev, level]));
  }

  const classificationCounts = useMemo(() => {
    let confirmed = 0, potential = 0, informational = 0, incomplete = 0;
    vulnerabilities.forEach((v) => {
      const st = (v.status || v.verification_status || "potential").toLowerCase();
      const sev = (v.severity || "info").toLowerCase();
      if (st === "confirmed") confirmed++;
      else if (st === "incomplete") incomplete++;
      else if (st === "informational" || st === "info" || sev === "info") informational++;
      else potential++;
    });
    return { all: vulnerabilities.length, confirmed, potential, informational, incomplete };
  }, [vulnerabilities]);

  const filtered = useMemo(() => {
    return vulnerabilities.filter((v) => {
      const q = query.toLowerCase();
      const title = (v.title || "").toLowerCase();
      const category = (v.category || "").toLowerCase();
      const target = (v.target || v.target_url || "").toLowerCase();
      const endpoint = (v.endpoint || v.path || "").toLowerCase();
      const cve = (v.cve || v.cve_id || "").toLowerCase();
      const tool = (v.tool || v.source || "").toLowerCase();
      const detectedBy = (v.detected_by || []).join(" ").toLowerCase();

      const matchesQuery =
        !query ||
        title.includes(q) ||
        category.includes(q) ||
        target.includes(q) ||
        endpoint.includes(q) ||
        cve.includes(q) ||
        tool.includes(q) ||
        detectedBy.includes(q);

      const vSev = (v.severity || "low").toLowerCase();
      const matchesLevel = activeLevels.length === 0 || activeLevels.includes(vSev);

      const st = (v.status || v.verification_status || "potential").toLowerCase();
      const matchesClassification =
        activeClassification === "all" ||
        (activeClassification === "confirmed" && st === "confirmed") ||
        (activeClassification === "potential" && (st === "potential" || (st !== "confirmed" && st !== "incomplete" && st !== "informational" && vSev !== "info"))) ||
        (activeClassification === "informational" && (st === "informational" || st === "info" || vSev === "info")) ||
        (activeClassification === "incomplete" && st === "incomplete");

      return matchesQuery && matchesLevel && matchesClassification;
    });
  }, [vulnerabilities, query, activeLevels, activeClassification]);

  const counts = LEVELS.reduce((acc, level) => {
    acc[level] = vulnerabilities.filter((v) => (v.severity || "").toLowerCase() === level).length;
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

      {/* Classification Quick Filter Tabs */}
      <div className="flex flex-wrap items-center gap-2 border-b border-cyan-500/20 pb-3">
        {[
          { key: "all", label: "All Findings", count: classificationCounts.all, activeBg: "bg-cyan-500/20 border-cyan-400 text-cyan-300 shadow-[0_0_15px_rgba(0,240,255,0.25)]" },
          { key: "confirmed", label: "Confirmed Vulnerabilities", count: classificationCounts.confirmed, activeBg: "bg-rose-500/20 border-rose-500 text-rose-300 shadow-[0_0_15px_rgba(244,63,94,0.3)]" },
          { key: "potential", label: "Potential Issues", count: classificationCounts.potential, activeBg: "bg-amber-500/20 border-amber-500 text-amber-300 shadow-[0_0_15px_rgba(245,158,11,0.3)]" },
          { key: "informational", label: "Informational Observations", count: classificationCounts.informational, activeBg: "bg-blue-500/20 border-blue-500 text-blue-300 shadow-[0_0_15px_rgba(59,130,246,0.3)]" },
          { key: "incomplete", label: "Incomplete Checks", count: classificationCounts.incomplete, activeBg: "bg-purple-500/20 border-purple-500 text-purple-300 shadow-[0_0_15px_rgba(168,85,247,0.3)]" },
        ].map((tab) => {
          const isActive = activeClassification === tab.key;
          return (
            <button
              key={tab.key}
              onClick={() => setActiveClassification(tab.key)}
              className={`flex items-center gap-2 rounded-xl border px-3.5 py-2 font-mono text-xs font-bold uppercase tracking-wider transition-all duration-200 ${
                isActive
                  ? `${tab.activeBg} scale-[1.02]`
                  : "border-slate-800 bg-[#03060D]/80 text-slate-400 hover:border-slate-700 hover:text-slate-300"
              }`}
            >
              <span>{tab.label}</span>
              <span className={`rounded-md px-1.5 py-0.5 text-[10px] ${isActive ? "bg-black/50 text-white font-mono" : "bg-slate-800 text-slate-400"}`}>
                {tab.count}
              </span>
            </button>
          );
        })}
      </div>

      {/* Control Panel: Search & Severity Filters */}
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between rounded-2xl bg-[#070D1B]/80 p-4 border border-cyan-500/25 shadow-[0_0_30px_rgba(0,0,0,0.5)] backdrop-blur-2xl">
        
        {/* Holographic Search Bar */}
        <div className="relative w-full lg:max-w-md group">
          <Search size={16} className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-cyan-400/70 group-focus-within:text-cyan-400 group-focus-within:drop-shadow-[0_0_8px_#00f0ff] transition-all" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search title, target, endpoint, CVE, tool, category..."
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
                {level === "info" ? "Informational" : level}
                <span className={`ml-1.5 rounded-md px-1.5 py-0.5 text-[10px] ${isActive ? "bg-black/40 text-white" : "bg-slate-800/80 text-slate-400 group-hover:text-slate-200"}`}>
                  {counts[level] || 0}
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

      <section className="space-y-3 border-t border-cyan-500/20 pt-5">
        <div>
          <h2 className="text-sm font-bold uppercase tracking-wider text-cyan-200">Latest Unified Assessment</h2>
          <p className="mt-1 text-xs text-slate-400">Normalized scanner observations remain unverified unless explicitly classified as confirmed.</p>
        </div>
        {unifiedObservationsError ? (
          <p className="rounded-lg border border-amber-500/30 bg-amber-950/20 px-4 py-3 text-sm text-amber-200">Unified results unavailable: {unifiedObservationsError}</p>
        ) : !unifiedObservations || unifiedObservations.status === "not_available" ? (
          <p className="rounded-lg border border-cyan-500/20 bg-[#070D1B]/60 px-4 py-3 text-sm text-slate-400">No unified assessment results found.</p>
        ) : (
          <div className="divide-y divide-cyan-500/15 overflow-hidden rounded-xl border border-cyan-500/20 bg-[#070D1B]/60">
            {["confirmed", "potential", "informational", "incomplete"].map((classification) => (
              <article key={classification} className="space-y-2 px-4 py-3">
                <p className="font-mono text-[11px] uppercase text-cyan-300">{classification}: {unifiedObservations[classification]?.length || 0}</p>
                {(unifiedObservations[classification] || []).map((observation, index) => (
                  <div key={observation.id || `${classification}-${index}`} className="break-words text-xs text-slate-400">
                    <span className="text-slate-200">{observation.title || observation.path || observation.message}</span>
                    <span className="text-slate-500"> · {observation.scanner || "scanner"} · {observation.verification_status || "unverified"}</span>
                  </div>
                ))}
              </article>
            ))}
          </div>
        )}
      </section>

      <section className="space-y-3 border-t border-cyan-500/20 pt-5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-bold uppercase tracking-wider text-cyan-200">Nikto scanner findings</h2>
            <p className="mt-1 text-xs text-slate-400">Raw scanner observations are unverified and are not included in confirmed vulnerability totals.</p>
          </div>
          <span className="font-mono text-xs text-slate-400">{niktoFindings.length} observations</span>
        </div>

        {niktoError ? (
          <p className="rounded-lg border border-amber-500/30 bg-amber-950/20 px-4 py-3 text-sm text-amber-200">Nikto results unavailable: {niktoError}</p>
        ) : niktoFindings.length === 0 ? (
          <p className="rounded-lg border border-cyan-500/20 bg-[#070D1B]/60 px-4 py-3 text-sm text-slate-400">No Nikto observations found.</p>
        ) : (
          <div className="divide-y divide-cyan-500/15 overflow-hidden rounded-xl border border-cyan-500/20 bg-[#070D1B]/60">
            {niktoFindings.map((finding) => (
              <article key={finding.id} className="space-y-2 px-4 py-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className={`rounded border px-2 py-0.5 font-mono text-[10px] uppercase ${finding.severity === "potential" ? "border-amber-500/40 text-amber-300" : "border-slate-600 text-slate-300"}`}>
                    {finding.severity}
                  </span>
                  <span className="rounded border border-slate-700 px-2 py-0.5 font-mono text-[10px] uppercase text-slate-400">{finding.status}</span>
                  <span className="font-mono text-[10px] text-slate-500">Nikto {finding.scanner_id} · {finding.method}</span>
                </div>
                <p className="break-words text-sm text-slate-200">{finding.raw_message}</p>
                <p className="break-all font-mono text-[11px] text-slate-500">{finding.target_url}</p>
              </article>
            ))}
          </div>
        )}
      </section>

      <section className="space-y-3 border-t border-cyan-500/20 pt-5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-bold uppercase tracking-wider text-cyan-200">Gobuster Observations</h2>
            <p className="mt-1 text-xs text-slate-400">Informational path discoveries are unverified and are not vulnerabilities.</p>
          </div>
          <span className="font-mono text-xs text-slate-400">{gobusterObservations.length} observations</span>
        </div>

        {gobusterError ? (
          <p className="rounded-lg border border-amber-500/30 bg-amber-950/20 px-4 py-3 text-sm text-amber-200">Gobuster results unavailable: {gobusterError}</p>
        ) : gobusterObservations.length === 0 ? (
          <p className="rounded-lg border border-cyan-500/20 bg-[#070D1B]/60 px-4 py-3 text-sm text-slate-400">No Gobuster observations found.</p>
        ) : (
          <div className="divide-y divide-cyan-500/15 overflow-hidden rounded-xl border border-cyan-500/20 bg-[#070D1B]/60">
            {gobusterObservations.map((observation) => (
              <article key={observation.id} className="space-y-2 px-4 py-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="rounded border border-slate-600 px-2 py-0.5 font-mono text-[10px] uppercase text-slate-300">{observation.classification}</span>
                  <span className="rounded border border-slate-700 px-2 py-0.5 font-mono text-[10px] uppercase text-slate-400">{observation.verification_status}</span>
                  <span className="font-mono text-[10px] text-slate-500">HTTP {observation.status_code} · {observation.response_size ?? "unknown"} bytes</span>
                </div>
                <p className="break-all font-mono text-sm text-slate-200">{observation.path}</p>
                <p className="break-words font-mono text-[11px] text-slate-500">{observation.message}</p>
              </article>
            ))}
          </div>
        )}
      </section>

    </div>
  );
}
