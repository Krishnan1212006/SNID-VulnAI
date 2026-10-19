import { useState } from "react";
import { Shield, Download, ExternalLink, ChevronDown, ChevronUp, AlertCircle, Crosshair, Cpu } from "lucide-react";
import api from "../lib/api";

export default function MitreAttackMatrix({ scanId, mitreData, findings = [] }) {
  const [downloading, setDownloading] = useState(false);
  const [expandedTactic, setExpandedTactic] = useState(null);

  const matrix = mitreData?.matrix || {};
  const tactics = matrix.tactics || {};
  const activeTactics = Object.values(tactics).filter((t) => t.active);
  const totalTechniques = matrix.total_mapped_techniques || 0;

  const handleDownloadLayer = async () => {
    if (!scanId) return;
    setDownloading(true);
    try {
      const res = await api.getBlob(`/scans/${scanId}/mitre-navigator`);
      const url = URL.createObjectURL(res.data);
      const a = document.createElement("a");
      a.href = url;
      a.download = `mitre-attack-navigator-${scanId}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Failed to download MITRE ATT&CK layer:", err);
    } finally {
      setDownloading(false);
    }
  };

  const getSeverityBadgeColor = (sev) => {
    const s = String(sev || "").toUpperCase();
    if (s === "CRITICAL" || s === "HIGH") return "border-rose-500/50 bg-rose-500/10 text-rose-400";
    if (s === "MEDIUM") return "border-amber-500/50 bg-amber-500/10 text-amber-400";
    return "border-cyan-500/50 bg-cyan-500/10 text-cyan-300";
  };

  return (
    <div className="rounded-xl border border-cyan-500/30 bg-[#060b13]/90 p-4 sm:p-5 shadow-[0_0_25px_rgba(0,240,255,0.08)] backdrop-blur-md">
      {/* Header Banner */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-cyan-500/40 bg-cyan-950/40 text-cyan-400 shadow-[0_0_12px_rgba(0,240,255,0.2)]">
            <Crosshair className="h-5 w-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="font-mono text-sm font-bold uppercase tracking-wider text-slate-100">
                MITRE ATT&CK® Threat Posture
              </h3>
              <span className="rounded-full border border-cyan-500/40 bg-cyan-500/10 px-2 py-0.5 text-[10px] font-mono text-cyan-300">
                Enterprise v14
              </span>
            </div>
            <p className="text-[11px] text-slate-400">
              Adversary Tactics, Techniques & Threat Actor Mapping derived from scan observations
            </p>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2">
          <button
            onClick={handleDownloadLayer}
            disabled={downloading}
            className="flex items-center gap-1.5 rounded-lg border border-cyan-500/50 bg-cyan-500/15 px-3 py-1.5 font-mono text-[11px] font-semibold text-cyan-200 transition-all hover:bg-cyan-500/25 hover:shadow-[0_0_15px_rgba(0,240,255,0.25)] disabled:opacity-50"
            title="Download JSON layer for MITRE ATT&CK Navigator"
          >
            <Download className="h-3.5 w-3.5" />
            <span>{downloading ? "Exporting..." : "Export Navigator Layer (.json)"}</span>
          </button>

          <a
            href="https://mitre-attack.github.io/attack-navigator/"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-900/80 px-2.5 py-1.5 font-mono text-[11px] text-slate-300 transition-all hover:border-slate-500 hover:text-white"
            title="Open online ATT&CK Navigator viewer"
          >
            <span>Navigator</span>
            <ExternalLink className="h-3 w-3" />
          </a>
        </div>
      </div>

      {/* Metrics Bar */}
      <div className="grid grid-cols-2 gap-3 py-3 sm:grid-cols-4">
        <div className="rounded-lg border border-slate-800 bg-[#03060D]/60 p-2.5">
          <span className="block text-[10px] uppercase font-mono text-slate-400">Active Tactics</span>
          <span className="mt-0.5 block text-base font-bold text-cyan-300 font-mono">
            {activeTactics.length} <span className="text-xs text-slate-500">/ 14</span>
          </span>
        </div>
        <div className="rounded-lg border border-slate-800 bg-[#03060D]/60 p-2.5">
          <span className="block text-[10px] uppercase font-mono text-slate-400">Mapped Techniques</span>
          <span className="mt-0.5 block text-base font-bold text-cyan-300 font-mono">
            {totalTechniques}
          </span>
        </div>
        <div className="rounded-lg border border-slate-800 bg-[#03060D]/60 p-2.5">
          <span className="block text-[10px] uppercase font-mono text-slate-400">Target Vector</span>
          <span className="mt-0.5 block text-xs font-semibold text-slate-200 font-mono truncate">
            Public-Facing Web & Network
          </span>
        </div>
        <div className="rounded-lg border border-slate-800 bg-[#03060D]/60 p-2.5">
          <span className="block text-[10px] uppercase font-mono text-slate-400">Threat Emulation</span>
          <span className="mt-0.5 block text-xs font-semibold text-emerald-400 font-mono">
            STIX 2.1 Ready
          </span>
        </div>
      </div>

      {/* Active Tactics & Techniques Accordions */}
      <div className="mt-2 space-y-2.5">
        {activeTactics.length === 0 ? (
          <p className="text-center text-xs text-slate-500 py-3">
            No adversary tactics triggered. The scan concluded with no active technique vectors.
          </p>
        ) : (
          activeTactics.map((tactic) => {
            const isExpanded = expandedTactic === tactic.id;
            const techList = Object.values(tactic.techniques || {});

            return (
              <div
                key={tactic.id}
                className="overflow-hidden rounded-lg border border-slate-800/90 bg-[#040812]/70 transition-colors"
              >
                <button
                  onClick={() => setExpandedTactic(isExpanded ? null : tactic.id)}
                  className="flex w-full items-center justify-between p-3 text-left transition-colors hover:bg-slate-800/40"
                >
                  <div className="flex items-center gap-2.5">
                    <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-[10px] font-bold text-slate-300">
                      {tactic.id}
                    </span>
                    <span className="font-mono text-xs font-bold text-slate-200 uppercase tracking-wide">
                      {tactic.name}
                    </span>
                    <span className={`rounded-full border px-2 py-0.5 text-[9px] font-mono uppercase ${getSeverityBadgeColor(tactic.highest_severity)}`}>
                      {tactic.highest_severity} Threat
                    </span>
                  </div>

                  <div className="flex items-center gap-3">
                    <span className="text-[11px] font-mono text-slate-400">
                      {techList.length} technique{techList.length !== 1 ? "s" : ""}
                    </span>
                    {isExpanded ? (
                      <ChevronUp className="h-4 w-4 text-slate-400" />
                    ) : (
                      <ChevronDown className="h-4 w-4 text-slate-400" />
                    )}
                  </div>
                </button>

                {isExpanded && (
                  <div className="border-t border-slate-800/80 bg-[#020409]/90 p-3 space-y-3">
                    {techList.map((tech) => (
                      <div
                        key={tech.id}
                        className="rounded-lg border border-slate-800/80 bg-slate-900/40 p-3 space-y-2 text-xs"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <span className="rounded bg-cyan-950/80 border border-cyan-500/40 px-2 py-0.5 font-mono text-[11px] font-bold text-cyan-300">
                              {tech.id}
                            </span>
                            <span className="font-semibold text-slate-200">{tech.name}</span>
                          </div>
                          <a
                            href={tech.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="flex items-center gap-1 font-mono text-[10px] text-cyan-400 hover:underline"
                          >
                            <span>ATT&CK Spec</span>
                            <ExternalLink className="h-2.5 w-2.5" />
                          </a>
                        </div>

                        {/* Known Threat Groups */}
                        {tech.threat_groups && tech.threat_groups.length > 0 && (
                          <div className="flex flex-wrap items-center gap-1.5 pt-1">
                            <span className="font-mono text-[10px] text-slate-500">Adversary Groups:</span>
                            {tech.threat_groups.map((grp) => (
                              <span
                                key={grp}
                                className="rounded border border-purple-500/30 bg-purple-950/30 px-1.5 py-0.5 text-[10px] font-mono text-purple-300"
                              >
                                {grp}
                              </span>
                            ))}
                          </div>
                        )}

                        {/* Standard Mitigations */}
                        {tech.mitigations && tech.mitigations.length > 0 && (
                          <div className="space-y-1 pt-1">
                            <span className="font-mono text-[10px] text-slate-500">Standard Defenses:</span>
                            <ul className="space-y-1">
                              {tech.mitigations.map((mit) => (
                                <li key={mit.id} className="flex items-start gap-1.5 text-[11px] text-slate-300">
                                  <span className="font-mono font-bold text-emerald-400">[{mit.id}]</span>
                                  <span>
                                    <strong>{mit.name}:</strong> {mit.description}
                                  </span>
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
