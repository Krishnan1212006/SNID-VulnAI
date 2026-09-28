import { useState, useEffect } from "react";
import { useParams, Link } from "react-router-dom";
import {
  ArrowLeft,
  ArrowUpCircle,
  ArrowDownCircle,
  MinusCircle,
  ShieldAlert,
  ShieldCheck,
  GitCompare,
  Cpu,
  Terminal,
  Sparkles,
} from "lucide-react";
import api from "../lib/api";
import SeverityBadge from "../components/SeverityBadge";

export default function ScanComparison() {
  const { current_id, previous_id } = useParams();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const res = await api.get(`/scans/${current_id}/compare/${previous_id}`);
        setData(res.data);
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [current_id, previous_id]);

  if (loading) {
    return (
      <div className="relative min-h-screen font-mono text-slate-100 p-6 flex justify-center items-center bg-[#020408]">
        <div className="rounded-2xl border border-cyan-500/30 bg-[#070D1B]/80 p-12 text-center text-xs text-cyan-400 font-mono flex items-center justify-center gap-3 backdrop-blur-2xl shadow-[0_0_30px_rgba(0,240,255,0.08)]">
          <Sparkles className="animate-spin text-cyan-400" size={20} />
          <p className="text-slate-200">Computing scan diff matrix...</p>
        </div>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="relative min-h-screen font-mono text-slate-100 p-6 flex justify-center items-center bg-[#020408]">
        <div className="rounded-2xl border border-rose-500/30 bg-[#070D1B]/80 p-12 text-center backdrop-blur-2xl">
          <p className="text-rose-400 font-mono text-xs">[ERROR] Failed to load comparison data.</p>
          <Link to="/reports" className="mt-4 inline-block text-xs text-cyan-400 hover:text-cyan-300 underline">
            ← Back to Reports
          </Link>
        </div>
      </div>
    );
  }

  const { current_score, previous_score, comparison, new_issues, resolved_issues, severity_shifts } = data;
  const scoreDiff = current_score - previous_score;

  return (
    <div className="relative min-h-screen font-mono text-slate-100 p-2 sm:p-6 overflow-hidden bg-[#020408] space-y-6">
      {/* Background */}
      <div className="fixed inset-0 z-0 pointer-events-none bg-[linear-gradient(to_right,#00f0ff08_1px,transparent_1px),linear-gradient(to_bottom,#00f0ff08_1px,transparent_1px)] bg-[size:3rem_3rem]" />
      <div className="fixed -top-24 -right-24 z-0 h-96 w-96 rounded-full bg-cyan-500/10 blur-[150px] pointer-events-none" />
      <div className="fixed top-1/2 -left-24 z-0 h-96 w-96 rounded-full bg-purple-600/10 blur-[150px] pointer-events-none" />

      <div className="relative z-10 max-w-6xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 rounded-2xl border border-cyan-500/30 bg-[#070D1B]/80 p-5 shadow-[0_0_30px_rgba(0,240,255,0.08)] backdrop-blur-2xl">
          <div className="flex items-center gap-3.5">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-purple-950/60 border border-purple-400/60 text-purple-400 shadow-[0_0_15px_rgba(168,85,247,0.3)]">
              <GitCompare size={22} className="animate-pulse" />
            </div>
            <div>
              <h1 className="text-lg font-extrabold tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-purple-400 via-slate-100 to-cyan-300 uppercase">
                Scan Comparison Diff
              </h1>
              <p className="text-[11px] text-slate-400 flex items-center gap-1 mt-0.5">
                <Cpu size={12} className="text-cyan-400" /> Delta between current and previous security assessment.
              </p>
            </div>
          </div>
          <Link
            to="/reports"
            className="flex items-center gap-2 text-xs font-bold text-cyan-400 hover:text-cyan-300 transition-colors self-start sm:self-auto"
          >
            <ArrowLeft size={14} /> Back to Reports
          </Link>
        </div>

        {/* Score Diff Row */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <ScoreCard label="Previous Score" value={previous_score} />
          <ScoreCard label="Current Score" value={current_score} />
          <div className="rounded-2xl border border-cyan-500/30 bg-[#070D1B]/80 p-5 shadow-[0_0_20px_rgba(0,0,0,0.5)] backdrop-blur-2xl">
            <p className="font-mono text-[10px] uppercase tracking-wider text-slate-400 font-bold mb-2">Posture Shift</p>
            <div className="flex items-center gap-2 text-3xl font-bold">
              {scoreDiff > 0 ? (
                <>
                  <ArrowUpCircle className="text-emerald-400" size={28} />
                  <span className="text-emerald-400 font-mono">+{scoreDiff}</span>
                </>
              ) : scoreDiff < 0 ? (
                <>
                  <ArrowDownCircle className="text-rose-400" size={28} />
                  <span className="text-rose-400 font-mono">{scoreDiff}</span>
                </>
              ) : (
                <>
                  <MinusCircle className="text-slate-500" size={28} />
                  <span className="text-slate-400 font-mono">0</span>
                </>
              )}
            </div>
          </div>
        </div>

        {/* Metrics Row */}
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <MetricCard label="New Vulnerabilities" value={`+${comparison.new}`} color="rose" />
          <MetricCard label="Resolved Findings" value={`-${comparison.resolved}`} color="emerald" />
          <MetricCard label="Severity Shifts" value={comparison.severity_shifts_count} color="cyan" />
          <MetricCard label="Unchanged" value={comparison.unchanged} color="slate" />
        </div>

        {/* Comparison Tables */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* New Issues */}
          <ComparisonSection
            title="New Vulnerabilities Introduced"
            icon={ShieldAlert}
            iconClass="text-rose-400 border-rose-500/30 bg-rose-950/40 shadow-[0_0_10px_rgba(244,63,94,0.2)]"
            empty="No new findings introduced! Excellent posture improvement."
          >
            {new_issues.map((iss) => (
              <IssueRow key={iss._id} iss={iss} strikethrough={false} />
            ))}
          </ComparisonSection>

          {/* Resolved Issues */}
          <ComparisonSection
            title="Resolved Vulnerabilities"
            icon={ShieldCheck}
            iconClass="text-emerald-400 border-emerald-500/30 bg-emerald-950/40 shadow-[0_0_10px_rgba(16,185,129,0.2)]"
            empty="No findings resolved this scan interval."
          >
            {resolved_issues.map((iss) => (
              <IssueRow key={iss._id} iss={iss} strikethrough resolved />
            ))}
          </ComparisonSection>

          {/* Severity Shifts */}
          <div className="lg:col-span-2 rounded-2xl border border-cyan-500/25 bg-[#070D1B]/80 p-6 shadow-[0_0_30px_rgba(0,0,0,0.5)] backdrop-blur-2xl">
            <div className="mb-4 flex items-center gap-2.5">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-purple-500/30 bg-purple-950/40 text-purple-400 shadow-[0_0_10px_rgba(168,85,247,0.2)]">
                <Terminal size={16} />
              </div>
              <h3 className="font-bold text-sm text-slate-100 uppercase tracking-wider">Severity Impact Shifts</h3>
            </div>
            {severity_shifts.length === 0 ? (
              <p className="text-xs text-slate-500 font-mono">No severity modifications detected.</p>
            ) : (
              <div className="divide-y divide-cyan-500/10">
                {severity_shifts.map((shift, idx) => (
                  <div key={idx} className="py-3 flex justify-between items-center gap-4 hover:bg-cyan-500/5 px-3 rounded-xl transition-colors">
                    <span className="text-xs text-slate-200 font-mono truncate">
                      {shift.title}{" "}
                      <span className="text-slate-500">@{shift.target_url}</span>
                    </span>
                    <div className="flex gap-2 items-center bg-[#03060D] px-3 py-1.5 rounded-xl border border-cyan-500/20 shrink-0">
                      <SeverityBadge level={shift.old_severity} />
                      <ArrowLeft className="rotate-180 text-cyan-400" size={14} />
                      <SeverityBadge level={shift.new_severity} />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function ScoreCard({ label, value }) {
  return (
    <div className="rounded-2xl border border-cyan-500/30 bg-[#070D1B]/80 p-5 shadow-[0_0_20px_rgba(0,0,0,0.5)] backdrop-blur-2xl">
      <p className="font-mono text-[10px] uppercase tracking-wider text-slate-400 font-bold mb-2">{label}</p>
      <p className="text-3xl font-bold font-mono text-cyan-300">{value}</p>
    </div>
  );
}

function MetricCard({ label, value, color }) {
  const colors = {
    rose: "text-rose-400 border-rose-500/30 bg-rose-950/20",
    emerald: "text-emerald-400 border-emerald-500/30 bg-emerald-950/20",
    cyan: "text-cyan-400 border-cyan-500/30 bg-cyan-950/20",
    slate: "text-slate-400 border-slate-700 bg-slate-900/20",
  };
  return (
    <div className={`rounded-2xl border p-4 text-center backdrop-blur-2xl ${colors[color]}`}>
      <p className="font-mono text-[10px] uppercase tracking-wider text-slate-400 font-bold mb-2">{label}</p>
      <p className={`text-2xl font-mono font-bold ${colors[color].split(" ")[0]}`}>{value}</p>
    </div>
  );
}

function ComparisonSection({ title, icon: Icon, iconClass, empty, children }) {
  const childArray = Array.isArray(children) ? children : children ? [children] : [];
  return (
    <div className="rounded-2xl border border-cyan-500/25 bg-[#070D1B]/80 p-6 shadow-[0_0_30px_rgba(0,0,0,0.5)] backdrop-blur-2xl">
      <div className="mb-4 flex items-center gap-2.5">
        <div className={`flex h-9 w-9 items-center justify-center rounded-xl border ${iconClass}`}>
          <Icon size={16} />
        </div>
        <h3 className="font-bold text-sm text-slate-100 uppercase tracking-wider">{title}</h3>
      </div>
      {childArray.length === 0 ? (
        <p className="text-xs text-slate-500 font-mono">{empty}</p>
      ) : (
        <div className="divide-y divide-cyan-500/10">{children}</div>
      )}
    </div>
  );
}

function IssueRow({ iss, strikethrough, resolved }) {
  return (
    <div className="py-3 flex justify-between items-center gap-4 hover:bg-cyan-500/5 px-3 rounded-xl transition-colors">
      <span className={`text-xs font-mono truncate ${strikethrough ? "line-through opacity-60 text-slate-400" : "text-slate-200"}`}>
        {iss.title}{" "}
        <span className="text-slate-500">@{iss.target_url}</span>
      </span>
      {resolved ? (
        <span className="text-xs text-emerald-400 font-mono font-bold tracking-wider bg-emerald-950/40 px-2.5 py-1 rounded-lg border border-emerald-500/30 shrink-0">
          PATCHED
        </span>
      ) : (
        <SeverityBadge level={iss.severity} />
      )}
    </div>
  );
}
