import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { 
  ShieldAlert, 
  ListChecks, 
  Bug, 
  Bell, 
  ArrowUpRight, 
  ScanLine, 
  Plus, 
  Terminal, 
  Activity, 
  Radio, 
  Cpu, 
  ShieldCheck,
  Zap,
  Lock,
  Globe
} from "lucide-react";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  BarChart,
  Bar,
  Cell,
} from "recharts";
import StatCard from "../components/StatCard";
import ScoreGauge from "../components/ScoreGauge";
import SeverityBadge from "../components/SeverityBadge";
import { severityColors } from "../data/mockData";
import api from "../lib/api";

const LEVELS = ["critical", "high", "medium", "low", "info"];

// Cyberpunk Neon Color Palette
const CYBER_COLORS = {
  critical: "#FF0055",
  high: "#FF6B00",
  medium: "#FFC700",
  low: "#00E5FF",
  info: "#A855F7"
};

export default function Dashboard() {
  const [scanHistory, setScanHistory] = useState([]);
  const [trendData, setTrendData] = useState([]);
  const [securityEvents, setSecurityEvents] = useState([]);
  const [metrics, setMetrics] = useState({
      total_scans: 0,
      unresolved_findings: 0,
      active_incidents: 0,
      severity_distribution: {}
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchData() {
      try {
        const [scansRes, trendsRes, eventsRes, metricsRes] = await Promise.all([
          api.get("/scans/"),
          api.get("/scans/trends"),
          api.get("/events/").catch(() => ({ data: [] })),
          api.get("/dashboard/metrics")
        ]);
        setScanHistory(scansRes.data);
        setTrendData(trendsRes.data);
        setSecurityEvents(eventsRes.data);
        setMetrics(metricsRes.data);
      } catch (err) {
        console.error("Dashboard fetch error:", err);
      } finally {
        setLoading(false);
      }
    }
    fetchData();
  }, []);

  if (loading) {
    return (
      <div className="relative space-y-10 bg-[#030712] p-8 rounded-3xl border border-cyan-500/30 shadow-[0_0_80px_rgba(0,240,255,0.08)] backdrop-blur-2xl">
        <section className="animate-pulse space-y-5">
          <div className="h-7 w-44 bg-cyan-950/60 rounded-md border-l-4 border-cyan-400"></div>
          <div className="grid grid-cols-1 gap-5 lg:grid-cols-4">
            <div className="h-[250px] bg-[#0B132B]/80 rounded-2xl border border-cyan-500/20"></div>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:col-span-3 lg:grid-cols-3">
              {[...Array(6)].map((_, i) => (
                <div key={i} className="h-28 bg-[#0B132B]/80 rounded-2xl border border-cyan-500/20"></div>
              ))}
            </div>
          </div>
        </section>
        <section className="animate-pulse space-y-5">
          <div className="h-7 w-44 bg-cyan-950/60 rounded-md border-l-4 border-cyan-400"></div>
          <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
             <div className="h-80 bg-[#0B132B]/80 rounded-2xl lg:col-span-2 border border-cyan-500/20"></div>
             <div className="h-80 bg-[#0B132B]/80 rounded-2xl border border-cyan-500/20"></div>
          </div>
        </section>
      </div>
    );
  }

  const latestScan = scanHistory[0] || {
    risk_score: { score: 100 },
    target_url: "-",
  };
  
  const severityChartData = LEVELS.map(level => ({
    level,
    count: metrics.severity_distribution?.[level] || 0
  }));

  return (
    <div className="relative min-h-screen bg-[#020408] text-slate-100 space-y-10 p-4 sm:p-8 font-mono selection:bg-cyan-400 selection:text-black overflow-hidden">
      
      {/* Visual Background FX */}
      <div className="fixed inset-0 pointer-events-none z-0">
        {/* Glow Spheres */}
        <div className="absolute -top-32 -left-32 w-[600px] h-[600px] bg-cyan-500/15 rounded-full blur-[160px] animate-pulse" />
        <div className="absolute top-1/2 -right-32 w-[600px] h-[600px] bg-purple-600/15 rounded-full blur-[180px] animate-pulse" style={{ animationDuration: '8s' }} />
        <div className="absolute -bottom-32 left-1/3 w-[500px] h-[500px] bg-rose-500/10 rounded-full blur-[150px]" />
        
        {/* Holographic Matrix Grid */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#111827_1px,transparent_1px),linear-gradient(to_bottom,#111827_1px,transparent_1px)] bg-[size:3rem_3rem] [mask-image:radial-gradient(ellipse_75%_75%_at_50%_20%,#000_80%,transparent_100%)] opacity-30" />
        
        {/* Laser Radar Scanning Line */}
        <div className="absolute inset-0 bg-gradient-to-b from-transparent via-cyan-400/10 to-transparent h-[150px] w-full animate-[scan_10s_linear_infinite] pointer-events-none" />
      </div>

      <div className="relative z-10 space-y-10">

        {/* Dynamic HUD Control Header */}
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center p-5 rounded-2xl bg-[#070D1B]/80 border border-cyan-500/30 backdrop-blur-2xl shadow-[0_0_40px_rgba(0,240,255,0.1)] relative overflow-hidden group">
          <div className="absolute top-0 left-0 w-full h-[2px] bg-gradient-to-r from-cyan-500 via-purple-500 to-rose-500" />
          
          <div className="flex items-center gap-4">
            <div className="relative flex h-4 w-4 items-center justify-center">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-400 shadow-[0_0_15px_#00f0ff]"></span>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <Terminal size={18} className="text-cyan-400 animate-pulse" />
                <h1 className="text-base font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-slate-100 to-cyan-200 tracking-widest uppercase">
                  DATANIX // CYBER SOC CENTER
                </h1>
              </div>
              <p className="text-[11px] text-slate-400 flex items-center gap-2 mt-1">
                <Cpu size={12} className="text-cyan-500" /> Active Threat Vector Monitoring & Real-time Telemetry
              </p>
            </div>
          </div>

          <div className="mt-4 md:mt-0 flex items-center gap-3 text-xs">
            <div className="flex items-center gap-2 bg-[#03060D] px-3.5 py-2 rounded-xl border border-rose-500/40 text-rose-300 shadow-[0_0_15px_rgba(244,63,94,0.15)]">
              <Radio size={14} className="animate-pulse text-rose-500" />
              <span className="font-bold tracking-wider text-[11px]">THREAT STATUS: ELEVATED</span>
            </div>
            <div className="hidden sm:flex items-center gap-2 bg-[#03060D] px-3 py-2 rounded-xl border border-cyan-500/30 text-cyan-400">
              <Zap size={14} className="text-cyan-400" />
              <span className="font-mono text-[11px]">LATENCY: 12ms</span>
            </div>
          </div>
        </div>

        {/* 01 — Overview Matrix */}
        <section className="space-y-4">
          <SectionLabel n="01" title="Threat & Defense Matrix" />
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-4">
            
            {/* Risk Gauge HUD Card */}
            <div className="group relative rounded-2xl bg-[#070D1B]/80 p-6 lg:col-span-1 border border-cyan-500/30 shadow-[0_0_30px_rgba(0,0,0,0.6)] backdrop-blur-2xl hover:border-cyan-400 transition-all duration-500 flex flex-col items-center justify-center gap-4 overflow-hidden">
              <div className="absolute inset-0 bg-gradient-to-b from-cyan-500/10 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none" />
              
              {/* Sci-Fi Futuristic HUD Brackets */}
              <div className="absolute top-0 left-0 w-4 h-4 border-t-2 border-l-2 border-cyan-400 shadow-[0_0_10px_#00f0ff]" />
              <div className="absolute top-0 right-0 w-4 h-4 border-t-2 border-r-2 border-cyan-400 shadow-[0_0_10px_#00f0ff]" />
              <div className="absolute bottom-0 left-0 w-4 h-4 border-b-2 border-l-2 border-cyan-400 shadow-[0_0_10px_#00f0ff]" />
              <div className="absolute bottom-0 right-0 w-4 h-4 border-b-2 border-r-2 border-cyan-400 shadow-[0_0_10px_#00f0ff]" />

              <div className="relative z-10 w-full flex flex-col items-center">
                <ScoreGauge score={latestScan.risk_score?.score || 100} />
                <div className="mt-4 px-3.5 py-1.5 bg-[#03060D]/90 border border-cyan-500/30 rounded-xl text-center shadow-[0_0_10px_rgba(0,240,255,0.1)] flex items-center gap-2">
                  <Globe size={13} className="text-cyan-400" />
                  <p className="text-[11px] text-slate-300">
                    Target: <span className="font-mono text-cyan-300 font-bold">{latestScan.target_url}</span>
                  </p>
                </div>
              </div>
            </div>

            {/* Stat Cards Grid */}
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:col-span-3 lg:grid-cols-3">
              <div className="hover:-translate-y-1.5 transition-all duration-300">
                <StatCard label="Total Findings" value={metrics.unresolved_findings} icon={Bug} accent="purple" />
              </div>
              <div className="hover:-translate-y-1.5 transition-all duration-300">
                <StatCard label="Critical Issues" value={metrics.severity_distribution?.critical || 0} icon={ShieldAlert} accent="critical" />
              </div>
              <div className="hover:-translate-y-1.5 transition-all duration-300">
                <StatCard label="Open Incidents" value={metrics.active_incidents} icon={Bell} accent="high" />
              </div>
              <div className="hover:-translate-y-1.5 transition-all duration-300">
                <StatCard label="Scans Completed" value={metrics.total_scans} icon={ListChecks} accent="blue" />
              </div>
              <div className="hover:-translate-y-1.5 transition-all duration-300">
                <StatCard label="Avg. Confidence" value="92" suffix="%" icon={ScanLine} accent="low" />
              </div>

              {/* Action Trigger Card */}
              <Link
                to="/scan"
                className="group relative flex flex-col items-center justify-center gap-3 p-5 text-center rounded-2xl bg-[#070D1B]/80 border border-cyan-500/30 hover:border-cyan-400 transition-all duration-300 shadow-[0_0_20px_rgba(0,240,255,0.1)] hover:shadow-[0_0_35px_rgba(0,240,255,0.35)] backdrop-blur-2xl overflow-hidden hover:scale-[1.02]"
              >
                <div className="absolute inset-0 bg-gradient-to-r from-cyan-500/20 via-purple-500/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
                <div className="relative z-10 border border-cyan-400/80 p-3 rounded-xl text-cyan-400 bg-cyan-950/50 group-hover:bg-cyan-400 group-hover:text-black transition-all duration-300 shadow-[0_0_20px_rgba(0,240,255,0.5)]">
                  <Plus size={24} strokeWidth={2.5} />
                </div>
                <span className="relative z-10 text-xs font-bold uppercase tracking-widest text-cyan-300 group-hover:text-white transition-colors">
                  Initiate New Scan
                </span>
              </Link>
            </div>

          </div>
        </section>

        {/* 02 — Telemetry Charts */}
        <section className="space-y-4">
          <SectionLabel n="02" title="Security Telemetry Analytics" />
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
            
            {/* Line Chart */}
            <div className="rounded-2xl bg-[#070D1B]/80 p-6 lg:col-span-2 border border-cyan-500/25 shadow-[0_0_30px_rgba(0,0,0,0.5)] backdrop-blur-2xl relative hover:border-cyan-500/40 transition-colors">
              <div className="flex justify-between items-center mb-6">
                <div>
                  <h3 className="text-sm font-bold tracking-wider text-slate-100 flex items-center gap-2">
                    <Activity size={16} className="text-cyan-400 animate-pulse" /> Security Score Vector
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">Historical progression across recent scans</p>
                </div>
              </div>
              <ResponsiveContainer width="100%" height={230}>
                <LineChart data={trendData} margin={{ left: -20, right: 10, top: 10 }}>
                  <CartesianGrid stroke="#1F2937" strokeDasharray="3 3" vertical={false} />
                  <XAxis dataKey="date" tick={{ fill: "#6B7280", fontSize: 11 }} axisLine={{ stroke: "#1F2937" }} tickLine={false} />
                  <YAxis tick={{ fill: "#6B7280", fontSize: 11 }} axisLine={false} tickLine={false} domain={[0, 100]} />
                  <Tooltip
                    contentStyle={{ background: "#03060D", border: "1px solid #00F0FF60", borderRadius: "12px", boxShadow: "0 0 25px rgba(0,240,255,0.3)", fontSize: "12px" }}
                    labelStyle={{ color: "#00F0FF", fontWeight: "bold" }}
                  />
                  <Line
                    type="monotone"
                    dataKey="score"
                    stroke="#00F0FF"
                    strokeWidth={3}
                    dot={{ r: 4, fill: "#00F0FF", stroke: "#03060D", strokeWidth: 2 }}
                    activeDot={{ r: 8, fill: "#FF0055", stroke: "#FFF", strokeWidth: 2 }}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>

            {/* Severity Distribution */}
            <div className="rounded-2xl bg-[#070D1B]/80 p-6 border border-cyan-500/25 shadow-[0_0_30px_rgba(0,0,0,0.5)] backdrop-blur-2xl hover:border-cyan-500/40 transition-colors">
              <h3 className="text-sm font-bold tracking-wider text-slate-100">Vulnerability Distribution</h3>
              <p className="mb-4 text-xs text-slate-400 mt-0.5">Current scan threat breakdown</p>
              <ResponsiveContainer width="100%" height={170}>
                <BarChart data={severityChartData} layout="vertical" margin={{ left: 10 }}>
                  <XAxis type="number" hide />
                  <YAxis
                    dataKey="level"
                    type="category"
                    tick={{ fill: "#9CA3AF", fontSize: 11, textTransform: "capitalize" }}
                    axisLine={false}
                    tickLine={false}
                    width={60}
                  />
                  <Tooltip
                    cursor={{ fill: "rgba(0,240,255,0.05)" }}
                    contentStyle={{ background: "#03060D", border: "1px solid #00F0FF40", borderRadius: "8px", fontSize: "12px" }}
                  />
                  <Bar dataKey="count" radius={[0, 6, 6, 0]} barSize={14}>
                    {severityChartData.map((entry) => (
                      <Cell key={entry.level} fill={CYBER_COLORS[entry.level] || severityColors[entry.level] || "#00F0FF"} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>

              <div className="mt-3 space-y-2 border-t border-slate-800/80 pt-3">
                {severityChartData.map((s) => (
                  <div key={s.level} className="flex items-center justify-between text-xs">
                    <span className="flex items-center gap-2 capitalize text-slate-300">
                      <span className="h-2 w-2 rounded-full" style={{ background: CYBER_COLORS[s.level] || severityColors[s.level], boxShadow: `0 0 10px ${CYBER_COLORS[s.level]}` }} />
                      {s.level}
                    </span>
                    <span className="font-mono text-cyan-400 font-bold">{s.count}</span>
                  </div>
                ))}
              </div>
            </div>

          </div>
        </section>

        {/* 03 — Operations Logs */}
        <section className="space-y-4">
          <SectionLabel n="03" title="Active Operations Logs" />
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            
            {/* Recent Scans Log */}
            <div className="rounded-2xl bg-[#070D1B]/80 p-6 border border-cyan-500/25 shadow-[0_0_30px_rgba(0,0,0,0.5)] backdrop-blur-2xl">
              <div className="mb-4 flex items-center justify-between">
                <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider flex items-center gap-2">
                  <ScanLine size={16} className="text-cyan-400" /> Recent Scans History
                </h3>
                <Link to="/reports" className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 hover:underline transition-all">
                  View all <ArrowUpRight size={12} />
                </Link>
              </div>
              <div className="divide-y divide-slate-800/60">
                {scanHistory.slice(0, 4).map((scan) => (
                  <div key={scan.id} className="flex items-center justify-between py-3.5 hover:bg-cyan-500/10 px-3 rounded-xl transition-all duration-200">
                    <div className="min-w-0">
                      <p className="truncate font-mono text-xs text-cyan-200 font-semibold">{scan.target_url}</p>
                      <p className="text-[10px] text-slate-400 mt-0.5">{new Date(scan.started_at).toLocaleDateString()}</p>
                    </div>
                    <div className="flex shrink-0 items-baseline gap-1 bg-[#03060D] px-3 py-1.5 rounded-xl border border-cyan-500/30 shadow-[0_0_12px_rgba(0,0,0,0.6)]">
                      <span className="font-mono text-sm font-bold text-cyan-400">{scan.risk_score?.score || "--"}</span>
                      <span className="text-[10px] text-slate-500">/100</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Live Events Feed */}
            <div className="rounded-2xl bg-[#070D1B]/80 p-6 border border-cyan-500/25 shadow-[0_0_30px_rgba(0,0,0,0.5)] backdrop-blur-2xl">
              <div className="mb-4 flex items-center justify-between">
                <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider flex items-center gap-2">
                  <ShieldAlert size={16} className="text-rose-500 animate-pulse" /> Live Security Events
                </h3>
                <Link to="/events" className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 hover:underline transition-all">
                  View all <ArrowUpRight size={12} />
                </Link>
              </div>
              <div className="divide-y divide-slate-800/60">
                {securityEvents.slice(0, 4).map((ev) => (
                  <div key={ev.id} className="flex items-center justify-between gap-3 py-3.5 hover:bg-rose-500/10 px-3 rounded-xl transition-all duration-200">
                    <div className="min-w-0">
                      <p className="truncate text-xs font-semibold text-slate-200">{ev.type}</p>
                      <p className="truncate font-mono text-[10px] text-slate-400 mt-0.5">{ev.source} · <span className="text-cyan-400">{ev.source_ip}</span></p>
                    </div>
                    <SeverityBadge level={ev.severity} />
                  </div>
                ))}
              </div>
            </div>

          </div>
        </section>

        {/* 04 — Neural Risk Scoring Explanation */}
        {latestScan.id && latestScan.risk_score?.explanation && (
        <section className="space-y-4">
          <SectionLabel n="04" title="AI Neural Risk Engine" />
          <div className="rounded-2xl bg-[#070D1B]/80 p-6 border border-cyan-500/35 shadow-[0_0_35px_rgba(0,240,255,0.08)] backdrop-blur-2xl">
             <h3 className="text-sm font-bold text-slate-100 mb-4 whitespace-pre-wrap flex items-center gap-2">
               <ShieldCheck size={18} className="text-cyan-400" /> Why did the scan receive a score of {latestScan.risk_score?.score}?
             </h3>
             <div className="space-y-2.5">
               {latestScan.risk_score?.explanation.map((e, idx) => (
                   <div key={idx} className="flex justify-between items-center text-sm border-b border-slate-800/80 py-3 px-3.5 rounded-xl hover:bg-cyan-500/10 transition-colors">
                       <div className="flex-1 pr-4">
                           <span className="font-semibold text-cyan-300 mr-2 block sm:inline">{e.finding}:</span>
                           <span className="text-xs text-slate-300">{e.reason}</span>
                       </div>
                       <div className="text-rose-400 font-mono font-bold flex-shrink-0 bg-rose-950/50 px-3 py-1 rounded-lg border border-rose-500/40 text-xs shadow-[0_0_12px_rgba(255,0,85,0.3)]">
                         -{e.deduction} pts
                       </div>
                   </div>
               ))}
               {latestScan.risk_score?.explanation.length === 0 && (
                   <div className="flex items-center gap-2 text-sm text-cyan-400/90 italic p-3 bg-cyan-950/20 rounded-xl border border-cyan-500/20">
                     <Lock size={15} />
                     <span>Zero vulnerabilities detected. Defense perimeter secure!</span>
                   </div>
               )}
             </div>
          </div>
        </section>
        )}

      </div>
    </div>
  );
}

function SectionLabel({ n, title }) {
  return (
    <div className="mb-2 flex items-center gap-3">
      <span className="font-mono text-xs font-bold text-black bg-cyan-400 px-2.5 py-0.5 rounded-md shadow-[0_0_15px_rgba(0,240,255,0.7)]">
        {n}
      </span>
      <h2 className="text-sm font-bold uppercase tracking-widest text-slate-200">{title}</h2>
      <span className="h-px flex-1 bg-gradient-to-r from-cyan-500/50 via-cyan-500/15 to-transparent" />
    </div>
  );
}