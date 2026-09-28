import { useState, useEffect } from "react";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import {
  Gauge,
  AlertCircle,
  Boxes,
  Server,
  Activity,
  Cpu,
  Cloud,
  ShieldHalf,
  Zap,
  Globe,
  Wifi,
  BarChart2,
} from "lucide-react";
import StatCard from "../components/StatCard";
import api from "../lib/api";

const PROTOCOL_COLORS = ["#00F0FF", "#8B5CF6", "#10B981", "#F59E0B"];

export default function Monitoring() {
  const [sysHealth, setSysHealth] = useState(null);
  const [netMetrics, setNetMetrics] = useState([]);
  const [alerts, setAlerts] = useState([]);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [healthRes, alertsRes] = await Promise.all([
          api.get("/monitoring/metrics").catch(() => ({ data: {} })),
          api.get("/monitoring/alerts").catch(() => ({ data: [] })),
        ]);
        setSysHealth(healthRes.data);
        setAlerts(alertsRes.data);
      } catch (err) {
        console.error("Monitoring fetch error:", err);
      }

      try {
        const netRes = await api.get("/network/metrics");
        setNetMetrics(netRes.data || []);
      } catch (err) {
        // Network metrics may be empty — silently handle
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  const cpu = sysHealth?.infrastructure?.cpu_usage_percent || 0;
  const memory = sysHealth?.infrastructure?.ram_usage_percent || 0;
  const requests = sysHealth?.application?.requests_per_minute || 0;
  const errors = sysHealth?.application?.error_rate_percent || 0;
  const dbLatency = sysHealth?.application?.database_latency_ms || 0;
  const blockedReqs = sysHealth?.security?.blocked_requests || 0;
  const activeScans = sysHealth?.security?.active_scans || 0;
  const uptime = sysHealth
    ? `${Math.floor((sysHealth.uptime_seconds || 0) / 60)}m`
    : "...";

  const latestNet = netMetrics[netMetrics.length - 1] || {};
  const chartData = netMetrics
    .map((m) => ({
      time: new Date(m.timestamp).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      }),
      mbps: parseFloat((m.bytes_per_second / 1000).toFixed(2)),
    }))
    .slice(-20);

  const protocolData = [
    { name: "HTTP/S", value: 65 },
    { name: "DNS", value: 20 },
    { name: "SSH", value: 5 },
    { name: "Other", value: 10 },
  ];

  return (
    <div className="relative min-h-screen font-mono text-slate-100 p-2 sm:p-6 overflow-hidden bg-[#020408] space-y-6">
      {/* Background Grid */}
      <div className="fixed inset-0 z-0 pointer-events-none bg-[linear-gradient(to_right,#00f0ff08_1px,transparent_1px),linear-gradient(to_bottom,#00f0ff08_1px,transparent_1px)] bg-[size:3rem_3rem]" />
      <div className="fixed -top-24 -right-24 z-0 h-96 w-96 rounded-full bg-cyan-500/10 blur-[150px] pointer-events-none" />
      <div className="fixed bottom-0 left-1/4 z-0 h-96 w-96 rounded-full bg-blue-600/10 blur-[150px] pointer-events-none" />

      <div className="relative z-10 max-w-7xl mx-auto space-y-6">
        {/* Header Banner */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 rounded-2xl border border-cyan-500/30 bg-[#070D1B]/80 p-5 shadow-[0_0_30px_rgba(0,240,255,0.08)] backdrop-blur-2xl">
          <div className="flex items-center gap-3.5">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-cyan-950/60 border border-cyan-400/60 text-cyan-400 shadow-[0_0_15px_rgba(0,240,255,0.3)]">
              <Cloud size={22} className="animate-pulse" />
            </div>
            <div>
              <h1 className="text-lg font-extrabold tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-slate-100 to-blue-300 uppercase">
                Infrastructure Health Monitor
              </h1>
              <p className="text-[11px] text-slate-400 flex items-center gap-1 mt-0.5">
                <Cpu size={12} className="text-cyan-400" /> Live telemetry
                from backend API, SNID network &amp; security sensors.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3 text-xs">
            <div className="flex items-center gap-2 bg-[#03060D] px-3.5 py-2 rounded-xl border border-emerald-500/40 text-emerald-300 shadow-[0_0_12px_rgba(16,185,129,0.15)]">
              <span className="relative flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-400" />
              </span>
              <span className="font-bold tracking-wider">API ONLINE</span>
            </div>
            <div className="hidden sm:flex items-center gap-2 bg-[#03060D] px-3 py-2 rounded-xl border border-cyan-500/30 text-cyan-400">
              <Zap size={13} />
              <span>Uptime: {uptime}</span>
            </div>
          </div>
        </div>

        {/* Stat Cards Grid */}
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <StatCard label="CPU Usage" value={cpu} suffix="%" icon={Cpu} accent="blue" />
          <StatCard label="RAM Usage" value={memory} suffix="%" icon={BarChart2} accent="purple" />
          <StatCard label="Requests / min" value={requests} icon={Gauge} accent="low" />
          <StatCard label="Error Rate" value={errors} suffix="%" icon={AlertCircle} accent="high" />
        </div>

        {/* Secondary Stats */}
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <StatCard label="DB Latency" value={dbLatency} suffix="ms" icon={Server} accent="blue" />
          <StatCard label="Blocked Reqs" value={blockedReqs} icon={ShieldHalf} accent="critical" />
          <StatCard label="Active Scans" value={activeScans} icon={Activity} accent="purple" />
          <StatCard label="Network Packets" value={latestNet.packets_per_second || 0} icon={Wifi} accent="low" />
        </div>

        {/* Charts Row */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          {/* Bandwidth Line Chart */}
          <div className="rounded-2xl bg-[#070D1B]/80 p-6 lg:col-span-2 border border-cyan-500/25 shadow-[0_0_30px_rgba(0,0,0,0.5)] backdrop-blur-2xl hover:border-cyan-500/40 transition-colors">
            <div className="mb-1 flex items-center gap-2.5">
              <Server size={15} className="text-cyan-400" />
              <h3 className="font-bold text-sm text-slate-100 uppercase tracking-wider">
                Bandwidth Trend
              </h3>
            </div>
            <p className="mb-5 text-xs text-slate-400">
              Live byte throughput trace · SNID Network Telemetry
            </p>
            <ResponsiveContainer width="100%" height={200}>
              <LineChart
                data={chartData.length > 0 ? chartData : [{ time: "No data", mbps: 0 }]}
                margin={{ left: -20, right: 10, top: 10 }}
              >
                <CartesianGrid stroke="#1F2937" strokeDasharray="3 3" vertical={false} />
                <XAxis
                  dataKey="time"
                  tick={{ fill: "#6B7280", fontSize: 11 }}
                  axisLine={{ stroke: "#1F2937" }}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fill: "#6B7280", fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip
                  contentStyle={{
                    background: "#03060D",
                    border: "1px solid #00F0FF60",
                    borderRadius: "8px",
                    fontSize: "12px",
                  }}
                />
                <Line
                  type="monotone"
                  dataKey="mbps"
                  stroke="#00F0FF"
                  strokeWidth={2.5}
                  dot={{ r: 3, fill: "#00F0FF" }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>

          {/* Protocol Pie Chart */}
          <div className="rounded-2xl bg-[#070D1B]/80 p-6 border border-cyan-500/25 shadow-[0_0_30px_rgba(0,0,0,0.5)] backdrop-blur-2xl hover:border-cyan-500/40 transition-colors">
            <div className="mb-1 flex items-center gap-2.5">
              <Boxes size={15} className="text-purple-400" />
              <h3 className="font-bold text-sm text-slate-100 uppercase tracking-wider">
                Protocol Mix
              </h3>
            </div>
            <ResponsiveContainer width="100%" height={170}>
              <PieChart>
                <Pie
                  data={protocolData}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={45}
                  outerRadius={70}
                  paddingAngle={3}
                >
                  {protocolData.map((entry, idx) => (
                    <Cell
                      key={entry.name}
                      fill={PROTOCOL_COLORS[idx % PROTOCOL_COLORS.length]}
                    />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: "#03060D",
                    border: "1px solid #00F0FF40",
                    borderRadius: "8px",
                    fontSize: "12px",
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="mt-2 grid grid-cols-2 gap-1.5">
              {protocolData.map((p, idx) => (
                <div key={p.name} className="flex items-center gap-1.5 text-xs text-slate-300">
                  <span
                    className="h-2 w-2 rounded-full"
                    style={{
                      background: PROTOCOL_COLORS[idx % PROTOCOL_COLORS.length],
                      boxShadow: `0 0 6px ${PROTOCOL_COLORS[idx % PROTOCOL_COLORS.length]}`,
                    }}
                  />
                  {p.name}{" "}
                  <span className="text-slate-500">{p.value}%</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* System Alerts */}
        <div className="rounded-2xl bg-[#070D1B]/80 p-6 border border-cyan-500/25 shadow-[0_0_30px_rgba(0,0,0,0.4)] backdrop-blur-2xl">
          <div className="mb-4 flex items-center gap-2.5">
            <AlertCircle size={16} className="text-yellow-400" />
            <h3 className="font-bold text-sm text-slate-100 uppercase tracking-wider">
              System Alerts
            </h3>
          </div>
          {alerts.length === 0 ? (
            <p className="text-xs text-slate-500 font-mono">
              [NOMINAL] No active system alerts.
            </p>
          ) : (
            <div className="space-y-2">
              {alerts.map((alert) => (
                <div
                  key={alert.id}
                  className={`flex items-center justify-between rounded-xl border px-4 py-3 text-xs font-mono ${
                    alert.severity === "warning"
                      ? "border-yellow-500/30 bg-yellow-950/20 text-yellow-300"
                      : "border-cyan-500/20 bg-cyan-950/10 text-cyan-300"
                  }`}
                >
                  <span className="flex items-center gap-2">
                    <Globe size={13} className="shrink-0" />
                    {alert.message}
                  </span>
                  <span className="text-slate-500 text-[10px] uppercase tracking-wider">
                    {alert.severity}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
