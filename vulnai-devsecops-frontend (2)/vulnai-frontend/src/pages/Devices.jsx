import { useState, useEffect, useRef, useMemo } from "react";
import {
  Cpu,
  Camera,
  Router as RouterIcon,
  Plug,
  HelpCircle,
  Wifi,
  WifiOff,
  ShieldCheck,
  Terminal,
  Sparkles,
  Server,
  Search,
  RefreshCw,
  Filter,
  Radio,
  Eye,
  X,
  CheckCircle,
  AlertTriangle,
  Play,
  Layers,
  Clock,
  ShieldAlert,
} from "lucide-react";
import StatCard from "../components/StatCard";
import api from "../lib/api";

const ICONS = {
  "IoT Sensor": Cpu,
  "Edge Compute": RouterIcon,
  Camera,
  "IoT Actuator": Plug,
  Unclassified: HelpCircle,
};

const RISK_STYLES = {
  low: "border-emerald-500/40 bg-emerald-950/40 text-emerald-400 shadow-[0_0_10px_rgba(16,185,129,0.2)]",
  medium: "border-yellow-500/40 bg-yellow-950/40 text-yellow-400 shadow-[0_0_10px_rgba(234,179,8,0.2)]",
  high: "border-rose-500/40 bg-rose-950/40 text-rose-400 shadow-[0_0_15px_rgba(244,63,94,0.3)]",
};

export default function Devices() {
  const [devices, setDevices] = useState([]);
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [activeFilter, setActiveFilter] = useState("all"); // all, online, stale, known, unknown, high_risk
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Discovery modal state
  const [showDiscoveryModal, setShowDiscoveryModal] = useState(false);
  const [discoverySubnet, setDiscoverySubnet] = useState("");
  const [activeSweep, setActiveSweep] = useState(false);
  const [discovering, setDiscovering] = useState(false);
  const [discoveryMessage, setDiscoveryMessage] = useState(null);

  // Wireless Telemetry View Tab (Devices vs ESP32 RF Sensor)
  const [viewTab, setViewTab] = useState("inventory"); // 'inventory' | 'wireless'
  const [wirelessEvents, setWirelessEvents] = useState([]);
  const [sensors, setSensors] = useState([]);

  const canvasRef = useRef(null);

  // Background Interactive Canvas Particle Network
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");

    let animationFrameId;
    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    const particles = [];
    const particleCount = Math.floor((width * height) / 16000);

    class Particle {
      constructor() {
        this.x = Math.random() * width;
        this.y = Math.random() * height;
        this.vx = (Math.random() - 0.5) * 0.4;
        this.vy = (Math.random() - 0.5) * 0.4;
        this.radius = Math.random() * 1.5 + 1;
      }

      update() {
        this.x += this.vx;
        this.y += this.vy;

        if (this.x < 0 || this.x > width) this.vx *= -1;
        if (this.y < 0 || this.y > height) this.vy *= -1;
      }

      draw() {
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
        ctx.fillStyle = "rgba(0, 240, 255, 0.6)";
        ctx.fill();
      }
    }

    for (let i = 0; i < particleCount; i++) {
      particles.push(new Particle());
    }

    const animate = () => {
      ctx.clearRect(0, 0, width, height);

      for (let i = 0; i < particles.length; i++) {
        particles[i].update();
        particles[i].draw();

        for (let j = i + 1; j < particles.length; j++) {
          const dx = particles[i].x - particles[j].x;
          const dy = particles[i].y - particles[j].y;
          const distance = Math.sqrt(dx * dx + dy * dy);

          if (distance < 100) {
            ctx.beginPath();
            ctx.strokeStyle = `rgba(0, 240, 255, ${0.2 - distance / 100})`;
            ctx.lineWidth = 0.5;
            ctx.moveTo(particles[i].x, particles[i].y);
            ctx.lineTo(particles[j].x, particles[j].y);
            ctx.stroke();
          }
        }
      }

      animationFrameId = requestAnimationFrame(animate);
    };

    animate();

    const handleResize = () => {
      if (!canvas) return;
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };

    window.addEventListener("resize", handleResize);
    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener("resize", handleResize);
    };
  }, []);

  const loadData = async (silent = false) => {
    if (!silent) setRefreshing(true);
    try {
      const [devRes, sumRes] = await Promise.all([
        api.get("/devices/"),
        api.get("/devices/summary"),
      ]);
      setDevices(devRes.data || []);
      setSummary(sumRes.data || null);
      setLastUpdated(new Date());

      // If on wireless tab, also fetch sensors and wireless events
      if (viewTab === "wireless") {
        const [wRes, sRes] = await Promise.all([
          api.get("/snid/wireless-events"),
          api.get("/snid/sensors"),
        ]);
        setWirelessEvents(wRes.data || []);
        setSensors(sRes.data || []);
      }
    } catch (err) {
      console.error("Failed to load device inventory:", err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [viewTab]);

  // Periodic polling if autoRefresh is enabled
  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(() => {
      loadData(true);
    }, 15000);
    return () => clearInterval(interval);
  }, [autoRefresh, viewTab]);

  const handleTriggerDiscovery = async (e) => {
    e.preventDefault();
    setDiscovering(true);
    setDiscoveryMessage(null);
    try {
      const res = await api.post("/devices/discovery", {
        authorized_subnet: discoverySubnet.trim() || null,
        active_sweep: activeSweep,
      });
      setDiscoveryMessage({
        type: "success",
        text: `Discovery complete in ${res.data.duration_seconds}s. Found ${res.data.new_devices_found} new nodes, updated ${res.data.updated_devices}.`,
      });
      await loadData();
      setTimeout(() => setShowDiscoveryModal(false), 2000);
    } catch (err) {
      setDiscoveryMessage({
        type: "error",
        text: err.response?.data?.detail || err.message || "Discovery failed.",
      });
    } finally {
      setDiscovering(false);
    }
  };

  const handleToggleAuthorization = async (device) => {
    const newAuth = !device.is_authorized;
    const newClass = newAuth ? "authorized" : "unknown";
    try {
      await api.patch(`/devices/${device.id}`, {
        is_authorized: newAuth,
        inventory_classification: newClass,
      });
      setDevices((prev) =>
        prev.map((d) =>
          d.id === device.id
            ? { ...d, is_authorized: newAuth, inventory_classification: newClass }
            : d
        )
      );
      if (selectedDevice && selectedDevice.id === device.id) {
        setSelectedDevice((prev) => ({
          ...prev,
          is_authorized: newAuth,
          inventory_classification: newClass,
        }));
      }
      loadData(true);
    } catch (err) {
      console.error("Failed to update device classification:", err);
    }
  };

  // Filtered devices list
  const filteredDevices = useMemo(() => {
    return devices.filter((d) => {
      // Search query
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase().trim();
        const pool = `${d.name || ""} ${d.ip_address || ""} ${d.mac_address || ""} ${d.hostname || ""} ${d.manufacturer || ""}`.toLowerCase();
        if (!pool.includes(q)) return false;
      }

      // Filter tabs
      if (activeFilter === "online") return d.status === "online";
      if (activeFilter === "stale") return d.status === "stale";
      if (activeFilter === "known") return d.inventory_classification === "authorized" || d.is_authorized;
      if (activeFilter === "unknown") return d.inventory_classification !== "authorized" && !d.is_authorized;
      if (activeFilter === "high_risk") return d.risk === "high";

      return true;
    });
  }, [devices, searchQuery, activeFilter]);

  if (loading && !devices.length) {
    return (
      <div className="relative min-h-screen font-mono text-slate-100 p-6 flex items-center justify-center bg-[#020408]">
        <div className="flex items-center gap-2.5 text-xs text-cyan-400 font-mono">
          <Sparkles size={18} className="animate-spin text-cyan-400" /> Scanning Authorized Network Topology...
        </div>
      </div>
    );
  }

  const onlineCount = summary?.devices_online ?? devices.filter((d) => d.status === "online").length;
  const knownCount = summary?.total_known_devices ?? devices.filter((d) => d.is_authorized || d.inventory_classification === "authorized").length;
  const unknownCount = summary?.unknown_devices ?? devices.filter((d) => !d.is_authorized && d.inventory_classification !== "authorized").length;
  const highRiskCount = summary?.high_risk_devices ?? devices.filter((d) => d.risk === "high").length;

  return (
    <div className="relative min-h-screen font-mono text-slate-100 p-2 sm:p-6 overflow-hidden bg-[#020408]">
      {/* Full Screen Interactive Canvas Background */}
      <canvas
        ref={canvasRef}
        className="fixed inset-0 z-0 h-screen w-screen pointer-events-none bg-[#020408] opacity-75"
      />

      {/* Futuristic Cyber Overlay Grid */}
      <div className="fixed inset-0 z-0 pointer-events-none bg-[linear-gradient(to_right,#00f0ff08_1px,transparent_1px),linear-gradient(to_bottom,#00f0ff08_1px,transparent_1px)] bg-[size:3rem_3rem]" />
      <div className="fixed -top-24 -right-24 z-0 h-96 w-96 rounded-full bg-cyan-500/10 blur-[150px] pointer-events-none" />
      <div className="fixed top-1/2 -left-24 z-0 h-96 w-96 rounded-full bg-blue-600/10 blur-[150px] pointer-events-none" />

      {/* Main Content Area */}
      <div className="relative z-10 mx-auto max-w-6xl space-y-6">
        {/* Header Bar */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 rounded-2xl border border-cyan-500/30 bg-[#070D1B]/80 p-5 shadow-[0_0_30px_rgba(0,240,255,0.08)] backdrop-blur-2xl">
          <div className="flex items-center gap-3.5">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-cyan-950/60 border border-cyan-400/60 text-cyan-400 shadow-[0_0_15px_rgba(0,240,255,0.3)]">
              <Server size={22} className="animate-pulse" />
            </div>
            <div>
              <h1 className="text-lg font-extrabold tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-slate-100 to-blue-300 uppercase">
                SNID // Network Inventory & Telemetry
              </h1>
              <p className="text-[11px] text-slate-400 flex items-center gap-1 mt-0.5">
                <Cpu size={12} className="text-cyan-400" /> Authorized device discovery, MAC/OUI inventory, & ESP32 wireless sensing.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            {/* View Switcher: Device Inventory vs ESP32 RF */}
            <div className="flex items-center rounded-xl border border-cyan-500/30 bg-[#03060D] p-1">
              <button
                onClick={() => setViewTab("inventory")}
                className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-bold transition-all ${
                  viewTab === "inventory"
                    ? "bg-cyan-500/20 text-cyan-300 border border-cyan-400/50 shadow-[0_0_10px_rgba(0,240,255,0.2)]"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                <Layers size={13} /> IP/MAC Inventory
              </button>
              <button
                onClick={() => setViewTab("wireless")}
                className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-bold transition-all ${
                  viewTab === "wireless"
                    ? "bg-cyan-500/20 text-cyan-300 border border-cyan-400/50 shadow-[0_0_10px_rgba(0,240,255,0.2)]"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                <Radio size={13} className="text-rose-400 animate-pulse" /> ESP32 RF & Rogue AP
              </button>
            </div>

            {/* Run Discovery Trigger Button */}
            <button
              onClick={() => setShowDiscoveryModal(true)}
              className="flex items-center gap-1.5 rounded-xl border border-cyan-400 bg-cyan-950/60 px-3.5 py-2 text-xs font-bold text-cyan-300 hover:bg-cyan-900/60 hover:shadow-[0_0_15px_rgba(0,240,255,0.4)] transition-all"
            >
              <Play size={13} className="text-cyan-400" /> Run Discovery
            </button>

            {/* Refresh Button */}
            <button
              onClick={() => loadData()}
              disabled={refreshing}
              className="flex items-center gap-1.5 rounded-xl border border-slate-700 bg-[#03060D] px-3 py-2 text-xs text-slate-300 hover:border-cyan-500/50 hover:text-cyan-300 transition-all disabled:opacity-50"
              title="Manual Refresh"
            >
              <RefreshCw size={13} className={refreshing ? "animate-spin text-cyan-400" : ""} />
            </button>
          </div>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-4">
          <div className="rounded-2xl border border-cyan-500/25 bg-[#070D1B]/80 p-4 shadow-[0_0_20px_rgba(0,240,255,0.05)] backdrop-blur-xl">
            <StatCard label="Devices Online" value={onlineCount} suffix={`/ ${devices.length}`} icon={Wifi} accent="blue" />
          </div>
          <div className="rounded-2xl border border-emerald-500/25 bg-[#070D1B]/80 p-4 shadow-[0_0_20px_rgba(16,185,129,0.05)] backdrop-blur-xl">
            <StatCard label="Known / Authorized" value={knownCount} icon={ShieldCheck} accent="low" />
          </div>
          <div className="rounded-2xl border border-yellow-500/25 bg-[#070D1B]/80 p-4 shadow-[0_0_20px_rgba(234,179,8,0.05)] backdrop-blur-xl">
            <StatCard label="Unknown Nodes" value={unknownCount} icon={HelpCircle} accent="high" />
          </div>
          <div className="rounded-2xl border border-rose-500/25 bg-[#070D1B]/80 p-4 shadow-[0_0_20px_rgba(244,63,94,0.05)] backdrop-blur-xl">
            <StatCard label="High Risk Nodes" value={highRiskCount} icon={RouterIcon} accent="critical" />
          </div>
        </div>

        {/* Main Tab Views */}
        {viewTab === "inventory" ? (
          <div className="space-y-4">
            {/* Filter and Search Control Bar */}
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between rounded-2xl border border-cyan-500/20 bg-[#070D1B]/80 p-4 shadow-lg backdrop-blur-xl">
              {/* Search Bar */}
              <div className="relative w-full sm:max-w-md">
                <Search size={14} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-cyan-400/60" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search IP, MAC, hostname, or manufacturer..."
                  className="w-full rounded-xl border border-cyan-500/30 bg-[#03060D] py-2 pl-9 pr-4 text-xs text-slate-100 placeholder:text-slate-500 focus:border-cyan-400 focus:outline-none"
                />
              </div>

              {/* Status Filter Pills */}
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-[10px] font-bold uppercase text-slate-400 flex items-center gap-1 mr-1">
                  <Filter size={11} className="text-cyan-400" /> Filter:
                </span>
                {[
                  { id: "all", label: "All", count: devices.length },
                  { id: "online", label: "Online", count: onlineCount },
                  { id: "stale", label: "Stale", count: summary?.stale_devices ?? 0 },
                  { id: "known", label: "Authorized", count: knownCount },
                  { id: "unknown", label: "Unknown", count: unknownCount },
                  { id: "high_risk", label: "High Risk", count: highRiskCount },
                ].map((tab) => (
                  <button
                    key={tab.id}
                    onClick={() => setActiveFilter(tab.id)}
                    className={`rounded-lg px-2.5 py-1 text-[11px] font-bold uppercase transition-all ${
                      activeFilter === tab.id
                        ? "bg-cyan-500/20 border border-cyan-400 text-cyan-300 shadow-[0_0_10px_rgba(0,240,255,0.2)]"
                        : "border border-slate-800 bg-[#03060D] text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    {tab.label} ({tab.count})
                  </button>
                ))}
              </div>
            </div>

            {/* Devices Table Container */}
            <div className="rounded-2xl border border-cyan-500/25 bg-[#070D1B]/80 shadow-[0_0_40px_rgba(0,240,255,0.05)] backdrop-blur-2xl overflow-hidden">
              {/* Table Header */}
              <div className="hidden grid-cols-12 gap-3 border-b border-cyan-500/20 bg-[#03060D]/90 px-6 py-3.5 font-mono text-[11px] uppercase tracking-wider text-cyan-400 font-bold md:grid">
                <div className="col-span-3">Device Node / Hostname</div>
                <div className="col-span-2">IP Address</div>
                <div className="col-span-2">MAC / Manufacturer</div>
                <div className="col-span-2">Discovery Source</div>
                <div className="col-span-1">Status</div>
                <div className="col-span-1">Risk</div>
                <div className="col-span-1 text-right">Action</div>
              </div>

              {/* Table Rows or Empty State */}
              {filteredDevices.length === 0 ? (
                <div className="p-10 text-center space-y-3 font-mono">
                  <div className="inline-flex h-12 w-12 items-center justify-center rounded-xl bg-cyan-950/40 border border-cyan-500/30 text-cyan-400">
                    <WifiOff size={24} />
                  </div>
                  <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider">
                    No matching devices discovered in local inventory
                  </h3>
                  <p className="max-w-md mx-auto text-xs text-slate-400">
                    Run an authorized discovery sweep to populate your local ARP table and network inventory. Devices on isolated VLANs or sleeping hosts may require direct router access.
                  </p>
                  <button
                    onClick={() => setShowDiscoveryModal(true)}
                    className="inline-flex items-center gap-2 rounded-xl border border-cyan-400 bg-cyan-500/20 px-4 py-2 text-xs font-bold text-cyan-300 hover:bg-cyan-500/30 transition-all shadow-[0_0_15px_rgba(0,240,255,0.2)]"
                  >
                    <Play size={13} /> Trigger Authorized Discovery
                  </button>
                </div>
              ) : (
                <div className="divide-y divide-cyan-500/10">
                  {filteredDevices.map((d) => {
                    const Icon = ICONS[d.device_type] || HelpCircle;
                    const risk_level = d.risk || (d.status === "warning" ? "high" : "low");
                    const isOnline = d.status === "online";
                    const isAuthorized = d.is_authorized || d.inventory_classification === "authorized";

                    return (
                      <div
                        key={d.id}
                        className="grid grid-cols-1 gap-2 px-6 py-4 transition-all duration-300 hover:bg-cyan-950/20 md:grid-cols-12 md:items-center md:gap-3"
                      >
                        {/* Device Node & Hostname */}
                        <div className="flex items-center gap-3 md:col-span-3">
                          <div
                            className={`rounded-xl border p-2.5 shadow-md ${
                              isOnline
                                ? "border-cyan-500/40 bg-cyan-950/40 text-cyan-400"
                                : "border-slate-700 bg-slate-900/60 text-slate-500"
                            }`}
                          >
                            <Icon size={16} />
                          </div>
                          <div className="truncate">
                            <p className="text-xs font-bold text-slate-100 truncate flex items-center gap-1.5">
                              {d.name}
                              {isAuthorized && (
                                <ShieldCheck size={12} className="text-emerald-400" title="Authorized Inventory" />
                              )}
                            </p>
                            <p className="text-[11px] text-slate-400 truncate">
                              {d.hostname || d.device_type}
                            </p>
                          </div>
                        </div>

                        {/* IP Address */}
                        <div className="font-mono text-xs text-cyan-300 md:col-span-2">
                          {d.ip_address}
                        </div>

                        {/* MAC & Manufacturer */}
                        <div className="font-mono text-xs md:col-span-2 truncate">
                          <div className="text-slate-300 truncate">{d.mac_address || "-"}</div>
                          <div className="text-[10px] text-slate-400 truncate">{d.manufacturer || "Unknown"}</div>
                        </div>

                        {/* Discovery Source */}
                        <div className="text-xs text-slate-400 md:col-span-2 truncate">
                          <span className="rounded bg-slate-800/80 px-2 py-0.5 text-[10px] font-mono text-cyan-400 border border-slate-700">
                            {d.discovery_source || "arp_cache"}
                          </span>
                        </div>

                        {/* Telemetry Status */}
                        <div className="flex items-center gap-1.5 text-xs md:col-span-1">
                          {isOnline ? (
                            <Wifi size={13} className="text-emerald-400 drop-shadow-[0_0_6px_#10b981]" />
                          ) : (
                            <WifiOff size={13} className="text-slate-500" />
                          )}
                          <span className={isOnline ? "text-emerald-400 font-bold" : "text-slate-500"}>
                            {d.status}
                          </span>
                        </div>

                        {/* Risk */}
                        <div className="md:col-span-1">
                          <span
                            className={`inline-flex rounded-md border px-2 py-0.5 font-mono text-[9px] uppercase tracking-wider font-extrabold ${
                              RISK_STYLES[risk_level] || RISK_STYLES.low
                            }`}
                          >
                            {risk_level}
                          </span>
                        </div>

                        {/* Action: View Details */}
                        <div className="flex items-center justify-end gap-2 md:col-span-1">
                          <button
                            onClick={() => setSelectedDevice(d)}
                            className="rounded-lg border border-cyan-500/30 bg-[#03060D] p-1.5 text-slate-400 hover:text-cyan-300 hover:border-cyan-400 transition-all"
                            title="Inspect Device Telemetry"
                          >
                            <Eye size={13} />
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Last Updated Timestamp & Limitations Bar */}
            <div className="flex flex-col sm:flex-row items-center justify-between text-[11px] text-slate-400 px-2">
              <span className="flex items-center gap-1.5">
                <Clock size={12} className="text-cyan-400" /> Last synchronized:{" "}
                {lastUpdated ? lastUpdated.toLocaleTimeString() : "Never"}
              </span>
              <span className="text-slate-400 text-right">
                Authorized subnet boundaries strictly enforced. Zero fabricated MACs or hostnames.
              </span>
            </div>
          </div>
        ) : (
          /* ESP32 RF & Rogue AP Wireless Telemetry Tab */
          <div className="space-y-6">
            {/* Sensors Status Card */}
            <div className="rounded-2xl border border-cyan-500/25 bg-[#070D1B]/80 p-5 shadow-xl backdrop-blur-xl">
              <div className="flex items-center justify-between border-b border-cyan-500/20 pb-3 mb-4">
                <div className="flex items-center gap-2">
                  <Radio size={16} className="text-cyan-400" />
                  <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200">
                    ESP32 Defensive Sensor Nodes (ProjectHydra Feeds)
                  </h3>
                </div>
                <span className="rounded-lg bg-cyan-950/60 border border-cyan-500/40 px-2.5 py-1 text-[10px] font-bold text-cyan-300">
                  {sensors.length} ACTIVE SENSORS
                </span>
              </div>

              {sensors.length === 0 ? (
                <div className="p-4 text-center text-xs text-slate-400">
                  No ESP32 hardware sensors registered yet. Sensors authenticate to{" "}
                  <code className="text-cyan-400">POST /api/snid/wireless-events</code> using{" "}
                  <code className="text-cyan-400">X-Sensor-Key</code>.
                </div>
              ) : (
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  {sensors.map((s) => (
                    <div
                      key={s.id}
                      className="rounded-xl border border-cyan-500/20 bg-[#03060D] p-3 text-xs space-y-1.5"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-slate-100">{s.name}</span>
                        <span className="flex items-center gap-1 text-[10px] text-emerald-400">
                          <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                          {s.status}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-400 font-mono">ID: {s.sensor_id}</div>
                      <div className="text-[10px] text-slate-500">Firmware: {s.firmware_version}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Wireless RF Security Events & Rogue AP Observations */}
            <div className="rounded-2xl border border-rose-500/25 bg-[#070D1B]/80 p-5 shadow-xl backdrop-blur-xl space-y-4">
              <div className="flex items-center justify-between border-b border-rose-500/20 pb-3">
                <div className="flex items-center gap-2">
                  <ShieldAlert size={16} className="text-rose-400" />
                  <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200">
                    Defensive RF Alerts & Rogue AP Detection
                  </h3>
                </div>
                <span className="text-xs text-slate-400">
                  Deauth burst heuristics & unauthorized BSSID detection
                </span>
              </div>

              {wirelessEvents.length === 0 ? (
                <div className="p-6 text-center text-xs text-slate-400">
                  No anomalous RF events or rogue access points detected in observation window.
                </div>
              ) : (
                <div className="space-y-2.5">
                  {wirelessEvents.map((ev) => (
                    <div
                      key={ev.id}
                      className={`rounded-xl border p-4 text-xs space-y-2 transition-all ${
                        ev.severity === "high"
                          ? "border-rose-500/40 bg-rose-950/20 text-rose-200"
                          : ev.severity === "medium"
                          ? "border-yellow-500/40 bg-yellow-950/20 text-yellow-200"
                          : "border-cyan-500/30 bg-[#03060D] text-slate-300"
                      }`}
                    >
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                        <div className="font-bold flex items-center gap-2">
                          <AlertTriangle size={14} className={ev.severity === "high" ? "text-rose-400" : "text-yellow-400"} />
                          {ev.title}
                        </div>
                        <span className="rounded px-2 py-0.5 text-[10px] font-mono uppercase bg-black/40 border border-current">
                          {ev.verification_status} ({ev.confidence}% confidence)
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-300">{ev.recommendation}</p>
                      <div className="flex flex-wrap items-center gap-3 text-[10px] text-slate-400 font-mono pt-1 border-t border-slate-800">
                        <span>BSSID: {ev.bssid || "N/A"}</span>
                        <span>SSID: {ev.ssid || "Hidden/None"}</span>
                        <span>Channel: {ev.channel || "N/A"}</span>
                        <span>Rule: {ev.detection_rule}</span>
                        <span>Sensor: {ev.sensor_id}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Device Details Modal */}
        {selectedDevice && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-md p-4">
            <div className="relative w-full max-w-xl rounded-2xl border border-cyan-500/30 bg-[#070D1B] p-6 shadow-[0_0_50px_rgba(0,240,255,0.2)] font-mono text-slate-100 space-y-4">
              <div className="flex items-center justify-between border-b border-cyan-500/20 pb-3">
                <div className="flex items-center gap-2.5">
                  <Server size={18} className="text-cyan-400" />
                  <h3 className="text-sm font-bold uppercase tracking-wider text-slate-100">
                    Device Node Telemetry: {selectedDevice.name}
                  </h3>
                </div>
                <button
                  onClick={() => setSelectedDevice(null)}
                  className="rounded-lg p-1 text-slate-400 hover:text-white"
                >
                  <X size={16} />
                </button>
              </div>

              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="rounded-xl border border-slate-800 bg-[#03060D] p-3 space-y-1">
                  <span className="text-[10px] text-slate-500 uppercase">IP Address</span>
                  <p className="font-bold text-cyan-300">{selectedDevice.ip_address}</p>
                </div>
                <div className="rounded-xl border border-slate-800 bg-[#03060D] p-3 space-y-1">
                  <span className="text-[10px] text-slate-500 uppercase">MAC Address</span>
                  <p className="font-bold text-slate-200">{selectedDevice.mac_address || "Unavailable"}</p>
                </div>
                <div className="rounded-xl border border-slate-800 bg-[#03060D] p-3 space-y-1">
                  <span className="text-[10px] text-slate-500 uppercase">Manufacturer (OUI)</span>
                  <p className="font-bold text-slate-200">{selectedDevice.manufacturer || "Unknown Vendor"}</p>
                </div>
                <div className="rounded-xl border border-slate-800 bg-[#03060D] p-3 space-y-1">
                  <span className="text-[10px] text-slate-500 uppercase">Hostname</span>
                  <p className="font-bold text-slate-200">{selectedDevice.hostname || "None detected"}</p>
                </div>
                <div className="rounded-xl border border-slate-800 bg-[#03060D] p-3 space-y-1">
                  <span className="text-[10px] text-slate-500 uppercase">Discovery Source</span>
                  <p className="font-bold text-cyan-400">{selectedDevice.discovery_source}</p>
                </div>
                <div className="rounded-xl border border-slate-800 bg-[#03060D] p-3 space-y-1">
                  <span className="text-[10px] text-slate-500 uppercase">Confidence Score</span>
                  <p className="font-bold text-emerald-400">{selectedDevice.confidence || 80}%</p>
                </div>
              </div>

              {/* Evidence String */}
              {selectedDevice.evidence && (
                <div className="rounded-xl border border-cyan-500/20 bg-[#03060D] p-3 text-xs space-y-1">
                  <span className="text-[10px] text-slate-500 uppercase">Raw Observation Evidence</span>
                  <p className="font-mono text-[11px] text-slate-300">{selectedDevice.evidence}</p>
                </div>
              )}

              {/* Classification Action */}
              <div className="flex items-center justify-between border-t border-cyan-500/20 pt-4">
                <span className="text-xs text-slate-400">
                  Inventory:{" "}
                  <span className={selectedDevice.is_authorized ? "text-emerald-400 font-bold" : "text-yellow-400 font-bold"}>
                    {selectedDevice.is_authorized ? "AUTHORIZED" : "UNKNOWN"}
                  </span>
                </span>
                <button
                  onClick={() => handleToggleAuthorization(selectedDevice)}
                  className={`rounded-xl border px-4 py-2 text-xs font-bold transition-all ${
                    selectedDevice.is_authorized
                      ? "border-yellow-500/50 bg-yellow-950/40 text-yellow-300 hover:bg-yellow-900/50"
                      : "border-emerald-500/50 bg-emerald-950/40 text-emerald-300 hover:bg-emerald-900/50"
                  }`}
                >
                  {selectedDevice.is_authorized ? "Mark as Unknown" : "Mark as Authorized"}
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Trigger Discovery Modal */}
        {showDiscoveryModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-md p-4">
            <div className="relative w-full max-w-lg rounded-2xl border border-cyan-500/30 bg-[#070D1B] p-6 shadow-[0_0_50px_rgba(0,240,255,0.2)] font-mono text-slate-100 space-y-4">
              <div className="flex items-center justify-between border-b border-cyan-500/20 pb-3">
                <div className="flex items-center gap-2">
                  <Play size={16} className="text-cyan-400" />
                  <h3 className="text-sm font-bold uppercase tracking-wider text-slate-100">
                    Run Authorized Network Discovery
                  </h3>
                </div>
                <button
                  onClick={() => setShowDiscoveryModal(false)}
                  className="rounded-lg p-1 text-slate-400 hover:text-white"
                >
                  <X size={16} />
                </button>
              </div>

              <form onSubmit={handleTriggerDiscovery} className="space-y-4 text-xs">
                <div className="space-y-1.5">
                  <label className="text-slate-300 font-bold">Authorized Subnet CIDR (Optional)</label>
                  <input
                    type="text"
                    value={discoverySubnet}
                    onChange={(e) => setDiscoverySubnet(e.target.value)}
                    placeholder="e.g. 192.168.1.0/24 (Leave blank for default neighbor table)"
                    className="w-full rounded-xl border border-cyan-500/30 bg-[#03060D] py-2 px-3 text-slate-100 focus:border-cyan-400 focus:outline-none"
                  />
                  <p className="text-[11px] text-slate-400">
                    Only authorized RFC 1918 subnets are permitted. Maximum 256 hosts per sweep.
                  </p>
                </div>

                <div className="flex items-center gap-2 bg-[#03060D] p-3 rounded-xl border border-slate-800">
                  <input
                    type="checkbox"
                    id="activeSweep"
                    checked={activeSweep}
                    onChange={(e) => setActiveSweep(e.target.checked)}
                    className="rounded border-slate-700 text-cyan-500 focus:ring-0"
                  />
                  <label htmlFor="activeSweep" className="text-slate-300 cursor-pointer">
                    Enable rate-limited ICMP ping sweep (wakes active nodes in subnet)
                  </label>
                </div>

                {discoveryMessage && (
                  <div
                    className={`rounded-xl border p-3 text-xs ${
                      discoveryMessage.type === "success"
                        ? "border-emerald-500/40 bg-emerald-950/30 text-emerald-300"
                        : "border-rose-500/40 bg-rose-950/30 text-rose-300"
                    }`}
                  >
                    {discoveryMessage.text}
                  </div>
                )}

                <div className="flex items-center justify-end gap-2.5 pt-2">
                  <button
                    type="button"
                    onClick={() => setShowDiscoveryModal(false)}
                    className="rounded-xl border border-slate-800 px-4 py-2 text-slate-400 hover:text-slate-200"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={discovering}
                    className="flex items-center gap-2 rounded-xl border border-cyan-400 bg-cyan-500/20 px-5 py-2 font-bold text-cyan-300 hover:bg-cyan-500/30 disabled:opacity-50 shadow-[0_0_15px_rgba(0,240,255,0.3)] transition-all"
                  >
                    {discovering ? (
                      <>
                        <Sparkles size={14} className="animate-spin text-cyan-400" /> Scanning...
                      </>
                    ) : (
                      <>
                        <Play size={14} /> Start Discovery
                      </>
                    )}
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}