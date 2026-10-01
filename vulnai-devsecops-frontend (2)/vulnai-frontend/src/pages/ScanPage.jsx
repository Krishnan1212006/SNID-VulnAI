import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Globe, ShieldCheck, Loader2, CheckCircle2, AlertTriangle, ScanSearch, Cpu, Terminal, Sparkles } from "lucide-react";
import { scanCheckSteps } from "../data/mockData";
import api from "../lib/api";

const STATE = { IDLE: "idle", VALIDATING: "validating", SCANNING: "scanning", DONE: "done" };
const PRIVATE_RANGES = ["127.", "10.", "192.168.", "169.254.", "0.0.0.0", "localhost", "169.254.169.254"];

export default function ScanPage() {
  const [url, setUrl] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [labMode, setLabMode] = useState(true);
  const [comprehensiveMode, setComprehensiveMode] = useState(false);
  const [state, setState] = useState(STATE.IDLE);
  const [stepIndex, setStepIndex] = useState(0);
  const [progress, setProgress] = useState(0);
  const [scannerStatus, setScannerStatus] = useState({});
  const [terminalLines, setTerminalLines] = useState([]);
  const [error, setError] = useState("");
  const [scanResult, setScanResult] = useState(null);
  const [assessmentResults, setAssessmentResults] = useState(null);
  const [scanId, setScanId] = useState("");
  const [scanTarget, setScanTarget] = useState("");
  const timerRef = useRef(null);
  const canvasRef = useRef(null);
  const navigate = useNavigate();

  // Full Screen Interactive Particle Canvas Background
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");

    let animationFrameId;
    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    const particles = [];
    const particleCount = Math.floor((width * height) / 14000);
    const pointer = { x: null, y: null, radius: 180 };

    class Particle {
      constructor() {
        this.x = Math.random() * width;
        this.y = Math.random() * height;
        this.vx = (Math.random() - 0.5) * 0.7;
        this.vy = (Math.random() - 0.5) * 0.7;
        this.radius = Math.random() * 2 + 1;
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
        ctx.fillStyle = "rgba(0, 240, 255, 0.7)";
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

          if (distance < 120) {
            ctx.beginPath();
            ctx.strokeStyle = `rgba(0, 240, 255, ${0.3 - distance / 120})`;
            ctx.lineWidth = 0.7;
            ctx.moveTo(particles[i].x, particles[i].y);
            ctx.lineTo(particles[j].x, particles[j].y);
            ctx.stroke();
          }
        }

        if (pointer.x !== null && pointer.y !== null) {
          const dx = particles[i].x - pointer.x;
          const dy = particles[i].y - pointer.y;
          const distance = Math.sqrt(dx * dx + dy * dy);

          if (distance < pointer.radius) {
            ctx.beginPath();
            ctx.strokeStyle = `rgba(0, 240, 255, ${0.7 - distance / pointer.radius})`;
            ctx.lineWidth = 1.4;
            ctx.moveTo(particles[i].x, particles[i].y);
            ctx.lineTo(pointer.x, pointer.y);
            ctx.stroke();
          }
        }
      }

      animationFrameId = requestAnimationFrame(animate);
    };

    animate();

    const handlePointerMove = (e) => {
      pointer.x = e.touches ? e.touches[0].clientX : e.clientX;
      pointer.y = e.touches ? e.touches[0].clientY : e.clientY;
    };

    const handlePointerLeave = () => {
      pointer.x = null;
      pointer.y = null;
    };

    const handleResize = () => {
      if (!canvas) return;
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };

    window.addEventListener("resize", handleResize);
    window.addEventListener("mousemove", handlePointerMove);
    window.addEventListener("touchmove", handlePointerMove);
    window.addEventListener("mouseleave", handlePointerLeave);
    window.addEventListener("touchend", handlePointerLeave);

    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener("resize", handleResize);
      window.removeEventListener("mousemove", handlePointerMove);
      window.removeEventListener("touchmove", handlePointerMove);
      window.removeEventListener("mouseleave", handlePointerLeave);
      window.removeEventListener("touchend", handlePointerLeave);
    };
  }, []);

  useEffect(() => () => clearInterval(timerRef.current), []);

  function isBlockedTarget(target) {
    if (labMode) return false;
    try {
      const host = new URL(target).hostname;
      return PRIVATE_RANGES.some((p) => host.includes(p));
    } catch {
      return false;
    }
  }

  async function startScan(e) {
    e.preventDefault();
    setError("");

    if (!url.trim()) {
      setError("Enter a target URL to scan.");
      return;
    }
    let parsed;
    const enteredTarget = url.trim();
    const candidateTarget = /^[a-z][a-z0-9+.-]*:\/\//i.test(enteredTarget)
      ? enteredTarget
      : `https://${enteredTarget}`;
    try {
      parsed = new URL(candidateTarget);
      if (!["http:", "https:"].includes(parsed.protocol)) throw new Error();
    } catch {
      setError("Enter a valid HTTP or HTTPS URL, e.g. https://your-app.local");
      return;
    }
    if (!authorized) {
      setError("You must confirm authorization before a scan can start.");
      return;
    }
    const normalizedTarget = parsed.toString();
    setScanTarget(normalizedTarget);
    if (isBlockedTarget(normalizedTarget)) {
      setError("Private/internal targets are blocked unless Lab Mode is enabled.");
      return;
    }

    setState(STATE.SCANNING);
    setStepIndex(0);
    setProgress(0);
    setScannerStatus({});
    setTerminalLines([]);
    setScanResult(null);
    setAssessmentResults(null);
    setScanId("");

    try {
      const assetRes = await api.post("/assets/", {
        name: `Scan Target: ${parsed.hostname}`,
        target_urls: [normalizedTarget],
        environment: "development"
      });
      const assetId = assetRes.data.id;

      const scanRes = await api.post("/scans/", {
        asset_id: assetId,
        authorized: authorized,
        lab_mode: labMode,
        kali_mode: false,
        unified_mode: comprehensiveMode,
        target_urls: [normalizedTarget],
      });
      const scanId = scanRes.data.id;
      setScanId(scanId);

      let pollingFails = 0;

      timerRef.current = setInterval(async () => {
        try {
          const progRes = await api.get(comprehensiveMode
            ? `/scans/${scanId}/assessment-status`
            : `/scans/${scanId}/progress`);
          const currentProgress = progRes.data.progress || 0;
          const status = progRes.data.status;
          setProgress(currentProgress);
          setScannerStatus(progRes.data.scanners || progRes.data.scanner_status || {});

          let newStep = Math.floor((currentProgress / 100) * scanCheckSteps.length);
          if (newStep >= scanCheckSteps.length) newStep = scanCheckSteps.length - 1;
          setStepIndex((currentStep) => Math.max(newStep, currentStep));

          if (["completed", "completed_with_failures", "failed", "incomplete"].includes(status)) {
            clearInterval(timerRef.current);
            if (comprehensiveMode) {
              const fullScan = await api.get(`/scans/${scanId}`);
              setScannerStatus(fullScan.data.scanner_status || progRes.data.scanners || {});
              try {
                const resultsRes = await api.get(`/scans/${scanId}/assessment-results`);
                setAssessmentResults(resultsRes.data);
                setScanResult({ ...fullScan.data, status: resultsRes.data.status || status });
                setState(STATE.DONE);
              } catch (resultsError) {
                if (status !== "failed") throw resultsError;
                setState(STATE.IDLE);
                setError(fullScan.data.error_message || "Assessment failed before unified results were available.");
              }
            } else if (status === "completed") {
              const fullScan = await api.get(`/scans/${scanId}`);
              setScanResult(fullScan.data);
              setState(STATE.DONE);
            } else {
              setState(STATE.IDLE);
              setError(progRes.data.error_message || "Scan failed to complete due to backend error.");
            }
          }
        } catch (err) {
          console.error("Polling error:", err);
          pollingFails += 1;
          if (pollingFails > 4) {
            clearInterval(timerRef.current);
            setState(STATE.IDLE);
            setError("Lost communication with backend scanner.");
          }
        }
      }, 2000);

    } catch (err) {
      setState(STATE.IDLE);
      setError(err.message || "Failed to initiate scan.");
    }
  }

  function reset() {
    setState(STATE.IDLE);
    setUrl("");
    setAuthorized(false);
    setStepIndex(0);
    setProgress(0);
    setScannerStatus({});
    setTerminalLines([]);
    setError("");
    setScanResult(null);
    setAssessmentResults(null);
    setScanId("");
    setScanTarget("");
    setComprehensiveMode(false);
  }

  return (
    <>
      {/* Fixed Full Screen Canvas Background (Covers entire Screen/Layout) */}
      <canvas
        ref={canvasRef}
        className="fixed inset-0 z-0 h-screen w-screen pointer-events-none bg-[#020408] opacity-75"
      />

      {/* Full Viewport Cyber Overlay Grid & Glow Ambient */}
      <div className="fixed inset-0 z-0 pointer-events-none bg-[linear-gradient(to_right,#00f0ff08_1px,transparent_1px),linear-gradient(to_bottom,#00f0ff08_1px,transparent_1px)] bg-[size:3rem_3rem]" />
      <div className="fixed -top-20 -right-20 z-0 h-96 w-96 rounded-full bg-cyan-500/10 blur-[150px] pointer-events-none" />
      <div className="fixed top-1/2 -left-20 z-0 h-96 w-96 rounded-full bg-purple-600/10 blur-[150px] pointer-events-none" />

      {/* Main Content Area */}
      <div className="relative z-10 font-mono text-slate-100 mx-auto max-w-3xl space-y-6 p-2 sm:p-4">

        {state !== STATE.SCANNING && state !== STATE.DONE && (
          <form
            onSubmit={startScan}
            className="rounded-2xl border border-cyan-500/30 bg-[#070D1B]/80 p-6 sm:p-8 shadow-[0_0_40px_rgba(0,240,255,0.08)] backdrop-blur-2xl transition-all duration-300"
          >
            {/* Header */}
            <div className="mb-6 flex items-center justify-between border-b border-cyan-500/20 pb-6">
              <div className="flex items-center gap-3.5">
                <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-cyan-950/50 border border-cyan-400/60 text-cyan-400 shadow-[0_0_15px_rgba(0,240,255,0.3)]">
                  <ScanSearch size={22} className="animate-pulse" />
                </div>
                <div>
                  <h2 className="text-lg font-extrabold tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-slate-100 to-cyan-200 uppercase">
                    Target Scanner Interface
                  </h2>
                  <p className="text-[11px] text-slate-400 flex items-center gap-1 mt-0.5">
                    <Cpu size={12} className="text-cyan-500" /> {comprehensiveMode ? "Active Assessment — Nmap, Nikto, Wapiti, SQLMap & Gobuster" : "Passive Assessment — Headers, TLS, Cookies & Tech Detection"}
                  </p>
                </div>
              </div>
              <span className="hidden sm:flex items-center gap-1.5 rounded-lg border border-cyan-500/30 bg-[#03060D] px-3 py-1 text-[11px] text-cyan-400 font-mono">
                <Terminal size={12} /> SEC_ENGINE: READY
              </span>
            </div>

            {/* Target URL Input */}
            <label className="mb-5 block">
              <span className="mb-2 block text-xs font-bold uppercase tracking-wider text-cyan-300 flex items-center gap-1.5">
                Target Endpoint URL
              </span>
              <div className="relative group">
                <Globe size={16} className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-cyan-400/70 group-focus-within:text-cyan-400 group-focus-within:drop-shadow-[0_0_8px_#00f0ff] transition-all" />
                <input
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://your-authorized-app.local"
                  className="w-full rounded-xl border border-cyan-500/30 bg-[#03060D]/90 py-3 pl-10 pr-4 font-mono text-xs text-slate-100 placeholder:text-slate-600 focus:border-cyan-400 focus:bg-[#03060D] focus:outline-none focus:ring-1 focus:ring-cyan-400/50 shadow-inner transition-all duration-300"
                />
              </div>
            </label>

            {/* Lab Mode Option */}
            <label className="mb-3.5 flex cursor-pointer items-center justify-between rounded-xl border border-slate-800 bg-[#03060D]/70 px-4 py-3.5 hover:border-cyan-500/40 transition-all">
              <div>
                <p className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
                  <Sparkles size={13} className="text-yellow-400" /> Lab Mode
                </p>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Allow scanning private/internal ranges (e.g. DVWA, Juice Shop, Localhost)
                </p>
              </div>
              <input
                type="checkbox"
                checked={labMode}
                onChange={(e) => setLabMode(e.target.checked)}
                className="h-4 w-4 rounded border-slate-700 bg-slate-900 text-cyan-400 accent-cyan-400 focus:ring-0 cursor-pointer"
              />
            </label>

            {/* Comprehensive Scanner Option */}
            <label className="mb-5 flex cursor-pointer items-start gap-3 rounded-xl border border-amber-700/40 bg-amber-950/15 px-4 py-3.5 hover:border-amber-500/50 transition-all">
              <input
                type="checkbox"
                checked={comprehensiveMode}
                onChange={(e) => setComprehensiveMode(e.target.checked)}
                className="mt-0.5 h-4 w-4 shrink-0 accent-amber-400"
              />
              <span>
                <span className="block text-xs font-bold uppercase tracking-wider text-amber-300">Comprehensive tool assessment</span>
                <span className="mt-1 block text-[11px] leading-relaxed text-slate-400">
                  Runs Nmap, Nikto, Wapiti, SQLMap, and Gobuster. This mode sends active probes and requires explicit authorization.
                </span>
              </span>
            </label>

            {/* Authorization Checkbox */}
            <label className="mb-6 flex cursor-pointer items-start gap-3 rounded-xl border border-slate-800 bg-[#03060D]/70 px-4 py-3.5 hover:border-cyan-500/40 transition-all">
              <input
                type="checkbox"
                checked={authorized}
                onChange={(e) => setAuthorized(e.target.checked)}
                className="mt-0.5 h-4 w-4 shrink-0 rounded border-slate-700 bg-slate-900 text-cyan-400 accent-cyan-400 focus:ring-0 cursor-pointer"
              />
              <span className="text-xs text-slate-300 leading-relaxed">
                <span className="font-bold text-cyan-300 uppercase tracking-wider">Explicit Authorization:</span> I confirm that I own this website or have explicit written permission to assess its security posture{comprehensiveMode ? ", including active vulnerability and directory probes" : " via safe, passive checks"}.
              </span>
            </label>

            {/* Error Message */}
            {error && (
              <div className="mb-5 flex items-center gap-2.5 rounded-xl border border-rose-500/40 bg-rose-950/30 px-4 py-3 text-xs font-semibold text-rose-400 shadow-[0_0_15px_rgba(255,0,85,0.2)]">
                <AlertTriangle size={16} className="shrink-0 text-rose-400 animate-pulse" />
                <span>{error}</span>
              </div>
            )}

            {/* Submit Button */}
            <button
              type="submit"
              className="group relative flex w-full items-center justify-center gap-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 py-3.5 text-xs font-extrabold uppercase tracking-widest text-slate-950 shadow-[0_0_25px_rgba(0,240,255,0.4)] hover:shadow-[0_0_35px_rgba(0,240,255,0.6)] hover:scale-[1.01] active:scale-[0.99] transition-all duration-300"
            >
              <ShieldCheck size={18} className="text-slate-950 transition-transform group-hover:scale-110" />
              Initiate Security Telemetry
            </button>
          </form>
        )}

        {/* SCANNING STATE */}
        {state === STATE.SCANNING && (
          <div className="rounded-2xl border border-cyan-500/30 bg-[#070D1B]/90 p-6 sm:p-8 shadow-[0_0_50px_rgba(0,240,255,0.15)] backdrop-blur-2xl">
            <div className="mb-6 flex items-center gap-3.5 border-b border-cyan-500/20 pb-6">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-950/60 border border-cyan-400 text-cyan-400 shadow-[0_0_15px_rgba(0,240,255,0.4)]">
                <Loader2 size={20} className="animate-spin text-cyan-400" />
              </div>
              <div>
                <h2 className="text-base font-extrabold tracking-wider text-cyan-300 uppercase">
                  Scanning Target: <span className="text-slate-100">{scanTarget || url}</span>
                </h2>
                <p className="text-[11px] text-slate-400">
                  {comprehensiveMode ? "Running authorized Nmap, Nikto, Wapiti, SQLMap, and Gobuster assessments..." : "Executing passive non-intrusive security checks..."}
                </p>
                {comprehensiveMode && (
                  <p className="mt-1 text-[11px] text-slate-500">Scan ID: {scanId || "Preparing"} · Overall status: Running</p>
                )}
              </div>
            </div>

            <div className="relative mb-2 h-2 w-full overflow-hidden rounded-full bg-slate-900 border border-cyan-500/20">
              <div
                className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 shadow-[0_0_12px_#00f0ff] transition-all duration-500"
                style={{ width: `${progress}%` }}
              />
            </div>
            <div className="mb-6 flex justify-between text-[11px] font-bold text-cyan-400">
              <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-cyan-400 animate-ping" /> Telemetry Active</span>
              <span>{progress}% Completed</span>
            </div>

            {comprehensiveMode ? (
              <>
                <div className="mb-4 grid grid-cols-2 gap-2 sm:grid-cols-5">
                  {Object.entries({ nmap: "Nmap", nikto: "Nikto", wapiti: "Wapiti", sqlmap: "SQLMap", gobuster: "Gobuster" }).map(([key, label]) => (
                    <div key={key} className="rounded-lg border border-slate-800 bg-[#03060D]/80 px-3 py-2">
                      <span className="block text-[10px] uppercase tracking-wider text-slate-500">{label}</span>
                      <span className="mt-1 block text-[11px] font-bold text-cyan-300">{String(scannerStatus[key] || "queued").replace("_", " ").toUpperCase()}</span>
                    </div>
                  ))}
                </div>
              </>
            ) : (
            <div className="space-y-2.5 rounded-xl bg-[#03060D]/80 p-4 border border-slate-800">
              {scanCheckSteps.map((step, idx) => (
                <div key={step} className="flex items-center gap-3 text-xs transition-all duration-300">
                  {idx < stepIndex ? (
                    <CheckCircle2 size={16} className="shrink-0 text-emerald-400 drop-shadow-[0_0_5px_#10b981]" />
                  ) : idx === stepIndex ? (
                    <Loader2 size={16} className="shrink-0 animate-spin text-cyan-400 drop-shadow-[0_0_5px_#00f0ff]" />
                  ) : (
                    <span className="h-4 w-4 shrink-0 rounded border border-slate-800 bg-slate-900/50" />
                  )}
                  <span className={idx <= stepIndex ? "font-bold text-slate-200" : "text-slate-500"}>{step}</span>
                </div>
              ))}
            </div>
            )}
          </div>
        )}

        {/* DONE STATE */}
        {state === STATE.DONE && (
          <div className={`rounded-2xl border ${scanResult?.status === "failed" ? "border-rose-500/40" : ["completed_with_failures", "incomplete"].includes(scanResult?.status) ? "border-amber-500/40" : "border-emerald-500/40"} bg-[#070D1B]/90 p-6 sm:p-8 text-center shadow-[0_0_50px_rgba(16,185,129,0.15)] backdrop-blur-2xl`}>
            <div className={`mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-2xl border ${scanResult?.status === "failed" ? "border-rose-400/50 bg-rose-950/40 text-rose-400" : ["completed_with_failures", "incomplete"].includes(scanResult?.status) ? "border-amber-400/50 bg-amber-950/40 text-amber-400" : "border-emerald-400/50 bg-emerald-950/40 text-emerald-400"}`}>
              {scanResult?.status === "failed" ? <AlertTriangle size={32} /> : <CheckCircle2 size={32} />}
            </div>
            <h2 className="text-xl font-extrabold tracking-widest text-slate-100 uppercase">
              {scanResult?.status === "failed" ? "Assessment Failed" : scanResult?.status === "incomplete" ? "Assessment Incomplete" : scanResult?.status === "completed_with_failures" ? "Assessment Completed with Failures" : "Scan Complete"}
            </h2>
            <p className="mx-auto mt-2 max-w-md text-xs text-slate-400 leading-relaxed">
              {scanResult?.status === "failed"
                ? "Required scanners failed. Review each scanner status and its recorded error below."
                : scanResult?.status === "completed_with_failures"
                  ? "Some scanners failed. Findings below include only results from completed scanners."
                  : scanResult?.status === "incomplete"
                    ? "The assessment is incomplete because one or more required scanners were unavailable or skipped."
                  : <>Target <span className="font-bold text-cyan-300">{url}</span> successfully assessed. Security posture score:{" "}
                    <span className="font-bold text-emerald-400">{scanResult?.security_score || 0}/100</span>.</>}{" "}
              <span className="font-bold text-rose-400">{scanResult?.total_findings || 0} confirmed findings</span>.
            </p>

            {comprehensiveMode && (
              <div className="mt-6 space-y-4 text-left">
                <div className="grid gap-2 rounded-xl border border-cyan-500/20 bg-[#03060D]/70 p-4 text-xs sm:grid-cols-3">
                  <p><span className="text-slate-500">Target</span><br /><span className="break-all text-cyan-200">{scanResult?.target_url || scanTarget}</span></p>
                  <p><span className="text-slate-500">Scan ID</span><br /><span className="break-all text-slate-200">{scanId}</span></p>
                  <p><span className="text-slate-500">Overall status</span><br /><span className={scanResult?.status === "failed" ? "text-rose-300" : scanResult?.status === "completed_with_failures" ? "text-amber-300" : "text-emerald-300"}>{scanResult?.status || "completed"}</span></p>
                </div>
                <div className="grid grid-cols-2 gap-2 sm:grid-cols-5">
                  {Object.entries({ nmap: "Nmap", nikto: "Nikto", wapiti: "Wapiti", sqlmap: "SQLMap", gobuster: "Gobuster" }).map(([key, label]) => (
                    <div key={key} className="rounded-lg border border-slate-800 bg-[#03060D]/80 px-3 py-2 text-left">
                      <span className="block text-[10px] uppercase text-slate-500">{label}</span>
                      <span className="mt-1 block text-[11px] font-bold text-cyan-300">{String(scannerStatus[key] || "unknown").replace("_", " ").toUpperCase()}</span>
                    </div>
                  ))}
                </div>
                {(() => {
                  const runtime = assessmentResults?.runtime_status || scanResult?.runtime_status;
                  const details = assessmentResults?.scanner_details || scanResult?.scanner_details || {};
                  return (
                    <section className="rounded-xl border border-amber-500/20 bg-amber-950/10 p-4 text-xs">
                      <h3 className="font-bold uppercase text-amber-200">Scanner runtime</h3>
                      <p className="mt-2 text-slate-300">
                        {runtime?.runtime?.toUpperCase() || "RUNTIME"} · {runtime?.distribution || "Local"} · {runtime?.status || "status unavailable"}
                        {runtime?.distribution_state_before_command ? ` · Ubuntu ${runtime.distribution_state_before_command}` : ""}
                      </p>
                      {(runtime?.error || !runtime?.command_executable) && (
                        <p className="mt-1 break-words text-rose-300">{runtime?.error || "Scanner runtime could not execute commands."}</p>
                      )}
                      {Object.entries(details).map(([scanner, detail]) => (
                        <details key={scanner} className="mt-3 border-t border-slate-800 pt-2">
                          <summary className="cursor-pointer text-slate-300">
                            {scanner.toUpperCase()} · {detail.status} · {detail.duration ?? detail.execution_seconds ?? 0}s
                            {detail.error ? ` · ${detail.error}` : ""}
                          </summary>
                          <p className="mt-2 break-words text-rose-300">stderr: {detail.stderr || "(empty)"}</p>
                          <p className="mt-1 break-words text-slate-400">stdout: {detail.stdout || "(empty)"}</p>
                        </details>
                      ))}
                    </section>
                  );
                })()}
                <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                  {[
                    ["Confirmed findings", assessmentResults?.confirmed?.length || 0],
                    ["Potential findings", assessmentResults?.potential?.length || 0],
                    ["Informational observations", assessmentResults?.informational?.length || 0],
                    ["Incomplete scanner results", assessmentResults?.incomplete?.length || 0],
                  ].map(([label, count]) => (
                    <div key={label} className="rounded-lg border border-slate-800 bg-[#03060D]/80 px-3 py-3">
                      <span className="block text-[10px] text-slate-400">{label}</span>
                      <span className="mt-1 block text-lg font-bold text-cyan-200">{count}</span>
                    </div>
                  ))}
                </div>
                <div className="space-y-3">
                  {[
                    ["confirmed", "Confirmed findings"],
                    ["potential", "Potential findings"],
                    ["informational", "Informational observations"],
                    ["incomplete", "Incomplete scanner results"],
                  ].map(([group, label]) => {
                    const observations = assessmentResults?.[group] || [];
                    return (
                      <section key={group} className="border-t border-slate-800 pt-3">
                        <h3 className="text-[11px] font-bold uppercase text-slate-300">{label}</h3>
                        {observations.length === 0 ? (
                          <p className="mt-1 text-[11px] text-slate-500">None</p>
                        ) : (
                          <ul className="mt-2 divide-y divide-slate-800">
                            {observations.map((observation, index) => (
                              <li key={observation.id || `${observation.scanner}-${index}`} className="space-y-1 py-2 text-[11px]">
                                <p className="break-words font-semibold text-slate-200">{observation.title || observation.path || observation.message}</p>
                                <p className="text-slate-500">{observation.scanner} · {observation.verification_status || observation.status || "unverified"}</p>
                                {observation.status_code != null && (
                                  <p className="font-mono text-slate-400">{observation.path} · HTTP {observation.status_code} · {observation.response_size ?? "unknown"} bytes</p>
                                )}
                                {(observation.message || observation.description) && (
                                  <p className="break-words text-slate-500">{observation.message || observation.description}</p>
                                )}
                              </li>
                            ))}
                          </ul>
                        )}
                      </section>
                    );
                  })}
                </div>
              </div>
            )}

            <div className="mt-7 flex flex-col justify-center gap-3.5 sm:flex-row">
              <button
                onClick={() => navigate("/vulnerabilities")}
                className="rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 px-6 py-3 text-xs font-extrabold uppercase tracking-wider text-slate-950 shadow-[0_0_20px_rgba(0,240,255,0.4)] hover:shadow-[0_0_30px_rgba(0,240,255,0.6)] transition-all duration-300"
              >
                View Security Telemetry
              </button>
              <button
                onClick={reset}
                className="rounded-xl border border-slate-700 bg-[#03060D] px-6 py-3 text-xs font-bold uppercase tracking-wider text-slate-300 hover:border-cyan-500/50 hover:text-cyan-300 transition-all duration-300"
              >
                Run New Scan
              </button>
            </div>
          </div>
        )}

      </div>
    </>
  );
}
