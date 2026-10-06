import { createContext, useContext, useState, useEffect, useCallback, useRef } from "react";

const NotificationContext = createContext(null);

const STORAGE_KEY = "vulnai_notifications_v1";

// Web Audio API synthesized alert chime (no external audio files needed)
function playCyberNotificationChime() {
  try {
    const AudioContextClass = window.AudioContext || window.webkitAudioContext;
    if (!AudioContextClass) return;
    const ctx = new AudioContextClass();
    
    // First tone (higher cyber blip)
    const osc1 = ctx.createOscillator();
    const gain1 = ctx.createGain();
    osc1.type = "sine";
    osc1.frequency.setValueAtTime(587.33, ctx.currentTime); // D5
    osc1.frequency.exponentialRampToValueAtTime(880, ctx.currentTime + 0.12); // A5
    gain1.gain.setValueAtTime(0.2, ctx.currentTime);
    gain1.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.25);
    osc1.connect(gain1);
    gain1.connect(ctx.destination);
    osc1.start();
    osc1.stop(ctx.currentTime + 0.25);

    // Second harmonic confirmation tone
    const osc2 = ctx.createOscillator();
    const gain2 = ctx.createGain();
    osc2.type = "triangle";
    osc2.frequency.setValueAtTime(880, ctx.currentTime + 0.1);
    osc2.frequency.exponentialRampToValueAtTime(1174.66, ctx.currentTime + 0.3); // D6
    gain2.gain.setValueAtTime(0.15, ctx.currentTime + 0.1);
    gain2.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.45);
    osc2.connect(gain2);
    gain2.connect(ctx.destination);
    osc2.start(ctx.currentTime + 0.1);
    osc2.stop(ctx.currentTime + 0.45);
  } catch (e) {
    // Audio context may be restricted by autoplay policy; fail silently
  }
}

export function NotificationProvider({ children }) {
  const [notifications, setNotifications] = useState(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      return saved ? JSON.parse(saved) : [];
    } catch {
      return [];
    }
  });

  const [activeToast, setActiveToast] = useState(null);
  const toastTimeoutRef = useRef(null);

  // Sync to local storage
  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(notifications.slice(0, 50)));
    } catch (e) {
      console.warn("Failed to persist notifications:", e);
    }
  }, [notifications]);

  // Request browser permission for native desktop notifications
  const requestNotificationPermission = useCallback(async () => {
    if ("Notification" in window && Notification.permission === "default") {
      try {
        await Notification.requestPermission();
      } catch (e) {
        console.warn("Notification permission request error:", e);
      }
    }
  }, []);

  // Add a live notification
  const addNotification = useCallback((notif) => {
    const newNotif = {
      id: notif.id || `notif_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
      title: notif.title || "Scan Completed",
      message: notif.message || (notif.target ? `Security assessment completed for ${notif.target}` : "Scan execution finished"),
      target: notif.target || notif.target_url || "Target URL",
      scanId: notif.scanId || notif.scan_id || null,
      status: notif.status || "completed",
      riskScore: notif.riskScore ?? notif.risk_score ?? null,
      riskRating: notif.riskRating ?? notif.rating ?? "Low",
      findingsCount: notif.findingsCount ?? notif.total_findings ?? 0,
      timestamp: new Date().toISOString(),
      read: false,
    };

    setNotifications((prev) => [newNotif, ...prev.filter((n) => n.id !== newNotif.id)]);

    // Trigger visual toast
    setActiveToast(newNotif);
    if (toastTimeoutRef.current) clearTimeout(toastTimeoutRef.current);
    toastTimeoutRef.current = setTimeout(() => {
      setActiveToast(null);
    }, 8500);

    // Audio chime
    playCyberNotificationChime();

    // Trigger Native HTML5 Web Desktop Notification
    if ("Notification" in window && Notification.permission === "granted") {
      try {
        const bodyLines = [];
        if (newNotif.target) bodyLines.push(`Target: ${newNotif.target}`);
        if (newNotif.riskScore != null) bodyLines.push(`Risk Score: ${newNotif.riskScore}/100 (${newNotif.riskRating})`);
        if (newNotif.findingsCount != null) bodyLines.push(`Total Findings: ${newNotif.findingsCount}`);
        
        new Notification(`VulnAI DevSecOps: ${newNotif.title}`, {
          body: bodyLines.join(" | ") || newNotif.message,
          icon: "/favicon.ico",
          tag: `vulnai_scan_${newNotif.scanId || Date.now()}`,
        });
      } catch (err) {
        console.warn("Desktop notification error:", err);
      }
    }
  }, []);

  const markAsRead = useCallback((id) => {
    setNotifications((prev) =>
      prev.map((n) => (n.id === id ? { ...n, read: true } : n))
    );
  }, []);

  const markAllAsRead = useCallback(() => {
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
  }, []);

  const clearNotifications = useCallback(() => {
    setNotifications([]);
    setActiveToast(null);
  }, []);

  const dismissToast = useCallback(() => {
    setActiveToast(null);
    if (toastTimeoutRef.current) clearTimeout(toastTimeoutRef.current);
  }, []);

  const unreadCount = notifications.filter((n) => !n.read).length;

  return (
    <NotificationContext.Provider
      value={{
        notifications,
        unreadCount,
        activeToast,
        addNotification,
        markAsRead,
        markAllAsRead,
        clearNotifications,
        dismissToast,
        requestNotificationPermission,
      }}
    >
      {children}
      {/* Global In-App Live Notification Toast */}
      {activeToast && (
        <div className="fixed bottom-6 right-6 z-50 max-w-md w-full animate-in fade-in slide-in-from-bottom-5 duration-300 font-mono">
          <div className="relative rounded-2xl border border-cyan-500/50 bg-[#070D1B]/95 p-4 text-slate-200 shadow-[0_10px_40px_rgba(0,240,255,0.25)] backdrop-blur-2xl">
            {/* Top Glowing Edge */}
            <div className={`absolute -top-[1px] left-8 right-8 h-[2px] ${
              activeToast.status === 'completed'
                ? 'bg-gradient-to-r from-transparent via-cyan-400 to-transparent'
                : 'bg-gradient-to-r from-transparent via-rose-500 to-transparent'
            }`} />

            <div className="flex items-start justify-between gap-3">
              <div className="flex items-center gap-2.5">
                <span className="relative flex h-3 w-3">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-3 w-3 bg-cyan-500"></span>
                </span>
                <span className="text-[10px] uppercase tracking-widest text-cyan-400 font-bold">
                  LIVE ALERT // SCAN FINISHED
                </span>
              </div>
              <button
                onClick={dismissToast}
                className="text-slate-400 hover:text-slate-200 text-xs px-1.5 py-0.5 rounded hover:bg-slate-800/60 transition"
              >
                ✕
              </button>
            </div>

            <div className="mt-2.5">
              <h4 className="text-sm font-extrabold text-slate-100 flex items-center gap-2">
                {activeToast.title}
                <span className={`text-[10px] px-2 py-0.5 rounded-full font-bold ${
                  activeToast.status === 'completed'
                    ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-500/40'
                    : 'bg-rose-950/80 text-rose-300 border border-rose-500/40'
                }`}>
                  {activeToast.status.toUpperCase()}
                </span>
              </h4>
              <p className="mt-1 text-xs text-slate-300 break-all">
                Target: <span className="text-cyan-300 font-bold">{activeToast.target}</span>
              </p>
              
              {activeToast.riskScore != null && (
                <div className="mt-2.5 flex items-center gap-3 text-xs bg-slate-900/80 rounded-xl p-2 border border-slate-800">
                  <div>
                    <span className="text-[10px] text-slate-400 block uppercase">Risk Score</span>
                    <span className="text-cyan-400 font-extrabold text-sm">
                      {activeToast.riskScore}/100
                    </span>
                  </div>
                  <div className="h-6 w-[1px] bg-slate-800" />
                  <div>
                    <span className="text-[10px] text-slate-400 block uppercase">Risk Level</span>
                    <span className="text-amber-400 font-bold text-xs uppercase">
                      {activeToast.riskRating}
                    </span>
                  </div>
                  <div className="h-6 w-[1px] bg-slate-800" />
                  <div>
                    <span className="text-[10px] text-slate-400 block uppercase">Findings</span>
                    <span className="text-slate-200 font-bold text-xs">
                      {activeToast.findingsCount} Detected
                    </span>
                  </div>
                </div>
              )}
            </div>

            <div className="mt-3 flex items-center justify-between text-[11px] pt-2 border-t border-slate-800/80">
              <span className="text-slate-500 text-[10px]">
                {new Date(activeToast.timestamp).toLocaleTimeString()}
              </span>
              <div className="flex gap-2">
                <button
                  onClick={() => {
                    dismissToast();
                    window.location.href = activeToast.scanId ? `/reports` : `/scan`;
                  }}
                  className="rounded-lg bg-cyan-500/20 px-2.5 py-1 text-cyan-300 hover:bg-cyan-500/30 transition text-[11px] font-bold border border-cyan-500/40"
                >
                  View Report →
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </NotificationContext.Provider>
  );
}

export function useNotifications() {
  const context = useContext(NotificationContext);
  if (!context) {
    throw new Error("useNotifications must be used within a NotificationProvider");
  }
  return context;
}
