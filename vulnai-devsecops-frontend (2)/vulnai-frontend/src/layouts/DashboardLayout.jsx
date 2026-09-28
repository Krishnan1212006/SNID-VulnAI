import { useState } from "react";
import { Outlet, Navigate, useLocation } from "react-router-dom";
import Sidebar from "../components/Sidebar";
import Topbar from "../components/Topbar";
import { useAuth } from "../context/AuthContext";

const PAGE_META = {
  "/dashboard": { title: "Security Briefing", subtitle: "Your overall posture, assembled from every scan" },
  "/scan": { title: "New Assessment", subtitle: "A safe, passive review of an authorized target" },
  "/vulnerabilities": { title: "Findings", subtitle: "Every vulnerability identified across your scans" },
  "/reports": { title: "Reports", subtitle: "Export scan results as PDF, JSON or CSV" },
  "/devices": { title: "Network Register", subtitle: "Devices discovered on the monitored network" },
  "/events": { title: "Security Events", subtitle: "Normalized signals from Zeek, Suricata, Wazuh & AI" },
  "/incidents": { title: "Correlated Incidents", subtitle: "Related signals merged into a single account" },
  "/devsecops": { title: "DevSecOps Pipeline", subtitle: "CI/CD security gate status" },
  "/monitoring": { title: "Infrastructure Health", subtitle: "Application and network monitoring" },
};

export default function DashboardLayout() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const { isAuthenticated } = useAuth();
  const location = useLocation();

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  const meta = PAGE_META[location.pathname] || { title: "VulnAI-DevSecOps" };

  return (
    <div className="flex min-h-screen bg-bg-main">
      <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar title={meta.title} subtitle={meta.subtitle} onMenuClick={() => setSidebarOpen(true)} />
        <main className="flex-1 px-5 py-6 lg:px-8 lg:py-8">
          <div className="fade-in-up mx-auto max-w-7xl">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
