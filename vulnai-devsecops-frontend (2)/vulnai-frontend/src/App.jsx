import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider } from "./context/AuthContext";
import { NotificationProvider } from "./context/NotificationContext";
import PublicLayout from "./layouts/PublicLayout";
import DashboardLayout from "./layouts/DashboardLayout";
import Landing from "./pages/Landing";
import About from "./pages/About";
import Contact from "./pages/Contact";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import ScanPage from "./pages/ScanPage";
import Vulnerabilities from "./pages/Vulnerabilities";
import VulnerabilityDetails from "./pages/VulnerabilityDetails";
import Reports from "./pages/Reports";
import Devices from "./pages/Devices";
import Events from "./pages/Events";
import Incidents from "./pages/Incidents";
import DevSecOps from "./pages/DevSecOps";
import Monitoring from "./pages/Monitoring";
import AuditLogs from "./pages/AuditLogs";
import ScanComparison from "./pages/ScanComparison";
import LastScanRecords from "./pages/LastScanRecords";

export default function App() {
  return (
    <AuthProvider>
      <NotificationProvider>
        <BrowserRouter>
          <Routes>
            <Route element={<PublicLayout />}>
              <Route path="/" element={<Landing />} />
              <Route path="/about" element={<About />} />
              <Route path="/contact" element={<Contact />} />
            </Route>

            <Route path="/login" element={<Login />} />

            <Route element={<DashboardLayout />}>
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/scan" element={<ScanPage />} />
              <Route path="/last-scan" element={<LastScanRecords />} />
              <Route path="/last-scan-records" element={<Navigate to="/last-scan" replace />} />
              <Route path="/vulnerabilities" element={<Vulnerabilities />} />
              <Route path="/vulnerabilities/:id" element={<VulnerabilityDetails />} />
              <Route path="/scans/:current_id/compare/:previous_id" element={<ScanComparison />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/devices" element={<Devices />} />
              <Route path="/events" element={<Events />} />
              <Route path="/incidents" element={<Incidents />} />
              <Route path="/devsecops" element={<DevSecOps />} />
              <Route path="/monitoring" element={<Monitoring />} />
              <Route path="/audit" element={<AuditLogs />} />
            </Route>

            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </BrowserRouter>
      </NotificationProvider>
    </AuthProvider>
  );
}
