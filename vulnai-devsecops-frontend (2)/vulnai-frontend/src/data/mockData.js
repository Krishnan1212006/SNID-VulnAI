// Centralized mock/demo data for the VulnAI-DevSecOps frontend.
// In production this would be replaced by calls to the FastAPI backend.

export const currentUser = {
  name: "Student User",
  email: "student@example.com",
  role: "Security Analyst",
  initials: "SU",
};

export const scanHistory = [
  {
    id: "scan_001",
    target_url: "https://demo-juiceshop.local",
    status: "completed",
    security_score: 72,
    total_findings: 8,
    severity_summary: { critical: 1, high: 3, medium: 3, low: 1 },
    started_at: "2026-08-24T10:30:00Z",
    completed_at: "2026-08-24T10:34:00Z",
  },
  {
    id: "scan_002",
    target_url: "https://staging.testapp.local",
    status: "completed",
    security_score: 88,
    total_findings: 4,
    severity_summary: { critical: 0, high: 1, medium: 2, low: 1 },
    started_at: "2026-08-22T09:12:00Z",
    completed_at: "2026-08-22T09:15:00Z",
  },
  {
    id: "scan_003",
    target_url: "https://dvwa.local",
    status: "completed",
    security_score: 41,
    total_findings: 12,
    severity_summary: { critical: 3, high: 4, medium: 4, low: 1 },
    started_at: "2026-08-19T14:02:00Z",
    completed_at: "2026-08-19T14:07:00Z",
  },
  {
    id: "scan_004",
    target_url: "https://webgoat.local",
    status: "completed",
    security_score: 63,
    total_findings: 9,
    severity_summary: { critical: 1, high: 2, medium: 4, low: 2 },
    started_at: "2026-08-15T11:44:00Z",
    completed_at: "2026-08-15T11:49:00Z",
  },
];

export const trendData = [
  { date: "Aug 12", score: 55 },
  { date: "Aug 15", score: 63 },
  { date: "Aug 19", score: 41 },
  { date: "Aug 22", score: 88 },
  { date: "Aug 24", score: 72 },
];

export const severityColors = {
  critical: "#A83B42",
  high: "#B5692B",
  medium: "#9C8536",
  low: "#4F7A5E",
};

export const vulnerabilities = [
  {
    id: "vuln_001",
    scan_id: "scan_001",
    target_url: "https://demo-juiceshop.local",
    title: "Missing Content-Security-Policy",
    severity: "medium",
    confidence: 0.94,
    category: "Security Misconfiguration",
    owasp_id: "A05:2021",
    status: "open",
    created_at: "2026-08-24T10:34:00Z",
    evidence: { header: "Content-Security-Policy", observed_value: null },
    ai_analysis: {
      problem: "The application does not define a Content-Security-Policy header.",
      impact: "The absence of CSP increases exposure to certain client-side injection scenarios such as XSS payload execution and unauthorized resource loading.",
      recommendation: "Configure a restrictive Content-Security-Policy based on the scripts, styles, fonts and external resources your application actually requires. Start in report-only mode, review violations, then enforce.",
      verification_steps: [
        "Add a Content-Security-Policy header to server responses",
        "Deploy in Content-Security-Policy-Report-Only first",
        "Review the browser console / report endpoint for violations",
        "Switch to enforcing mode once no legitimate resources are blocked",
      ],
      priority: "medium",
    },
  },
  {
    id: "vuln_002",
    scan_id: "scan_001",
    target_url: "https://demo-juiceshop.local",
    title: "TRACE Method Enabled",
    severity: "critical",
    confidence: 0.88,
    category: "Security Misconfiguration",
    owasp_id: "A05:2021",
    status: "open",
    created_at: "2026-08-24T10:34:00Z",
    evidence: { header: "Allow", observed_value: "GET, POST, PUT, TRACE, OPTIONS" },
    ai_analysis: {
      problem: "The web server accepts the HTTP TRACE method on this endpoint.",
      impact: "TRACE can be leveraged in Cross-Site Tracing (XST) attacks to read cookies and headers that are otherwise inaccessible to client-side scripts, undermining HttpOnly protections.",
      recommendation: "Disable the TRACE (and TRACK) HTTP methods at the web server or reverse proxy layer. Only allow the HTTP methods the application actually needs.",
      verification_steps: [
        "Send an OPTIONS request and inspect the Allow header",
        "Disable TRACE/TRACK in the web server configuration",
        "Re-scan and confirm TRACE now returns 405",
      ],
      priority: "critical",
    },
  },
  {
    id: "vuln_003",
    scan_id: "scan_001",
    target_url: "https://demo-juiceshop.local",
    title: "Missing HttpOnly Cookie Flag",
    severity: "high",
    confidence: 0.91,
    category: "Session Management",
    owasp_id: "A05:2021",
    status: "in_progress",
    created_at: "2026-08-24T10:34:00Z",
    evidence: { header: "Set-Cookie", observed_value: "session=***; Path=/" },
    ai_analysis: {
      problem: "The session cookie is set without the HttpOnly attribute.",
      impact: "Client-side scripts can read the cookie, so any successful XSS on the page can be used to steal the session token.",
      recommendation: "Set the HttpOnly (and Secure, SameSite=Lax/Strict) attributes on all session and authentication cookies.",
      verification_steps: [
        "Inspect Set-Cookie headers in the browser network tab",
        "Add HttpOnly, Secure and SameSite attributes server-side",
        "Confirm document.cookie no longer exposes the session value",
      ],
      priority: "high",
    },
  },
  {
    id: "vuln_004",
    scan_id: "scan_001",
    target_url: "https://demo-juiceshop.local",
    title: "Server Version Disclosure",
    severity: "low",
    confidence: 0.97,
    category: "Information Disclosure",
    owasp_id: "A05:2021",
    status: "resolved",
    created_at: "2026-08-24T10:34:00Z",
    evidence: { header: "Server", observed_value: "nginx/1.18.0" },
    ai_analysis: {
      problem: "The Server response header discloses the exact web server version.",
      impact: "Attackers can use this to quickly match known CVEs for that specific version instead of probing blindly.",
      recommendation: "Suppress or generalize the Server header at the reverse proxy / web server configuration.",
      verification_steps: [
        "Locate server_tokens / ServerTokens setting",
        "Set it to off / Prod",
        "Re-scan and confirm the header no longer returns a version",
      ],
      priority: "low",
    },
  },
  {
    id: "vuln_005",
    scan_id: "scan_003",
    target_url: "https://dvwa.local",
    title: "Missing HTTP Strict Transport Security",
    severity: "medium",
    confidence: 0.9,
    category: "Security Misconfiguration",
    owasp_id: "A05:2021",
    status: "open",
    created_at: "2026-08-19T14:07:00Z",
    evidence: { header: "Strict-Transport-Security", observed_value: null },
    ai_analysis: {
      problem: "The Strict-Transport-Security response header is absent on an HTTPS endpoint.",
      impact: "Browsers may still be tricked into connecting over plain HTTP, exposing traffic to SSL-stripping style downgrade attacks.",
      recommendation: "Add a Strict-Transport-Security header with an appropriate max-age and includeSubDomains once all subdomains support HTTPS.",
      verification_steps: [
        "Add Strict-Transport-Security: max-age=63072000; includeSubDomains",
        "Preload only after confirming full HTTPS coverage",
        "Re-scan to confirm the header is present",
      ],
      priority: "medium",
    },
  },
  {
    id: "vuln_006",
    scan_id: "scan_003",
    target_url: "https://dvwa.local",
    title: "Expired TLS Certificate",
    severity: "critical",
    confidence: 0.99,
    category: "Transport Security",
    owasp_id: "A02:2021",
    status: "open",
    created_at: "2026-08-19T14:07:00Z",
    evidence: { header: "TLS", observed_value: "Certificate expired 2026-07-30" },
    ai_analysis: {
      problem: "The presented TLS certificate expired and is no longer trusted by modern browsers.",
      impact: "Visitors receive security warnings, and traffic can no longer be reliably assumed to be encrypted end-to-end without exceptions being clicked through.",
      recommendation: "Renew the TLS certificate immediately and enable automatic renewal (for example, via ACME/Let's Encrypt) to prevent recurrence.",
      verification_steps: [
        "Check certificate expiry with openssl s_client",
        "Renew the certificate through your CA/ACME client",
        "Enable auto-renewal and monitoring alerts before expiry",
      ],
      priority: "critical",
    },
  },
];

export const devices = [
  { id: "dev_001", name: "ESP32", ip: "192.168.1.20", mac: "3C:71:BF:AA:11:02", type: "IoT Sensor", status: "online", risk: "low", known: true },
  { id: "dev_002", name: "Raspberry Pi", ip: "192.168.1.21", mac: "B8:27:EB:44:9A:10", type: "Edge Compute", status: "online", risk: "low", known: true },
  { id: "dev_003", name: "IP Camera", ip: "192.168.1.22", mac: "AC:CF:23:11:8B:5D", type: "Camera", status: "online", risk: "medium", known: true },
  { id: "dev_004", name: "Smart Plug", ip: "192.168.1.28", mac: "18:FE:34:9C:20:A1", type: "IoT Actuator", status: "offline", risk: "low", known: true },
  { id: "dev_005", name: "Unknown Device", ip: "192.168.1.35", mac: "DE:AD:12:34:BE:EF", type: "Unclassified", status: "online", risk: "high", known: false },
];

export const securityEvents = [
  { id: "event_001", source: "Suricata", source_ip: "192.168.1.35", type: "IDS Alert", detail: "Signature matched: possible port scan pattern", severity: "high", timestamp: "2026-08-24T10:25:00Z" },
  { id: "event_002", source: "Zeek", source_ip: "192.168.1.35", type: "Abnormal Traffic", detail: "Unusual outbound connection burst to 5 distinct hosts in 10s", severity: "medium", timestamp: "2026-08-24T10:25:04Z" },
  { id: "event_003", source: "WiFi Guard", source_ip: "192.168.1.35", type: "Unknown Device", detail: "Unrecognized MAC joined the network", severity: "high", timestamp: "2026-08-24T10:24:40Z" },
  { id: "event_004", source: "AI Engine", source_ip: "192.168.1.35", type: "Anomaly Detected", detail: "Isolation Forest flagged outlier connection pattern (score 0.87)", severity: "high", timestamp: "2026-08-24T10:25:10Z" },
  { id: "event_005", source: "Wazuh", source_ip: "192.168.1.22", type: "Config Change", detail: "Camera firmware settings modified outside maintenance window", severity: "medium", timestamp: "2026-08-23T21:02:00Z" },
  { id: "event_006", source: "Scanner", source_ip: "demo-juiceshop.local", type: "Vulnerability Found", detail: "TRACE method enabled on web server", severity: "critical", timestamp: "2026-08-24T10:34:00Z" },
];

export const incidents = [
  {
    id: "incident_001",
    title: "Correlated Intrusion Pattern — 192.168.1.35",
    risk_score: 91,
    risk_level: "high",
    status: "open",
    created_at: "2026-08-24T10:25:10Z",
    asset: "192.168.1.35 (Unknown Device)",
    signals: [
      { source: "WiFi Guard", detail: "Unknown device joined the network" },
      { source: "Zeek", detail: "Abnormal outbound traffic burst" },
      { source: "Suricata", detail: "IDS signature match: possible port scan" },
      { source: "AI Engine", detail: "Anomaly score 0.87 (high)" },
    ],
    formula_breakdown: { S: 0.8, E: 0.75, A: 0.87, I: 0.9, R: 0.7 },
  },
  {
    id: "incident_002",
    title: "Web Misconfiguration Cluster — demo-juiceshop.local",
    risk_score: 64,
    risk_level: "medium",
    status: "investigating",
    created_at: "2026-08-24T10:34:00Z",
    asset: "demo-juiceshop.local",
    signals: [
      { source: "Scanner", detail: "TRACE method enabled" },
      { source: "Scanner", detail: "Missing HttpOnly cookie flag" },
      { source: "AI Engine", detail: "Findings clustered under Security Misconfiguration" },
    ],
    formula_breakdown: { S: 0.6, E: 0.4, A: 0.2, I: 0.55, R: 0.3 },
  },
];

export const pipelineRuns = [
  { stage: "Build", status: "passed" },
  { stage: "Unit Tests", status: "passed" },
  { stage: "Semgrep (SAST)", status: "passed" },
  { stage: "Trivy (Image Scan)", status: "warning", detail: "2 medium CVEs in base image" },
  { stage: "OWASP ZAP Baseline", status: "failed", detail: "2 critical findings on staging target" },
  { stage: "Security Gate", status: "blocked" },
  { stage: "Deploy", status: "blocked" },
];

export const cloudMetrics = {
  status: "online",
  cpu: 32,
  memory: 48,
  requests_per_min: 245,
  errors: 3,
  containers_healthy: 5,
  containers_total: 5,
  uptime: "14d 6h",
};

export const networkMetrics = {
  packets_per_sec: 1240,
  active_connections: 86,
  bandwidth_mbps: 34.2,
  protocol_distribution: [
    { name: "TCP", value: 58 },
    { name: "UDP", value: 21 },
    { name: "DNS", value: 12 },
    { name: "HTTP", value: 9 },
  ],
  traffic_trend: [
    { time: "10:00", mbps: 18 },
    { time: "10:05", mbps: 22 },
    { time: "10:10", mbps: 19 },
    { time: "10:15", mbps: 31 },
    { time: "10:20", mbps: 27 },
    { time: "10:25", mbps: 40 },
    { time: "10:30", mbps: 34 },
  ],
  top_ips: [
    { ip: "192.168.1.21", traffic: "4.1 GB" },
    { ip: "192.168.1.35", traffic: "2.8 GB" },
    { ip: "192.168.1.20", traffic: "1.2 GB" },
  ],
};

export function severitySummaryFor(scanId) {
  const scan = scanHistory.find((s) => s.id === scanId);
  return scan ? scan.severity_summary : { critical: 0, high: 0, medium: 0, low: 0 };
}

export const scanCheckSteps = [
  "Resolving target & validating authorization",
  "Analyzing HTTP response & redirects",
  "Inspecting TLS/SSL certificate",
  "Checking security headers",
  "Checking cookie flags",
  "Probing allowed HTTP methods",
  "Detecting technology stack",
  "Mapping findings to OWASP categories",
  "Running AI risk analysis",
  "Finalizing report",
];
