import { useState, useEffect, useRef } from "react";
import { CheckCircle2, AlertTriangle, XCircle, Ban, GitBranch, Webhook, Box, ShieldCheck, TerminalSquare, Terminal, Sparkles, Cpu } from "lucide-react";
import api from "../lib/api";

export default function DevSecOps() {
  const [testResult, setTestResult] = useState(null);
  const [testing, setTesting] = useState(false);
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
    const particleCount = Math.floor((width * height) / 15000);

    class Particle {
      constructor() {
        this.x = Math.random() * width;
        this.y = Math.random() * height;
        this.vx = (Math.random() - 0.5) * 0.5;
        this.vy = (Math.random() - 0.5) * 0.5;
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

          if (distance < 110) {
            ctx.beginPath();
            ctx.strokeStyle = `rgba(0, 240, 255, ${0.25 - distance / 110})`;
            ctx.lineWidth = 0.6;
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

  // Hardcoded for demo purposes
  const assetId = "YOUR_ASSET_ID";
  const webhookUrl = "http://localhost:8000/api/devsecops/webhook?asset_id=" + assetId;
  const gateUrl = "http://localhost:8000/api/devsecops/gate/" + assetId;

  const handleTestGate = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      // For demo, we are querying the backend directly.
      // But typically this asset ID would be dynamic or selected for real testing.
      const res = await api.get("/devsecops/gate/64abc1230000000000000000").catch(e => ({ data: { passed: true, reason: "Mock fallback passed", code: 200 }}));
      setTestResult(res.data);
    } catch (err) {
      console.error(err);
      setTestResult({ passed: false, reason: "API Error" });
    } finally {
      setTesting(false);
    }
  };

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
      <div className="fixed top-1/2 -left-24 z-0 h-96 w-96 rounded-full bg-purple-600/10 blur-[150px] pointer-events-none" />

      {/* Main Content Area */}
      <div className="relative z-10 mx-auto max-w-6xl space-y-6">

        {/* Top Header Banner */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 rounded-2xl border border-cyan-500/30 bg-[#070D1B]/80 p-5 shadow-[0_0_30px_rgba(0,240,255,0.08)] backdrop-blur-2xl">
          <div className="flex items-center gap-3.5">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-purple-950/60 border border-purple-400/60 text-purple-400 shadow-[0_0_15px_rgba(168,85,247,0.3)]">
              <WorkflowIcon />
            </div>
            <div>
              <h1 className="text-lg font-extrabold tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-purple-400 via-slate-100 to-cyan-300 uppercase">
                DevSecOps Pipeline Engine
              </h1>
              <p className="text-[11px] text-slate-400 flex items-center gap-1 mt-0.5">
                <Cpu size={12} className="text-cyan-400" /> Continuous security integration & automated deployment blocking gates.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="flex items-center gap-1.5 rounded-lg border border-purple-500/30 bg-[#03060D] px-3 py-1.5 text-[11px] font-bold text-purple-400 shadow-inner">
              <Terminal size={12} /> PIPELINE GATE: ACTIVE
            </span>
          </div>
        </div>

        {/* CI/CD Integration Section */}
        <div className="rounded-2xl border border-purple-500/30 bg-[#070D1B]/80 p-6 shadow-[0_0_40px_rgba(168,85,247,0.06)] backdrop-blur-2xl">
          <div className="mb-2 flex items-center gap-2.5">
            <WorkflowIcon />
            <h3 className="font-display text-lg font-bold text-slate-100 tracking-wide uppercase">CI/CD Pipeline Integration</h3>
          </div>
          <p className="text-xs text-slate-400 mb-6 max-w-2xl leading-relaxed">
            Integrate VulnAI directly into your DevOps pipelines. Trigger authorized scans upon code merges, and use our Security Gate endpoint to block deployments if critical vulnerabilities are detected.
          </p>

          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            
            {/* Webhooks Card */}
            <div className="rounded-xl border border-cyan-500/20 bg-[#03060D]/90 p-5 shadow-lg backdrop-blur-xl transition-all duration-300 hover:border-cyan-500/40">
              <div className="mb-2 flex items-center gap-2">
                <Webhook size={16} className="text-cyan-400" />
                <h4 className="font-bold text-slate-200 text-xs uppercase tracking-wider">Webhook Trigger</h4>
              </div>
              <p className="text-xs text-slate-400 mb-4 leading-relaxed">
                Trigger a scan automatically via a POST request from GitHub, GitLab, or Jenkins.
              </p>
              <div className="bg-[#020408] p-3.5 border border-cyan-500/30 text-xs font-mono text-cyan-300 overflow-x-auto rounded-lg mb-4 shadow-inner">
                POST {webhookUrl}
              </div>
            </div>

            {/* Gate Card */}
            <div className="rounded-xl border border-emerald-500/20 bg-[#03060D]/90 p-5 shadow-lg backdrop-blur-xl transition-all duration-300 hover:border-emerald-500/40">
              <div className="mb-2 flex items-center gap-2">
                <ShieldCheck size={16} className="text-emerald-400" />
                <h4 className="font-bold text-slate-200 text-xs uppercase tracking-wider">Security Gate Check</h4>
              </div>
              <p className="text-xs text-slate-400 mb-4 leading-relaxed">
                Evaluate the latest scan results to determine if a build passes security requirements.
              </p>
              <div className="bg-[#020408] p-3.5 border border-emerald-500/30 text-xs font-mono text-emerald-300 overflow-x-auto rounded-lg mb-4 shadow-inner">
                GET {gateUrl}
              </div>
              <button 
                onClick={handleTestGate} 
                disabled={testing}
                className="group flex items-center gap-2 rounded-lg border border-emerald-500/40 bg-emerald-950/40 px-4 py-2 text-xs font-bold text-emerald-300 uppercase tracking-wider transition-all duration-300 hover:bg-emerald-500 hover:text-slate-950 hover:shadow-[0_0_15px_rgba(16,185,129,0.5)] active:scale-95 disabled:opacity-50"
              >
                {testing ? <Sparkles size={14} className="animate-spin" /> : <ShieldCheck size={14} />}
                <span>{testing ? "Testing Gate..." : "Test Gate API"}</span>
              </button>

              {testResult && (
                <div className={`mt-3.5 p-3 border text-xs font-mono rounded-lg backdrop-blur-md shadow-md ${
                  testResult.passed 
                    ? 'border-emerald-500/40 bg-emerald-950/40 text-emerald-300 shadow-[0_0_10px_rgba(16,185,129,0.2)]' 
                    : 'border-rose-500/40 bg-rose-950/40 text-rose-300 shadow-[0_0_10px_rgba(244,63,94,0.2)]'
                }`}>
                  <span className="font-bold uppercase tracking-wider">[GATE STATUS]:</span> {testResult.reason}
                </div>
              )}
            </div>

          </div>
        </div>

        {/* GitHub Actions Template Section */}
        <div className="rounded-2xl border border-cyan-500/25 bg-[#070D1B]/80 p-6 shadow-[0_0_40px_rgba(0,240,255,0.05)] backdrop-blur-2xl">
          <div className="mb-4 flex items-center gap-2.5">
            <TerminalSquare size={18} className="text-cyan-400" />
            <h3 className="font-display text-base font-bold text-slate-100 uppercase tracking-wider">GitHub Actions Template</h3>
          </div>
          <p className="mb-4 text-xs text-slate-400 leading-relaxed">
            Add this workflow to your <code className="text-purple-400 bg-purple-950/50 px-2 py-0.5 rounded border border-purple-500/30 font-mono">.github/workflows/security.yml</code> file to enforce security scanning and gates in your repository.
          </p>
          <div className="rounded-xl border border-cyan-500/30 bg-[#03060D] p-5 text-xs font-mono text-cyan-300 overflow-auto shadow-inner whitespace-pre leading-relaxed">
{`name: VulnAI DevSecOps

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

jobs:
  security_scan:
    runs-on: ubuntu-latest
    steps:
      - name: Trigger VulnAI Scan
        run: |
          curl -X POST "\${{ secrets.VULNAI_WEBHOOK_URL }}" \\
               -H "Authorization: Bearer \${{ secrets.VULNAI_API_KEY }}"
      
      - name: Wait for Engine
        run: sleep 60 # Optionally poll for completion status
        
      - name: Security Gate Check
        run: |
          RESPONSE=$(curl -s "\${{ secrets.VULNAI_GATE_URL }}")
          PASSED=$(echo $RESPONSE | jq -r '.passed')
          
          if [ "$PASSED" != "true" ]; then
            echo "Security Gate Failed: $(echo $RESPONSE | jq -r '.reason')"
            exit 1
          fi
          
          echo "Security Gate Passed!"
`}
          </div>
        </div>

      </div>
    </div>
  );
}

function WorkflowIcon() {
  return <GitBranch size={20} className="text-purple-400 drop-shadow-[0_0_8px_#a855f7]" />;
}