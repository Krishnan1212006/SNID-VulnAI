import { Link } from "react-router-dom";
import { ArrowRight } from "lucide-react";

const PRINCIPLES = [
  {
    n: "01",
    title: "Authorization first",
    text: "Every scan requires an explicit confirmation of ownership or written permission. There is no path around it — the backend rejects unauthorized targets outright.",
  },
  {
    n: "02",
    title: "Passive by default",
    text: "We check headers, certificates, cookies and methods. We do not exploit, brute-force, or actively probe. Safety is a design constraint, not an afterthought.",
  },
  {
    n: "03",
    title: "Explainable risk",
    text: "A score with no reasoning behind it isn't useful. Every finding carries a plain-language problem statement, its impact, and a verifiable fix.",
  },
  {
    n: "04",
    title: "One view of truth",
    text: "Web findings, network signals, IoT device state and pipeline status belong in a single account — not five tabs that never agree with each other.",
  },
];

export default function About() {
  return (
    <div>
      {/* Header */}
      <section className="mx-auto max-w-4xl px-5 pb-14 pt-16 lg:px-8 lg:pb-20 lg:pt-24">
        <p className="kicker mb-4">About</p>
        <h1 className="font-display text-4xl font-medium leading-[1.15] text-text-main sm:text-5xl">
          Built for teams who'd rather <span className="italic text-purple">know</span> than hope.
        </h1>
        <p className="mt-6 max-w-2xl text-base leading-relaxed text-text-secondary">
          VulnAI-DevSecOps started as a final-year project with a simple complaint: small teams
          and student projects end up stitching together a web scanner, a network monitor, an
          intrusion detector, and a spreadsheet of findings — and still can't answer "how exposed
          are we, right now?" in one sentence. This platform is an attempt to give a straight
          answer to that question.
        </p>
      </section>

      {/* 01 — Why */}
      <section className="border-t border-border">
        <div className="mx-auto max-w-4xl px-5 py-14 lg:px-8 lg:py-20">
          <SectionLabel n="01" title="Why this exists" />
          <div className="space-y-5 text-sm leading-relaxed text-text-secondary sm:text-base">
            <p>
              Most tools in this space are built for enterprise security teams with dedicated
              analysts and six-figure tooling budgets. Everyone else is left combining a handful
              of open-source scanners, reading raw JSON output, and manually deciding what
              actually matters.
            </p>
            <p>
              VulnAI-DevSecOps takes a narrower, more honest scope: passive web assessment,
              network and IoT signal correlation, and AI-assisted explanation — wired into one
              dashboard with a transparent, published risk-scoring formula. Nothing here claims
              to replace a professional penetration test. It claims to replace guessing.
            </p>
          </div>
        </div>
      </section>

      {/* 02 — Principles */}
      <section className="border-t border-border bg-bg-secondary">
        <div className="mx-auto max-w-4xl px-5 py-14 lg:px-8 lg:py-20">
          <SectionLabel n="02" title="Principles" />
          <div className="divide-y divide-border border-t border-border">
            {PRINCIPLES.map((p) => (
              <div key={p.n} className="grid grid-cols-1 gap-2 py-6 sm:grid-cols-12 sm:gap-6">
                <span className="font-display text-2xl font-medium text-purple sm:col-span-1">{p.n}</span>
                <h3 className="font-display text-lg font-medium text-text-main sm:col-span-3">{p.title}</h3>
                <p className="text-sm leading-relaxed text-text-secondary sm:col-span-8">{p.text}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* 03 — How it's built */}
      <section className="border-t border-border">
        <div className="mx-auto max-w-4xl px-5 py-14 lg:px-8 lg:py-20">
          <SectionLabel n="03" title="How it's built" />
          <div className="grid grid-cols-1 gap-8 sm:grid-cols-2">
            <div>
              <p className="kicker mb-2">Frontend</p>
              <p className="text-sm leading-relaxed text-text-secondary">
                React and Vite, with a component system built around hairline borders and a
                single accent color rather than gradients or motion for its own sake.
              </p>
            </div>
            <div>
              <p className="kicker mb-2">Backend &amp; data</p>
              <p className="text-sm leading-relaxed text-text-secondary">
                FastAPI and Neon Postgres, with a scanner service performing passive HTTP, TLS and
                header checks, an AI service for explanation, and a rule-based correlation
                engine for network and IoT signals.
              </p>
            </div>
            <div>
              <p className="kicker mb-2">Scoring</p>
              <p className="text-sm leading-relaxed text-text-secondary">
                A published, weighted formula — severity, event volume, AI anomaly score,
                correlation strength and asset risk — so every number on the dashboard can be
                traced back to a reason.
              </p>
            </div>
            <div>
              <p className="kicker mb-2">Safety controls</p>
              <p className="text-sm leading-relaxed text-text-secondary">
                Authorization gating, private-range blocking outside lab mode, rate limits,
                request timeouts, and full logging of every scan request.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="border-t border-border bg-bg-secondary">
        <div className="mx-auto flex max-w-4xl flex-col items-start justify-between gap-6 px-5 py-14 lg:flex-row lg:items-center lg:px-8 lg:py-20">
          <div>
            <h2 className="font-display text-2xl font-medium text-text-main">Have a question about the project?</h2>
            <p className="mt-2 max-w-md text-sm text-text-secondary">
              Reach out — we read every message.
            </p>
          </div>
          <Link to="/contact" className="btn-signature flex shrink-0 items-center gap-2 px-6 py-3.5 text-sm font-semibold">
            Get in touch <ArrowRight size={15} />
          </Link>
        </div>
      </section>
    </div>
  );
}

function SectionLabel({ n, title }) {
  return (
    <div className="mb-10 flex items-baseline gap-3">
      <span className="font-mono text-xs text-purple">{n}</span>
      <h2 className="font-display text-2xl font-medium text-text-main">{title}</h2>
      <span className="h-px flex-1 bg-border" />
    </div>
  );
}
