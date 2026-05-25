import React, { useState, useEffect, useMemo } from "react";
import {
  Shield, GitBranch, Zap, FileCheck, AlertTriangle, CheckCircle2, XCircle,
  Activity, Database, Lock, FileText, Layers, Server, Cpu, Workflow,
  ArrowRight, Github, ExternalLink, Terminal, ChevronRight, Sparkles,
  Boxes, ScrollText, Gauge, Network, Eye, Play, Loader2
} from "lucide-react";

/**
 * AI Risk Platform — portfolio page
 * Single-file React + Tailwind component. Drop into Claude artifacts.
 *
 * Design notes:
 *  - Security-console aesthetic: deep zinc, mono type, signal colors.
 *  - Emerald = PASS / safe path. Rose = BLOCK / risk. Amber = AI-advisory.
 *  - Every section maps to a real component in the codebase.
 */

const SCANNERS = [
  { name: "Semgrep", kind: "SAST", color: "violet" },
  { name: "Grype", kind: "SCA", color: "cyan" },
  { name: "Trivy", kind: "SCA + Image", color: "cyan" },
  { name: "Gitleaks", kind: "Secrets", color: "rose" },
  { name: "Checkov", kind: "IaC", color: "amber" },
  { name: "ZAP", kind: "DAST", color: "blue" },
  { name: "kube-bench", kind: "CIS", color: "emerald" },
  { name: "CIS-Java", kind: "CIS", color: "emerald" },
  { name: "SpotBugs", kind: "SAST", color: "violet" },
];

const FRAMEWORKS = [
  {
    code: "PCI-DSS",
    version: "v4.0",
    name: "Payment Card Industry",
    coverage: "Req 1, 2, 3, 6, 8, 11",
    why: "Cardholder data handling, network segmentation, app security",
    accent: "rose",
  },
  {
    code: "SOC 2",
    version: "TSC 2017",
    name: "AICPA Trust Services Criteria",
    coverage: "CC6 / CC7 / CC8 + Confidentiality",
    why: "Security, availability, processing integrity, confidentiality",
    accent: "violet",
  },
  {
    code: "ISO 27001",
    version: "2022 Annex A",
    name: "ISO/IEC Information Security",
    coverage: "A.5 / A.8 — organizational + technological",
    why: "Internationally recognized ISMS baseline",
    accent: "amber",
  },
];

const PIPELINE_STEPS = [
  { n: 1, label: "Ingest", detail: "8 scanner formats", icon: Layers },
  { n: 2, label: "Parse", detail: "→ Finding[]", icon: ScrollText },
  { n: 3, label: "Tag controls", detail: "PCI / SOC 2 / ISO 27001", icon: Lock },
  { n: 4, label: "Enrich (EPSS)", detail: "CVE → exploit prob.", icon: Sparkles },
  { n: 5, label: "Risk pipeline", detail: "NIST SP 800-30", icon: Cpu },
  { n: 6, label: "Gate", detail: "YAML + Rego", icon: Shield },
  { n: 7, label: "SAR + POA&M", detail: "auditor evidence", icon: FileText },
  { n: 8, label: "Authorize", detail: "ATO / DATO", icon: CheckCircle2 },
];

const RMF_STEPS = [
  { n: 1, label: "GATHER", who: "no AI", detail: "Collect findings, EPSS, controls" },
  { n: 2, label: "FILTER", who: "Haiku 4.5", detail: "Pick top-200 most critical" },
  { n: 3, label: "ASSESS", who: "Sonnet 4.6 · ×5 parallel", detail: "Per-finding SP 800-30" },
  { n: 4, label: "RESPOND", who: "no AI", detail: "Build POA&M + risk response" },
];

/* ────────────────────────────────────────────────────────────────────── */

export default function PortfolioPage() {
  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 font-sans antialiased selection:bg-emerald-400/30">
      <BackgroundGrid />
      <Nav />
      <main className="relative">
        <Hero />
        <StatsStrip />
        <PipelineSection />
        <LiveDemo />
        <FrameworksSection />
        <RmfPipelineSection />
        <ArchitectureSection />
        <TechStack />
        <Footer />
      </main>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────── */

function BackgroundGrid() {
  return (
    <>
      <div
        aria-hidden
        className="pointer-events-none fixed inset-0 opacity-[0.025]"
        style={{
          backgroundImage:
            "linear-gradient(to right, white 1px, transparent 1px), linear-gradient(to bottom, white 1px, transparent 1px)",
          backgroundSize: "48px 48px",
        }}
      />
      <div
        aria-hidden
        className="pointer-events-none fixed inset-x-0 top-0 h-[520px] bg-gradient-to-b from-emerald-500/[0.07] via-transparent to-transparent blur-3xl"
      />
    </>
  );
}

function Nav() {
  return (
    <header className="sticky top-0 z-30 border-b border-zinc-900/80 bg-zinc-950/70 backdrop-blur-xl">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-md bg-emerald-400/10 ring-1 ring-emerald-400/30">
            <Shield className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="font-mono text-sm tracking-tight">
            ai-risk-platform <span className="text-zinc-600">/</span>{" "}
            <span className="text-zinc-400">v0.1.0</span>
          </div>
        </div>
        <nav className="hidden items-center gap-7 text-sm text-zinc-400 md:flex">
          <a href="#pipeline" className="hover:text-zinc-100">Pipeline</a>
          <a href="#demo" className="hover:text-zinc-100">Live gate</a>
          <a href="#frameworks" className="hover:text-zinc-100">Frameworks</a>
          <a href="#rmf" className="hover:text-zinc-100">RMF engine</a>
          <a href="#stack" className="hover:text-zinc-100">Stack</a>
        </nav>
        <a
          href="#"
          className="group inline-flex items-center gap-2 rounded-md border border-zinc-800 bg-zinc-900/50 px-3 py-1.5 text-sm text-zinc-300 hover:border-zinc-700 hover:bg-zinc-900"
        >
          <Github className="h-4 w-4" />
          <span>Source</span>
          <ExternalLink className="h-3 w-3 text-zinc-500 group-hover:text-zinc-300" />
        </a>
      </div>
    </header>
  );
}

/* ────────────────────────────────────────────────────────────────────── */

function Hero() {
  return (
    <section className="relative mx-auto max-w-7xl px-6 pt-20 pb-24 md:pt-28 md:pb-32">
      <div className="grid items-center gap-14 md:grid-cols-[1.1fr,1fr]">
        <div>
          <div className="inline-flex items-center gap-2 rounded-full border border-emerald-400/20 bg-emerald-400/5 px-3 py-1 font-mono text-xs text-emerald-300">
            <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />
            NIST SP 800-30 · SP 800-37 RMF · cATO-aligned
          </div>
          <h1 className="mt-6 text-4xl font-semibold leading-[1.05] tracking-tight text-zinc-50 sm:text-5xl md:text-6xl">
            From scanner output<br />
            to{" "}
            <span className="bg-gradient-to-r from-emerald-300 to-emerald-500 bg-clip-text text-transparent">
              ATO decision
            </span>
            ,<br />in one pipeline.
          </h1>
          <p className="mt-6 max-w-xl text-lg leading-relaxed text-zinc-400">
            A compliance-driven DevSecOps risk engine that ingests output
            from 9 scanners, maps every finding to a control, scores risk via{" "}
            <span className="text-zinc-200">Claude Sonnet 4.6</span> (or
            deterministic fallback), and emits a gate decision plus
            auditor-ready SAR &amp; POA&amp;M.
          </p>

          <div className="mt-8 flex flex-wrap items-center gap-3">
            <a
              href="#demo"
              className="inline-flex items-center gap-2 rounded-md bg-emerald-400 px-4 py-2.5 text-sm font-medium text-zinc-950 transition hover:bg-emerald-300"
            >
              <Play className="h-4 w-4" /> See it gate a PR
            </a>
            <a
              href="#pipeline"
              className="inline-flex items-center gap-2 rounded-md border border-zinc-800 bg-zinc-900/40 px-4 py-2.5 text-sm text-zinc-300 transition hover:border-zinc-700"
            >
              How it works <ArrowRight className="h-4 w-4" />
            </a>
          </div>

          <div className="mt-10 flex flex-wrap gap-x-8 gap-y-3 font-mono text-xs text-zinc-500">
            <span>Python 3.11</span>
            <span className="text-zinc-700">·</span>
            <span>FastAPI</span>
            <span className="text-zinc-700">·</span>
            <span>AWS Bedrock</span>
            <span className="text-zinc-700">·</span>
            <span>OPA / Rego</span>
            <span className="text-zinc-700">·</span>
            <span>Redis</span>
            <span className="text-zinc-700">·</span>
            <span>EKS / ECR</span>
          </div>
        </div>

        <HeroPanel />
      </div>
    </section>
  );
}

function HeroPanel() {
  return (
    <div className="relative">
      <div className="absolute -inset-4 -z-10 rounded-2xl bg-gradient-to-br from-emerald-400/10 via-transparent to-rose-500/10 blur-2xl" />
      <div className="overflow-hidden rounded-xl border border-zinc-800 bg-zinc-900/40 shadow-2xl shadow-black/40">
        <div className="flex items-center gap-2 border-b border-zinc-800 bg-zinc-900/60 px-4 py-2.5">
          <div className="flex gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-zinc-700" />
            <span className="h-2.5 w-2.5 rounded-full bg-zinc-700" />
            <span className="h-2.5 w-2.5 rounded-full bg-zinc-700" />
          </div>
          <div className="ml-2 font-mono text-xs text-zinc-500">
            POST /v1/products/payment-api/assess
          </div>
          <span className="ml-auto inline-flex items-center gap-1.5 rounded-full bg-emerald-400/10 px-2 py-0.5 font-mono text-[10px] text-emerald-300">
            <CheckCircle2 className="h-3 w-3" /> 200 OK
          </span>
        </div>
        <div className="p-5 font-mono text-[13px] leading-relaxed">
          <div className="text-zinc-500">// gate decision</div>
          <Line k="passed" v="false" vClass="text-rose-400" />
          <Line
            k="reason"
            v={`"BLOCKED: max_critical_findings violated\n   found 2, limit 0 (control: PCI-DSS-6.3.1)"`}
            vClass="text-rose-300"
          />
          <Line k="findings_count" v="" />
          <div className="pl-4">
            <Line k="critical" v="2" vClass="text-rose-400" />
            <Line k="high" v="7" vClass="text-amber-400" />
            <Line k="medium" v="14" vClass="text-zinc-300" />
            <Line k="low" v="31" vClass="text-zinc-500" />
          </div>
          <div className="mt-3 text-zinc-500">// authorization</div>
          <Line k="decision" v={`"denied"`} vClass="text-rose-300" />
          <Line k="next_review" v={`"2026-08-25"`} vClass="text-zinc-300" />
        </div>
      </div>
    </div>
  );
}

function Line({ k, v, vClass = "text-zinc-300" }: { k: string; v: string; vClass?: string }) {
  return (
    <div className="flex gap-3">
      <span className="text-zinc-500">{k}:</span>
      <span className={vClass + " whitespace-pre"}>{v}</span>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────── */

function StatsStrip() {
  const stats = [
    { v: "9", l: "scanner adapters" },
    { v: "3", l: "compliance frameworks" },
    { v: "7", l: "DevSecOps phases" },
    { v: "100%", l: "local gate path" },
    { v: "×5", l: "parallel AI assess" },
  ];
  return (
    <section className="border-y border-zinc-900 bg-zinc-950/50">
      <div className="mx-auto grid max-w-7xl grid-cols-2 gap-px overflow-hidden bg-zinc-900 md:grid-cols-5">
        {stats.map((s) => (
          <div key={s.l} className="bg-zinc-950/80 px-6 py-7">
            <div className="font-mono text-3xl font-semibold tracking-tight text-zinc-50">
              {s.v}
            </div>
            <div className="mt-1 text-sm text-zinc-500">{s.l}</div>
          </div>
        ))}
      </div>
    </section>
  );
}

/* ────────────────────────────────────────────────────────────────────── */

function PipelineSection() {
  return (
    <section id="pipeline" className="mx-auto max-w-7xl px-6 py-24">
      <SectionHeader
        eyebrow="Pipeline"
        title="One pipeline. Every finding traceable to a control."
        sub="The whole platform pivots on Control ID. Every scanner output gets normalized, tagged, scored, and gated against a YAML + Rego policy — then bundled into auditor evidence."
      />

      <div className="mt-14 grid gap-3 md:grid-cols-4">
        {PIPELINE_STEPS.map((step, i) => {
          const Icon = step.icon;
          return (
            <div
              key={step.n}
              className="group relative overflow-hidden rounded-lg border border-zinc-800/80 bg-zinc-900/30 p-5 transition hover:border-emerald-400/30 hover:bg-zinc-900/60"
            >
              <div className="absolute right-3 top-3 font-mono text-xs text-zinc-700">
                {String(step.n).padStart(2, "0")}
              </div>
              <Icon className="h-5 w-5 text-emerald-400" />
              <div className="mt-3 text-base font-medium text-zinc-100">
                {step.label}
              </div>
              <div className="mt-1 font-mono text-xs text-zinc-500">
                {step.detail}
              </div>
              {i < PIPELINE_STEPS.length - 1 && (
                <ChevronRight className="absolute -right-2 top-1/2 hidden h-5 w-5 -translate-y-1/2 text-zinc-700 md:block" />
              )}
            </div>
          );
        })}
      </div>

      <ScannerMarquee />
    </section>
  );
}

function ScannerMarquee() {
  return (
    <div className="mt-14 overflow-hidden rounded-xl border border-zinc-900 bg-zinc-950/60">
      <div className="grid grid-cols-2 gap-px bg-zinc-900 md:grid-cols-3 lg:grid-cols-9">
        {SCANNERS.map((s) => (
          <div
            key={s.name}
            className="bg-zinc-950 px-4 py-5 transition hover:bg-zinc-900/60"
          >
            <div className="font-mono text-sm text-zinc-200">{s.name}</div>
            <div className="mt-1 text-[11px] uppercase tracking-wider text-zinc-500">
              {s.kind}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────── */

function LiveDemo() {
  const [phase, setPhase] = useState<"idle" | "running" | "done">("idle");
  const [step, setStep] = useState(0);

  useEffect(() => {
    if (phase !== "running") return;
    if (step >= PIPELINE_STEPS.length) {
      setPhase("done");
      return;
    }
    const t = setTimeout(() => setStep((s) => s + 1), 350);
    return () => clearTimeout(t);
  }, [phase, step]);

  const run = () => {
    setStep(0);
    setPhase("running");
  };
  const reset = () => {
    setStep(0);
    setPhase("idle");
  };

  return (
    <section id="demo" className="border-y border-zinc-900 bg-gradient-to-b from-zinc-950 to-zinc-950/40">
      <div className="mx-auto max-w-7xl px-6 py-24">
        <SectionHeader
          eyebrow="Live demo"
          title="Watch a PR get gated."
          sub="Simulated assessment on payment-api (PCI + PII-financial, ap-northeast-1). The gate path is 100% local — AI only enriches narrative."
        />

        <div className="mt-12 grid gap-6 md:grid-cols-[1fr,1.1fr]">
          {/* Control panel */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-6">
            <div className="font-mono text-xs text-zinc-500">request</div>
            <div className="mt-2 rounded-md border border-zinc-800 bg-zinc-950/80 p-4 font-mono text-[12.5px] leading-relaxed">
              <div className="text-emerald-400">POST</div>
              <div className="text-zinc-300">/v1/products/payment-api/assess</div>
              <div className="mt-3 text-zinc-500">{`{`}</div>
              <div className="pl-4 text-zinc-300">
                "trigger": <span className="text-amber-300">"pre_merge"</span>,
              </div>
              <div className="pl-4 text-zinc-300">
                "async_mode": <span className="text-amber-300">true</span>,
              </div>
              <div className="pl-4 text-zinc-300">
                "results": <span className="text-zinc-500">[ 8 scanner payloads… ]</span>
              </div>
              <div className="text-zinc-500">{`}`}</div>
            </div>

            <div className="mt-5 flex items-center gap-3">
              <button
                onClick={run}
                disabled={phase === "running"}
                className="inline-flex items-center gap-2 rounded-md bg-emerald-400 px-4 py-2 text-sm font-medium text-zinc-950 transition hover:bg-emerald-300 disabled:opacity-60"
              >
                {phase === "running" ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Play className="h-4 w-4" />
                )}
                {phase === "running" ? "Assessing…" : "Run assessment"}
              </button>
              {phase !== "idle" && (
                <button
                  onClick={reset}
                  className="text-sm text-zinc-500 hover:text-zinc-300"
                >
                  reset
                </button>
              )}
            </div>

            <ul className="mt-6 space-y-2 font-mono text-xs">
              {PIPELINE_STEPS.map((s, i) => {
                const active = phase === "running" && i === step;
                const done = i < step || phase === "done";
                return (
                  <li
                    key={s.n}
                    className={
                      "flex items-center gap-3 transition " +
                      (done
                        ? "text-emerald-300"
                        : active
                        ? "text-zinc-100"
                        : "text-zinc-600")
                    }
                  >
                    <span
                      className={
                        "flex h-5 w-5 items-center justify-center rounded-full border text-[10px] " +
                        (done
                          ? "border-emerald-400/40 bg-emerald-400/10"
                          : active
                          ? "border-zinc-600 bg-zinc-800"
                          : "border-zinc-800")
                      }
                    >
                      {done ? <CheckCircle2 className="h-3 w-3" /> : s.n}
                    </span>
                    <span>{s.label}</span>
                    <span className="text-zinc-700">·</span>
                    <span className="text-zinc-600">{s.detail}</span>
                    {active && (
                      <Loader2 className="ml-auto h-3.5 w-3.5 animate-spin text-zinc-500" />
                    )}
                  </li>
                );
              })}
            </ul>
          </div>

          {/* Result panel */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 overflow-hidden">
            <div className="flex items-center justify-between border-b border-zinc-800 px-5 py-3">
              <div className="font-mono text-xs text-zinc-500">
                GET /v1/jobs/job_8f3a…
              </div>
              {phase === "done" ? (
                <span className="inline-flex items-center gap-1.5 rounded-full bg-rose-400/10 px-2 py-0.5 font-mono text-[11px] text-rose-300">
                  <XCircle className="h-3 w-3" /> BLOCKED
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 rounded-full bg-zinc-800 px-2 py-0.5 font-mono text-[11px] text-zinc-400">
                  {phase === "running" ? "pending" : "idle"}
                </span>
              )}
            </div>
            {phase === "done" ? (
              <ResultPanel />
            ) : (
              <div className="flex h-[420px] items-center justify-center px-6 text-center text-sm text-zinc-600">
                {phase === "idle"
                  ? "Hit Run assessment to populate."
                  : "Awaiting completion…"}
              </div>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}

function ResultPanel() {
  return (
    <div className="space-y-5 p-5">
      <div>
        <div className="text-xs uppercase tracking-wider text-zinc-500">
          Gate decision
        </div>
        <div className="mt-1.5 flex items-baseline gap-3">
          <span className="font-mono text-2xl font-semibold text-rose-400">
            BLOCK
          </span>
          <span className="text-sm text-zinc-400">
            critical_findings &gt; 0 in PCI scope
          </span>
        </div>
      </div>

      <div className="grid grid-cols-4 gap-2">
        {[
          { l: "critical", v: 2, c: "text-rose-400" },
          { l: "high", v: 7, c: "text-amber-400" },
          { l: "medium", v: 14, c: "text-zinc-200" },
          { l: "low", v: 31, c: "text-zinc-500" },
        ].map((x) => (
          <div
            key={x.l}
            className="rounded-md border border-zinc-800 bg-zinc-950/60 p-3 text-center"
          >
            <div className={"font-mono text-xl " + x.c}>{x.v}</div>
            <div className="mt-1 text-[10px] uppercase tracking-wider text-zinc-500">
              {x.l}
            </div>
          </div>
        ))}
      </div>

      <div>
        <div className="text-xs uppercase tracking-wider text-zinc-500">
          Affected controls
        </div>
        <div className="mt-2 flex flex-wrap gap-1.5">
          {["PCI-DSS-6.3.1", "PCI-DSS-6.4.3", "SOC2-CC6.1", "ISO27001-A.8.28"].map(
            (c) => (
              <span
                key={c}
                className="rounded-md border border-zinc-800 bg-zinc-900 px-2 py-0.5 font-mono text-[11px] text-zinc-300"
              >
                {c}
              </span>
            )
          )}
        </div>
      </div>

      <div className="rounded-md border border-amber-400/20 bg-amber-400/[0.04] p-3">
        <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-amber-300">
          <Sparkles className="h-3.5 w-3.5" />
          AI narrative (Sonnet 4.6, advisory)
        </div>
        <p className="mt-2 text-sm leading-relaxed text-zinc-300">
          Two SQL injection patterns in <span className="font-mono">/v1/checkout</span> reach
          the cardholder data store. Combined with EPSS &gt; 0.4 on a transitive
          dep, threat event TE-002 is rated <span className="text-rose-300">high</span>{" "}
          likelihood × <span className="text-rose-300">high</span> impact →{" "}
          <span className="text-rose-300">risk score 78</span>.
        </p>
      </div>

      <div className="text-[11px] text-zinc-600">
        Authorization: <span className="text-rose-300">denied</span> · POA&amp;M items:{" "}
        <span className="text-zinc-300">23 open</span> · Next review:{" "}
        <span className="text-zinc-300">2026-08-25</span>
      </div>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────── */

function FrameworksSection() {
  return (
    <section id="frameworks" className="mx-auto max-w-7xl px-6 py-24">
      <SectionHeader
        eyebrow="Compliance plane"
        title="Findings → Controls → Frameworks"
        sub="OSCAL-compatible YAML controls. Every scanner finding gets tagged with the controls it satisfies (or violates). The SAR knows which scanner was supposed to verify which control."
      />

      <div className="mt-12 grid gap-5 md:grid-cols-3">
        {FRAMEWORKS.map((f) => (
          <FrameworkCard key={f.code} {...f} />
        ))}
      </div>
    </section>
  );
}

function FrameworkCard({
  code, version, name, coverage, why, accent,
}: typeof FRAMEWORKS[number]) {
  const accentMap: Record<string, string> = {
    rose: "from-rose-400/30 to-transparent text-rose-300 border-rose-400/30",
    violet: "from-violet-400/30 to-transparent text-violet-300 border-violet-400/30",
    amber: "from-amber-400/30 to-transparent text-amber-300 border-amber-400/30",
  };
  return (
    <div className="group relative overflow-hidden rounded-xl border border-zinc-800 bg-zinc-900/30 p-6">
      <div
        className={`absolute inset-x-0 top-0 h-px bg-gradient-to-r ${accentMap[accent].split(" ")[0]} ${accentMap[accent].split(" ")[1]}`}
      />
      <div className="flex items-baseline justify-between">
        <div className={`font-mono text-2xl font-semibold ${accentMap[accent].split(" ")[2]}`}>
          {code}
        </div>
        <div className="font-mono text-xs text-zinc-500">{version}</div>
      </div>
      <div className="mt-2 text-base text-zinc-200">{name}</div>
      <div className="mt-6 space-y-3 text-sm">
        <div>
          <div className="text-[11px] uppercase tracking-wider text-zinc-500">
            Coverage
          </div>
          <div className="mt-0.5 text-zinc-300">{coverage}</div>
        </div>
        <div>
          <div className="text-[11px] uppercase tracking-wider text-zinc-500">
            Why
          </div>
          <div className="mt-0.5 text-zinc-400">{why}</div>
        </div>
      </div>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────── */

function RmfPipelineSection() {
  return (
    <section id="rmf" className="border-y border-zinc-900 bg-zinc-950/40">
      <div className="mx-auto max-w-7xl px-6 py-24">
        <SectionHeader
          eyebrow="RMF engine"
          title={
            <>
              Deterministic gate. <span className="text-amber-300">Advisory AI.</span>
            </>
          }
          sub="The gate decision (PASS/BLOCK) is computed locally from YAML + Rego — it never depends on an AI call. AI only enriches risk narratives, POA&M descriptions, and threat modeling. Swap strategies at runtime."
        />

        <div className="mt-12 grid gap-3 md:grid-cols-4">
          {RMF_STEPS.map((s) => (
            <div
              key={s.n}
              className="relative overflow-hidden rounded-lg border border-zinc-800 bg-zinc-900/30 p-5"
            >
              <div className="font-mono text-xs text-zinc-500">
                Step {s.n}
              </div>
              <div className="mt-2 text-lg font-semibold tracking-tight text-zinc-100">
                {s.label}
              </div>
              <div
                className={
                  "mt-1 inline-flex items-center gap-1.5 font-mono text-[11px] " +
                  (s.who.includes("AI") || s.who.includes("Haiku") || s.who.includes("Sonnet")
                    ? "text-amber-300"
                    : "text-emerald-300")
                }
              >
                <span className="h-1.5 w-1.5 rounded-full bg-current" />
                {s.who}
              </div>
              <div className="mt-4 text-sm text-zinc-400">{s.detail}</div>
            </div>
          ))}
        </div>

        <div className="mt-10 grid gap-5 md:grid-cols-2">
          <ModeCard
            icon={Gauge}
            title="Static mode"
            badge="no network"
            color="emerald"
            bullets={[
              "Lookup-table risk scoring (likelihood × impact)",
              "Deterministic severity sort for top-N",
              "Air-gapped friendly · offline CI runs",
              "Same gate decision as AI mode",
            ]}
          />
          <ModeCard
            icon={Sparkles}
            title="Bedrock mode"
            badge="advisory only"
            color="amber"
            bullets={[
              "Haiku 4.5 filters top-200 critical findings",
              "Sonnet 4.6 · 5-way parallel per-finding SP 800-30",
              "Prompt-cache reads (stream_with_cache)",
              "Failure → graceful per-finding static fallback",
            ]}
          />
        </div>
      </div>
    </section>
  );
}

function ModeCard({
  icon: Icon, title, badge, color, bullets,
}: {
  icon: any; title: string; badge: string; color: "emerald" | "amber"; bullets: string[];
}) {
  const c =
    color === "emerald"
      ? "border-emerald-400/30 bg-emerald-400/[0.04] text-emerald-300"
      : "border-amber-400/30 bg-amber-400/[0.04] text-amber-300";
  return (
    <div className={`overflow-hidden rounded-xl border ${c.split(" ")[0]} ${c.split(" ")[1]} p-6`}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Icon className={`h-5 w-5 ${c.split(" ")[2]}`} />
          <div className="text-lg font-medium text-zinc-100">{title}</div>
        </div>
        <span className={`rounded-full border ${c.split(" ")[0]} px-2 py-0.5 font-mono text-[10px] ${c.split(" ")[2]}`}>
          {badge}
        </span>
      </div>
      <ul className="mt-5 space-y-2.5 text-sm text-zinc-300">
        {bullets.map((b) => (
          <li key={b} className="flex gap-2">
            <span className={"mt-1.5 h-1 w-1 rounded-full " + (color === "emerald" ? "bg-emerald-400" : "bg-amber-400")} />
            <span>{b}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────── */

function ArchitectureSection() {
  return (
    <section className="mx-auto max-w-7xl px-6 py-24">
      <SectionHeader
        eyebrow="Deployment"
        title="Production topology"
        sub="Multi-replica EKS deployment with Redis-backed job queue and cross-replica WorkerLoop. Janitor recovers stranded jobs via heartbeat TTL."
      />

      <div className="mt-12 overflow-hidden rounded-xl border border-zinc-800 bg-zinc-900/30">
        <div className="grid grid-cols-1 gap-px bg-zinc-900 lg:grid-cols-[1.2fr,1.2fr,1fr]">
          {/* CI/CD */}
          <Panel title="CI/CD callers" icon={GitBranch}>
            <div className="space-y-2 font-mono text-xs">
              {["github-actions", "gitlab-ci", "jenkins"].map((x) => (
                <div key={x} className="rounded-md border border-zinc-800 bg-zinc-950 px-3 py-1.5 text-zinc-400">
                  {x}
                </div>
              ))}
              <div className="pt-3 text-[10px] uppercase tracking-wider text-zinc-600">
                X-API-Key · 16MB body cap
              </div>
            </div>
          </Panel>

          {/* EKS cluster */}
          <Panel title="EKS cluster (ap-northeast-2)" icon={Server} accent>
            <div className="space-y-3 font-mono text-xs">
              <Pod label="ai-risk-platform · replica 0" />
              <Pod label="ai-risk-platform · replica 1" />
              <div className="flex items-center justify-center gap-2 py-1 text-zinc-600">
                <Network className="h-3 w-3" /> HPA · rolling · maxUnavailable=0
              </div>
              <Pod label="redis (StatefulSet)" tone="rose" />
            </div>
          </Panel>

          {/* Outputs */}
          <Panel title="Outputs" icon={FileCheck}>
            <div className="space-y-3">
              {[
                { l: "GateDecision", v: "PASS / BLOCK", icon: Shield },
                { l: "SAR", v: "auditor evidence", icon: FileText },
                { l: "POA&M", v: "remediation plan", icon: ScrollText },
                { l: "Authorization", v: "ATO / DATO", icon: CheckCircle2 },
              ].map((o) => {
                const I = o.icon;
                return (
                  <div key={o.l} className="flex items-center gap-3 rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2">
                    <I className="h-4 w-4 text-emerald-400" />
                    <div>
                      <div className="font-mono text-xs text-zinc-300">{o.l}</div>
                      <div className="text-[11px] text-zinc-500">{o.v}</div>
                    </div>
                  </div>
                );
              })}
            </div>
          </Panel>
        </div>
      </div>

      <div className="mt-5 grid gap-3 text-xs text-zinc-500 md:grid-cols-3">
        <SecurityFact label="Pod security" v="runAsNonRoot · readOnlyRootFS · drop ALL · seccomp RuntimeDefault" />
        <SecurityFact label="Image" v="ECR · multi-stage Docker · 0.1.0" />
        <SecurityFact label="Persistence" v="AssessmentRecord + JSONL audit trail" />
      </div>
    </section>
  );
}

function Panel({ title, icon: Icon, accent, children }: any) {
  return (
    <div className={"bg-zinc-950 p-6 " + (accent ? "ring-1 ring-inset ring-emerald-400/10" : "")}>
      <div className="mb-4 flex items-center gap-2">
        <Icon className={"h-4 w-4 " + (accent ? "text-emerald-400" : "text-zinc-500")} />
        <div className="text-sm font-medium text-zinc-200">{title}</div>
      </div>
      {children}
    </div>
  );
}

function Pod({ label, tone = "emerald" }: { label: string; tone?: "emerald" | "rose" }) {
  const c = tone === "emerald" ? "border-emerald-400/30 text-emerald-300" : "border-rose-400/30 text-rose-300";
  return (
    <div className={`flex items-center gap-2 rounded-md border ${c} bg-zinc-950 px-3 py-2`}>
      <span className={`h-1.5 w-1.5 rounded-full ${tone === "emerald" ? "bg-emerald-400" : "bg-rose-400"} animate-pulse`} />
      <span className="font-mono text-xs">{label}</span>
    </div>
  );
}

function SecurityFact({ label, v }: { label: string; v: string }) {
  return (
    <div className="rounded-md border border-zinc-900 bg-zinc-950/50 p-3">
      <div className="text-[10px] uppercase tracking-wider text-zinc-600">{label}</div>
      <div className="mt-1 font-mono text-zinc-400">{v}</div>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────── */

function TechStack() {
  const groups = [
    {
      title: "Runtime",
      items: ["Python 3.11", "FastAPI", "Uvicorn", "ThreadPoolExecutor"],
    },
    {
      title: "AI",
      items: ["AWS Bedrock", "Claude Sonnet 4.6", "Claude Haiku 4.5", "prompt cache"],
    },
    {
      title: "Gate",
      items: ["OPA / Rego", "YAML thresholds", "OSCAL controls"],
    },
    {
      title: "Infra",
      items: ["Kubernetes (EKS)", "ECR", "Redis", "HPA", "ConfigMap"],
    },
    {
      title: "Quality",
      items: ["pytest", "mypy strict", "contract tests", "JSONL audit trail"],
    },
    {
      title: "Standards",
      items: ["NIST SP 800-30", "SP 800-37 RMF", "FIPS 199", "MITRE ATT&CK"],
    },
  ];
  return (
    <section id="stack" className="mx-auto max-w-7xl px-6 py-24">
      <SectionHeader eyebrow="Stack" title="Built with" />
      <div className="mt-12 grid gap-3 md:grid-cols-3">
        {groups.map((g) => (
          <div key={g.title} className="rounded-xl border border-zinc-800 bg-zinc-900/30 p-5">
            <div className="text-[11px] uppercase tracking-wider text-zinc-500">
              {g.title}
            </div>
            <div className="mt-3 flex flex-wrap gap-1.5">
              {g.items.map((i) => (
                <span
                  key={i}
                  className="rounded-md border border-zinc-800 bg-zinc-950 px-2 py-1 font-mono text-xs text-zinc-300"
                >
                  {i}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

/* ────────────────────────────────────────────────────────────────────── */

function Footer() {
  return (
    <footer className="border-t border-zinc-900">
      <div className="mx-auto flex max-w-7xl flex-col gap-6 px-6 py-12 md:flex-row md:items-center md:justify-between">
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-md bg-emerald-400/10 ring-1 ring-emerald-400/30">
            <Shield className="h-4 w-4 text-emerald-400" />
          </div>
          <div>
            <div className="font-mono text-sm text-zinc-200">ai-risk-platform</div>
            <div className="text-xs text-zinc-500">
              Compliance-driven DevSecOps risk engine
            </div>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm text-zinc-500">
          <a href="#" className="hover:text-zinc-200">GitHub</a>
          <a href="#" className="hover:text-zinc-200">Docs</a>
          <a href="#" className="hover:text-zinc-200">API reference</a>
          <span className="font-mono text-xs text-zinc-700">© 2026</span>
        </div>
      </div>
    </footer>
  );
}

/* ────────────────────────────────────────────────────────────────────── */

function SectionHeader({
  eyebrow, title, sub,
}: {
  eyebrow: string;
  title: React.ReactNode;
  sub?: string;
}) {
  return (
    <div className="max-w-2xl">
      <div className="font-mono text-xs uppercase tracking-[0.18em] text-emerald-400">
        {eyebrow}
      </div>
      <h2 className="mt-3 text-3xl font-semibold tracking-tight text-zinc-50 sm:text-4xl">
        {title}
      </h2>
      {sub && <p className="mt-4 text-base leading-relaxed text-zinc-400">{sub}</p>}
    </div>
  );
}
