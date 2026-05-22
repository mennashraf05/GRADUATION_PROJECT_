import React from "react";
import { useNavigate } from "react-router-dom";
import {
  ArrowRight,
  BarChart3,
  BookOpen,
  CheckCircle2,
  ClipboardList,
  Eye,
  FileLock2,
  KeyRound,
  Layers3,
  MailWarning,
  Network,
  Radar,
  Shield,
  ShieldCheck,
  Users,
} from "lucide-react";
import { Button } from "../ui/button";
import { useLanguage } from "../../contexts/LanguageContext";

type Badge = "Active" | "Protected" | "Review" | "Reports";

type CardItem = {
  title: string;
  description: string;
  icon: React.ComponentType<{ className?: string }>;
};

type ModuleItem = CardItem & {
  badge: Badge;
};

const mission: CardItem[] = [
  {
    title: "Detect",
    description: "Surface risky passwords, suspicious links, exposure signals, and network alerts.",
    icon: Radar,
  },
  {
    title: "Understand",
    description: "Turn security signals into clear context, priorities, and safer next steps.",
    icon: BarChart3,
  },
  {
    title: "Respond",
    description: "Guide users and review teams toward practical action without exposing sensitive evidence.",
    icon: ShieldCheck,
  },
];

const modules: ModuleItem[] = [
  {
    title: "Password Checker",
    description: "Review password strength and everyday account risk.",
    badge: "Active",
    icon: KeyRound,
  },
  {
    title: "Identity Leak Monitor",
    description: "Summarize exposure signals with privacy-safe guidance.",
    badge: "Protected",
    icon: Eye,
  },
  {
    title: "PCAP Analyzer",
    description: "Analyze network alerts through safe metadata and severity context.",
    badge: "Review",
    icon: Network,
  },
  {
    title: "File Vault",
    description: "Support safer storage workflows for sensitive files.",
    badge: "Protected",
    icon: FileLock2,
  },
  {
    title: "Phishing Scanner",
    description: "Check suspicious URLs and strengthen phishing awareness.",
    badge: "Active",
    icon: MailWarning,
  },
  {
    title: "Reports Center",
    description: "Create high-level reports for security review.",
    badge: "Reports",
    icon: ClipboardList,
  },
  {
    title: "Security Review",
    description: "Help review teams prioritize what needs attention.",
    badge: "Review",
    icon: Users,
  },
  {
    title: "Risk Monitoring",
    description: "Keep security signals organized in one workspace.",
    badge: "Active",
    icon: Layers3,
  },
];

const privacyChecks = [
  "No raw passwords in reports",
  "No password hashes in exports",
  "No packet payloads in summaries",
  "No leaked identity values in admin views",
];

const workflow = [
  ["01", "Collect safe signals", "Gather security-relevant summaries from connected tools."],
  ["02", "Analyze risk", "Prioritize findings by category, severity, and context."],
  ["03", "Generate alerts and reports", "Create clear outputs for users and security review."],
  ["04", "Guide safer actions", "Recommend practical next steps without exposing sensitive data."],
];

const values = [
  {
    title: "For Users",
    icon: ShieldCheck,
    points: ["Understand personal risk quickly", "Build safer everyday habits"],
  },
  {
    title: "For Security Awareness",
    icon: BookOpen,
    points: ["Turn complex signals into teachable moments", "Support practical cyber safety learning"],
  },
  {
    title: "For Review Teams",
    icon: ClipboardList,
    points: ["Prioritize alerts and reports", "Review safe summaries with less noise"],
  },
];

export function AboutPage() {
  const { isRtl } = useLanguage();
  const navigate = useNavigate();

  const navItems = [
    ["Home", "/"],
    ["Features", "/features"],
    ["Dashboard", "/dashboard"],
    ["Learn", "/learn"],
    ["Contact", "/contact"],
  ];

  return (
    <div className="about-page min-h-screen overflow-x-hidden bg-[#030A14] text-white" dir={isRtl ? "rtl" : "ltr"}>
      <AboutPageStyles />
      <AboutBackdrop />

      <nav className="sticky top-0 z-50 border-b border-white/10 bg-[#07111F]/88 backdrop-blur-xl">
        <div className="about-container about-navbar py-3">
          <button onClick={() => navigate("/")} className="about-brand rounded-xl focus:outline-none focus:ring-2 focus:ring-cyan-300/70" aria-label="Go to Sentinel AI home">
            <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 shadow-lg shadow-cyan-500/20">
              <Shield className="h-6 w-6" />
            </span>
            <span className="bg-gradient-to-r from-cyan-300 to-blue-300 bg-clip-text text-xl font-semibold text-transparent">
              Sentinel AI
            </span>
          </button>

          <div className="about-nav-links">
            {navItems.map(([label, route]) => (
              <Button key={route} variant="ghost" onClick={() => navigate(route)} className="about-nav-button">
                {label}
              </Button>
            ))}
          </div>

          <div className="about-auth-actions">
            <Button variant="ghost" onClick={() => navigate("/login")} className="text-slate-200 hover:bg-white/5">
              Login
            </Button>
            <Button onClick={() => navigate("/signup")} className="bg-gradient-to-r from-cyan-600 to-blue-600 text-white shadow-lg shadow-cyan-950/25">
              Sign Up
            </Button>
          </div>
        </div>
      </nav>

      <main className="relative z-10">
        <section className="about-hero about-container">
          <div className="about-reveal">
            <div className="about-badge">
              <ShieldCheck className="h-4 w-4" />
              About Sentinel AI
            </div>
            <h1 className="mt-5 max-w-3xl text-4xl font-semibold leading-tight tracking-normal sm:text-5xl lg:text-[3.35rem]">
              Protecting Your Digital World
            </h1>
            <p className="mt-4 max-w-2xl text-lg leading-8 text-slate-300">
              Sentinel AI brings password security, identity monitoring, network analysis, and privacy-safe reporting into one intelligent cybersecurity platform.
            </p>
            <div className="mt-6 flex flex-col gap-3 sm:flex-row">
              <Button onClick={() => navigate("/features")} className="about-primary-button h-11 px-5 text-white">
                Explore Features
                <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
              <Button variant="outline" onClick={() => navigate("/dashboard")} className="h-11 border-white/15 bg-white/5 px-5 text-white hover:bg-white/10">
                Open Dashboard
              </Button>
            </div>
          </div>

          <SecurityConsole />
        </section>

        <section className="about-container about-section">
          <div className="about-mission-grid">
            {mission.map((item, index) => (
              <MissionCard key={item.title} item={item} index={index} />
            ))}
          </div>
        </section>

        <section className="about-container about-section">
          <SectionHeading eyebrow="Platform modules" title="One intelligent security workspace" />
          <div className="about-module-grid mt-6">
            {modules.map((item, index) => (
              <ModuleCard key={item.title} item={item} index={index} />
            ))}
          </div>
        </section>

        <section className="about-container about-section">
          <div className="about-privacy-card">
            <div>
              <span className="about-shield-mark">
                <ShieldCheck className="h-7 w-7 text-cyan-100" />
              </span>
              <h2 className="mt-5 text-3xl font-semibold">Privacy-first security reporting</h2>
              <p className="mt-3 max-w-xl text-sm leading-6 text-slate-300">
                Sentinel AI focuses on safe summaries, labels, timestamps, counts, and recommendations instead of exposing sensitive evidence.
              </p>
            </div>
            <div className="about-privacy-grid">
              {privacyChecks.map((point) => (
                <div key={point} className="about-check-item">
                  <CheckCircle2 className="h-5 w-5 shrink-0 text-emerald-200" />
                  <span>{point}</span>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="about-container about-section">
          <SectionHeading eyebrow="How it works" title="From safe signal to safer action" />
          <div className="about-step-grid mt-6">
            {workflow.map(([number, title, description], index) => (
              <StepCard key={number} number={number} title={title} description={description} index={index} />
            ))}
          </div>
        </section>

        <section className="about-container about-section">
          <SectionHeading eyebrow="Why it matters" title="Built for practical cyber safety" />
          <div className="about-value-grid mt-6">
            {values.map((item, index) => (
              <ValueCard key={item.title} item={item} index={index} />
            ))}
          </div>
        </section>

        <section className="about-container py-12 sm:py-14">
          <div className="about-final-cta">
            <ShieldCheck className="mx-auto h-9 w-9 text-cyan-200" />
            <h2 className="mt-4 text-3xl font-semibold">Ready to explore Sentinel AI?</h2>
            <p className="mx-auto mt-2 max-w-xl text-sm leading-6 text-slate-300">
              Start with the dashboard or build practical cyber safety habits.
            </p>
            <div className="mt-6 flex flex-col justify-center gap-3 sm:flex-row">
              <Button onClick={() => navigate("/dashboard")} className="about-primary-button px-5 text-white">
                Go to Dashboard
              </Button>
              <Button variant="outline" onClick={() => navigate("/learn")} className="border-white/15 bg-white/5 px-5 text-white hover:bg-white/10">
                Learn Cyber Safety
              </Button>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}

function AboutBackdrop() {
  return (
    <div className="about-backdrop" aria-hidden="true">
      <div className="about-circuit-grid" />
      <div className="about-glow about-glow-a" />
      <div className="about-glow about-glow-b" />
      <div className="about-light-line about-light-line-a" />
      <div className="about-light-line about-light-line-b" />
    </div>
  );
}

function SecurityConsole() {
  const rows = [
    ["Password Risk", "Safe", KeyRound],
    ["Identity Exposure", "Ready", Eye],
    ["Network Alerts", "Review", Network],
    ["Safe Reports", "Ready", ClipboardList],
  ];

  return (
    <div className="about-console about-reveal-delayed">
      <div className="about-console-inner">
        <div className="flex items-center justify-between gap-4">
          <div>
            <p className="text-sm text-cyan-200">Unified Risk Console</p>
            <h2 className="mt-1 text-2xl font-semibold">Security overview</h2>
          </div>
          <span className="about-shield-orbit">
            <Shield className="h-7 w-7 text-cyan-100" />
          </span>
        </div>

        <div className="mt-5 grid grid-cols-3 gap-3">
          {[
            ["Signals", "Clean"],
            ["Reports", "Safe"],
            ["Actions", "Guided"],
          ].map(([label, value]) => (
            <div key={label} className="about-mini-stat">
              <span className="text-xs text-slate-400">{label}</span>
              <span className="mt-1 text-sm font-semibold">{value}</span>
            </div>
          ))}
        </div>

        <div className="mt-5 space-y-3">
          {rows.map(([label, state, Icon], index) => {
            const RowIcon = Icon as React.ComponentType<{ className?: string }>;
            return (
              <div key={String(label)} className="about-signal-row" style={{ animationDelay: `${index * 160}ms` }}>
                <span className="about-row-icon">
                  <RowIcon className="h-4 w-4" />
                </span>
                <span className="text-sm text-slate-200">{label}</span>
                <span className="ml-auto rounded-full border border-white/10 bg-white/[0.04] px-2.5 py-1 text-xs text-slate-300">
                  {state}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function SectionHeading({ eyebrow, title }: { eyebrow: string; title: string }) {
  return (
    <div>
      <p className="text-sm font-medium text-cyan-300">{eyebrow}</p>
      <h2 className="mt-1 text-3xl font-semibold">{title}</h2>
    </div>
  );
}

function MissionCard({ item, index }: { item: CardItem; index: number }) {
  const Icon = item.icon;

  return (
    <article className="about-card" style={{ animationDelay: `${index * 90}ms` }}>
      <span className="about-card-icon">
        <Icon className="h-6 w-6" />
      </span>
      <h3 className="mt-4 text-xl font-semibold">{item.title}</h3>
      <p className="mt-2 text-sm leading-6 text-slate-400">{item.description}</p>
    </article>
  );
}

function ModuleCard({ item, index }: { item: ModuleItem; index: number }) {
  const Icon = item.icon;

  return (
    <article className="about-module-card" style={{ animationDelay: `${index * 60}ms` }}>
      <div className="flex items-start justify-between gap-3">
        <span className="about-module-icon">
          <Icon className="h-5 w-5" />
        </span>
        <StatusBadge label={item.badge} />
      </div>
      <h3 className="mt-4 text-base font-semibold">{item.title}</h3>
      <p className="mt-2 text-sm leading-5 text-slate-400">{item.description}</p>
    </article>
  );
}

function StatusBadge({ label }: { label: Badge }) {
  const className =
    label === "Protected"
      ? "border-emerald-300/20 bg-emerald-400/10 text-emerald-100"
      : label === "Review"
        ? "border-amber-300/20 bg-amber-400/10 text-amber-100"
        : label === "Reports"
          ? "border-purple-300/20 bg-purple-400/10 text-purple-100"
          : "border-cyan-300/20 bg-cyan-400/10 text-cyan-100";

  return <span className={`rounded-full border px-2.5 py-1 text-xs ${className}`}>{label}</span>;
}

function StepCard({ number, title, description, index }: { number: string; title: string; description: string; index: number }) {
  return (
    <article className="about-step-card" style={{ animationDelay: `${index * 80}ms` }}>
      <span className="about-step-number">{number}</span>
      <h3 className="mt-4 text-lg font-semibold">{title}</h3>
      <p className="mt-2 text-sm leading-6 text-slate-400">{description}</p>
    </article>
  );
}

function ValueCard({
  item,
  index,
}: {
  item: {
    title: string;
    icon: React.ComponentType<{ className?: string }>;
    points: string[];
  };
  index: number;
}) {
  const Icon = item.icon;

  return (
    <article className="about-value-card" style={{ animationDelay: `${index * 90}ms` }}>
      <span className="about-value-icon">
        <Icon className="h-5 w-5" />
      </span>
      <h3 className="mt-4 text-xl font-semibold">{item.title}</h3>
      <div className="mt-4 space-y-3">
        {item.points.map((point) => (
          <div key={point} className="flex gap-3 text-sm text-slate-300">
            <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-cyan-300" />
            <span>{point}</span>
          </div>
        ))}
      </div>
    </article>
  );
}

function AboutPageStyles() {
  return (
    <style>{`
      .about-page {
        --about-cyan: 34, 211, 238;
        --about-blue: 59, 130, 246;
        --about-purple: 168, 85, 247;
        position: relative;
      }

      .about-container {
        width: min(100% - 2rem, 1160px);
        margin-inline: auto;
      }

      .about-navbar {
        display: grid;
        grid-template-columns: auto minmax(0, 1fr) auto;
        align-items: center;
        gap: 1rem;
      }

      .about-brand,
      .about-auth-actions {
        display: flex;
        align-items: center;
        gap: 0.75rem;
        min-width: 0;
      }

      .about-auth-actions {
        justify-content: flex-end;
        gap: 0.5rem;
      }

      .about-nav-links {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 0.1rem;
        overflow-x: auto;
        scrollbar-width: none;
        min-width: 0;
      }

      .about-nav-links::-webkit-scrollbar {
        display: none;
      }

      .about-nav-button {
        color: rgb(203, 213, 225);
        white-space: nowrap;
        padding-inline: 0.75rem;
      }

      .about-nav-button:hover {
        background: rgba(255, 255, 255, 0.05);
        color: white;
      }

      .about-section {
        padding-block: 1.7rem;
      }

      .about-hero {
        min-height: 0;
        display: grid;
        grid-template-columns: minmax(0, 1fr) minmax(280px, 30rem);
        align-items: center;
        gap: 1.6rem;
        padding-block: 2rem 1.2rem;
      }

      .about-backdrop {
        position: fixed;
        inset: 0;
        pointer-events: none;
        z-index: 0;
        overflow: hidden;
        background:
          linear-gradient(rgba(34, 211, 238, 0.045) 1px, transparent 1px),
          linear-gradient(90deg, rgba(34, 211, 238, 0.035) 1px, transparent 1px),
          #030a14;
        background-size: 56px 56px;
        mask-image: linear-gradient(to bottom, black, black 78%, transparent);
      }

      .about-circuit-grid {
        position: absolute;
        inset: 0;
        background:
          linear-gradient(90deg, transparent 0 16%, rgba(34, 211, 238, 0.08) 16% 16.2%, transparent 16.2% 100%),
          linear-gradient(0deg, transparent 0 28%, rgba(59, 130, 246, 0.06) 28% 28.2%, transparent 28.2% 100%);
        background-size: 220px 180px;
        opacity: 0.45;
        animation: about-grid-drift 18s linear infinite;
      }

      .about-glow {
        position: absolute;
        width: 44rem;
        height: 24rem;
        filter: blur(72px);
        opacity: 0.22;
        transform: rotate(-12deg);
      }

      .about-glow-a {
        top: 2rem;
        right: -12rem;
        background: rgba(var(--about-cyan), 0.72);
        animation: about-float 12s ease-in-out infinite;
      }

      .about-glow-b {
        top: 28rem;
        left: -14rem;
        background: rgba(var(--about-purple), 0.5);
        animation: about-float 14s ease-in-out infinite reverse;
      }

      .about-light-line {
        position: absolute;
        height: 1px;
        width: 32rem;
        background: linear-gradient(90deg, transparent, rgba(34, 211, 238, 0.4), transparent);
        opacity: 0.35;
      }

      .about-light-line-a {
        top: 11rem;
        right: 5%;
        animation: about-line-slide 9s ease-in-out infinite;
      }

      .about-light-line-b {
        top: 48rem;
        left: 8%;
        animation: about-line-slide 11s ease-in-out infinite reverse;
      }

      .about-reveal,
      .about-reveal-delayed,
      .about-card,
      .about-module-card,
      .about-step-card,
      .about-value-card {
        opacity: 0;
        animation: about-rise 680ms cubic-bezier(0.2, 0.8, 0.2, 1) forwards;
      }

      .about-reveal-delayed {
        animation-delay: 140ms;
      }

      .about-badge {
        width: fit-content;
        display: inline-flex;
        align-items: center;
        gap: 0.5rem;
        border: 1px solid rgba(34, 211, 238, 0.25);
        background: rgba(34, 211, 238, 0.1);
        color: #cffafe;
        border-radius: 999px;
        padding: 0.35rem 0.85rem;
        font-size: 0.875rem;
      }

      .about-primary-button {
        background: linear-gradient(135deg, #0891b2, #2563eb);
        box-shadow: 0 12px 34px rgba(8, 145, 178, 0.26);
        position: relative;
        overflow: hidden;
      }

      .about-primary-button::after {
        content: "";
        position: absolute;
        inset: 0;
        transform: translateX(-110%);
        background: linear-gradient(90deg, transparent, rgba(255,255,255,0.22), transparent);
        transition: transform 700ms ease;
      }

      .about-primary-button:hover::after {
        transform: translateX(110%);
      }

      .about-console,
      .about-privacy-card,
      .about-final-cta {
        border: 1px solid rgba(255, 255, 255, 0.1);
        background: linear-gradient(135deg, rgba(15, 23, 42, 0.78), rgba(8, 19, 35, 0.86));
        box-shadow: 0 24px 70px rgba(2, 6, 23, 0.35);
        backdrop-filter: blur(18px);
      }

      .about-console {
        border-radius: 26px;
        padding: 1px;
        max-width: 30rem;
        justify-self: end;
        background:
          linear-gradient(135deg, rgba(34, 211, 238, 0.38), rgba(168, 85, 247, 0.2), rgba(255,255,255,0.08));
        animation: about-rise 520ms cubic-bezier(0.2, 0.8, 0.2, 1) 140ms forwards, about-console-float 6s ease-in-out 900ms infinite;
      }

      .about-console-inner {
        border-radius: 25px;
        background: rgba(7, 17, 31, 0.92);
        padding: 1rem;
      }

      .about-shield-orbit,
      .about-shield-mark {
        border-radius: 999px;
        display: flex;
        align-items: center;
        justify-content: center;
        border: 1px solid rgba(34, 211, 238, 0.28);
        background: radial-gradient(circle, rgba(34, 211, 238, 0.22), rgba(37, 99, 235, 0.06));
        box-shadow: 0 0 42px rgba(34, 211, 238, 0.22);
        animation: about-soft-pulse 2.8s ease-in-out infinite;
      }

      .about-shield-orbit {
        width: 4rem;
        height: 4rem;
      }

      .about-shield-mark {
        width: 4.5rem;
        height: 4.5rem;
      }

      .about-mini-stat,
      .about-signal-row,
      .about-card,
      .about-module-card,
      .about-step-card,
      .about-value-card,
      .about-check-item {
        border: 1px solid rgba(255, 255, 255, 0.1);
        background: rgba(255, 255, 255, 0.045);
      }

      .about-mini-stat {
        border-radius: 16px;
        padding: 0.8rem;
        display: flex;
        flex-direction: column;
      }

      .about-signal-row {
        border-radius: 16px;
        padding: 0.85rem;
        display: flex;
        align-items: center;
        gap: 0.75rem;
        animation: about-signal-glow 3s ease-in-out infinite;
      }

      .about-row-icon {
        width: 2rem;
        height: 2rem;
        border-radius: 0.75rem;
        display: grid;
        place-items: center;
        color: #a5f3fc;
        background: rgba(34, 211, 238, 0.1);
        border: 1px solid rgba(34, 211, 238, 0.18);
      }

      .about-mission-grid,
      .about-value-grid {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: 1.25rem;
      }

      .about-module-grid {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: 1.25rem;
      }

      .about-step-grid {
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: 1rem;
      }

      .about-card,
      .about-module-card,
      .about-step-card,
      .about-value-card {
        position: relative;
        border-radius: 24px;
        padding: 1.15rem;
        background: linear-gradient(180deg, rgba(11, 22, 39, 0.94), rgba(7, 17, 31, 0.96));
        overflow: hidden;
        box-shadow: 0 18px 45px rgba(2, 6, 23, 0.18);
        transition: transform 220ms ease, border-color 220ms ease, box-shadow 220ms ease;
      }

      .about-card {
        min-height: 190px;
      }

      .about-module-card {
        min-height: 178px;
      }

      .about-step-card {
        min-height: 190px;
      }

      .about-card::before,
      .about-module-card::before,
      .about-step-card::before,
      .about-value-card::before {
        content: "";
        position: absolute;
        inset: 0;
        border-radius: inherit;
        padding: 1px;
        background: linear-gradient(135deg, rgba(34,211,238,0.34), rgba(168,85,247,0.18), transparent 55%);
        -webkit-mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
        -webkit-mask-composite: xor;
        mask-composite: exclude;
        opacity: 0;
        transition: opacity 220ms ease;
        pointer-events: none;
      }

      .about-card:hover,
      .about-module-card:hover,
      .about-step-card:hover,
      .about-value-card:hover {
        transform: translateY(-5px);
        border-color: rgba(34, 211, 238, 0.38);
        box-shadow: 0 22px 60px rgba(8, 145, 178, 0.13);
      }

      .about-card:hover::before,
      .about-module-card:hover::before,
      .about-step-card:hover::before,
      .about-value-card:hover::before {
        opacity: 1;
      }

      .about-card-icon,
      .about-module-icon,
      .about-value-icon {
        display: flex;
        align-items: center;
        justify-content: center;
        border: 1px solid rgba(34, 211, 238, 0.2);
        background: rgba(34, 211, 238, 0.1);
        color: #a5f3fc;
      }

      .about-card-icon {
        width: 3rem;
        height: 3rem;
        border-radius: 1rem;
      }

      .about-module-icon,
      .about-value-icon {
        width: 2.65rem;
        height: 2.65rem;
        border-radius: 0.95rem;
      }

      .about-privacy-card {
        border-radius: 28px;
        display: grid;
        grid-template-columns: minmax(0, 0.8fr) minmax(0, 1.2fr);
        align-items: center;
        gap: 1.5rem;
        padding: 1.5rem;
        background:
          radial-gradient(circle at 12% 16%, rgba(34,211,238,0.18), transparent 28%),
          linear-gradient(135deg, rgba(34,211,238,0.12), rgba(37,99,235,0.11), rgba(168,85,247,0.08)),
          rgba(7,17,31,0.82);
      }

      .about-privacy-grid {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 0.9rem;
      }

      .about-check-item {
        border-radius: 16px;
        padding: 1rem;
        display: flex;
        align-items: center;
        gap: 0.75rem;
        color: #ecfeff;
        font-size: 0.9rem;
      }

      .about-step-number {
        display: inline-flex;
        height: 2.25rem;
        width: 2.25rem;
        align-items: center;
        justify-content: center;
        border-radius: 999px;
        border: 1px solid rgba(34,211,238,0.26);
        background: rgba(34,211,238,0.1);
        color: #cffafe;
        font-size: 0.85rem;
        font-weight: 700;
      }

      .about-final-cta {
        border-radius: 26px;
        padding: 1.75rem;
        text-align: center;
        background:
          linear-gradient(135deg, rgba(34,211,238,0.15), rgba(37,99,235,0.13)),
          rgba(7,17,31,0.82);
      }

      @keyframes about-rise {
        from { opacity: 0; transform: translateY(18px); }
        to { opacity: 1; transform: translateY(0); }
      }

      @keyframes about-console-float {
        0%, 100% { transform: translateY(0); }
        50% { transform: translateY(-8px); }
      }

      @keyframes about-float {
        0%, 100% { transform: translate3d(0, 0, 0) rotate(-12deg); }
        50% { transform: translate3d(18px, -20px, 0) rotate(-8deg); }
      }

      @keyframes about-grid-drift {
        from { background-position: 0 0; }
        to { background-position: 220px 180px; }
      }

      @keyframes about-line-slide {
        0%, 100% { transform: translateX(-20px); opacity: 0.14; }
        50% { transform: translateX(28px); opacity: 0.38; }
      }

      @keyframes about-soft-pulse {
        0%, 100% { transform: scale(1); box-shadow: 0 0 34px rgba(34,211,238,0.16); }
        50% { transform: scale(1.025); box-shadow: 0 0 54px rgba(34,211,238,0.27); }
      }

      @keyframes about-signal-glow {
        0%, 100% { border-color: rgba(255,255,255,0.1); }
        50% { border-color: rgba(34,211,238,0.24); }
      }

      @media (max-width: 1024px) {
        .about-navbar {
          grid-template-columns: 1fr auto;
        }

        .about-nav-links {
          grid-column: 1 / -1;
          width: 100%;
          padding-top: 0.25rem;
          justify-content: flex-start;
        }

        .about-hero {
          grid-template-columns: 1fr;
          padding-block: 1.5rem 0.75rem;
        }

        .about-console {
          justify-self: stretch;
          max-width: none;
        }

        .about-module-grid,
        .about-step-grid {
          grid-template-columns: repeat(2, minmax(0, 1fr));
        }

        .about-privacy-card {
          grid-template-columns: 1fr;
        }
      }

      @media (max-width: 720px) {
        .about-mission-grid,
        .about-module-grid,
        .about-step-grid,
        .about-value-grid,
        .about-privacy-grid {
          grid-template-columns: 1fr;
        }
      }

      @media (max-width: 640px) {
        .about-container {
          width: min(100% - 1rem, 1160px);
        }

        .about-section {
          padding-block: 1.25rem;
        }

        .about-hero {
          padding-block: 1.25rem 0.5rem;
        }

        .about-auth-actions {
          gap: 0.25rem;
        }
      }

      @media (prefers-reduced-motion: reduce) {
        .about-page *,
        .about-page *::before,
        .about-page *::after {
          animation-duration: 1ms !important;
          animation-iteration-count: 1 !important;
          transition-duration: 1ms !important;
          scroll-behavior: auto !important;
        }
      }
    `}</style>
  );
}
