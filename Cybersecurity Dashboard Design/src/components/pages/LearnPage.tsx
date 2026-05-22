import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ArrowRight,
  BookOpen,
  CheckCircle2,
  Clock,
  Eye,
  FileLock2,
  HelpCircle,
  KeyRound,
  Laptop,
  Lock,
  MailWarning,
  PlayCircle,
  Search,
  Shield,
  ShieldCheck,
  Sparkles,
  Target,
  Video,
  X,
} from 'lucide-react';
import { Button } from '../ui/button';
import { useLanguage } from '../../contexts/LanguageContext';

type Category = 'All' | 'Phishing' | 'Passwords' | 'Network Security' | 'Identity' | 'Encryption';
type Difficulty = 'Beginner' | 'Intermediate';

type LearningCard = {
  id: string;
  title: string;
  description: string;
  category: Exclude<Category, 'All'>;
  duration: string;
  difficulty: Difficulty;
  icon: React.ComponentType<{ className?: string }>;
  videoUrl: string;
  objectives: string[];
};

type GuideArticle = {
  intro: string;
  checklist: string[];
  sections: { heading: string; body: string }[];
};

type ToolCard = {
  title: string;
  description: string;
  route?: string;
  icon: React.ComponentType<{ className?: string }>;
};

const categories: Category[] = ['All', 'Phishing', 'Passwords', 'Network Security', 'Identity', 'Encryption'];

const tutorialVideos = {
  phishing: new URL('../../assets/learning-videos/phishing.mp4', import.meta.url).href,
  password: new URL('../../assets/learning-videos/password.mp4', import.meta.url).href,
  pcap: new URL('../../assets/learning-videos/pcap.mp4', import.meta.url).href,
  identity: new URL('../../assets/learning-videos/identity.mp4', import.meta.url).href,
  file: new URL('../../assets/learning-videos/file.mp4', import.meta.url).href,
};

const learningCards: LearningCard[] = [
  {
    id: 'phishing-emails',
    title: 'How to Detect Phishing Emails',
    description: 'Learn the sender, wording, link, and attachment signals that make suspicious emails easier to catch.',
    category: 'Phishing',
    duration: '6 min',
    difficulty: 'Beginner',
    icon: MailWarning,
    videoUrl: tutorialVideos.phishing,
    objectives: ['Inspect sender identity safely', 'Check links before clicking', 'Recognize urgency and attachment traps'],
  },
  {
    id: 'password-hygiene',
    title: 'Why Password Hygiene Matters',
    description: 'Understand why unique passwords, password managers, and MFA reduce everyday account takeover risk.',
    category: 'Passwords',
    duration: '5 min',
    difficulty: 'Beginner',
    icon: KeyRound,
    videoUrl: tutorialVideos.password,
    objectives: ['Avoid password reuse', 'Prioritize accounts for MFA', 'Use managers and recovery codes safely'],
  },
  {
    id: 'pcap-alerts',
    title: 'Understanding PCAP Alerts Safely',
    description: 'Review network alert concepts with privacy-safe metadata, severity, and source context.',
    category: 'Network Security',
    duration: '7 min',
    difficulty: 'Intermediate',
    icon: Laptop,
    videoUrl: tutorialVideos.pcap,
    objectives: ['Read alert severity with context', 'Prefer metadata before payloads', 'Handle packet evidence carefully'],
  },
  {
    id: 'identity-leak',
    title: 'Identity Leak Explained Simply',
    description: 'Make sense of exposure findings and learn calm, practical response steps that do not share sensitive data.',
    category: 'Identity',
    duration: '6 min',
    difficulty: 'Beginner',
    icon: Eye,
    videoUrl: tutorialVideos.identity,
    objectives: ['Understand exposure signals', 'Secure primary accounts first', 'Respond through trusted sources'],
  },
  {
    id: 'encryption-basics',
    title: 'Encryption Basics for Everyday Users',
    description: 'See how encryption protects files and messages, and what to do so recovery stays possible.',
    category: 'Encryption',
    duration: '5 min',
    difficulty: 'Beginner',
    icon: Lock,
    videoUrl: tutorialVideos.file,
    objectives: ['Know what encryption protects', 'Keep keys and recovery options private', 'Use protected storage for sensitive files'],
  },
];

const guideArticles: Record<string, GuideArticle> = {
  'phishing-emails': {
    intro: 'Phishing succeeds by making a risky action feel normal, urgent, or routine. A short pause before clicking is the habit that changes the outcome.',
    sections: [
      { heading: 'Inspect the sender', body: 'Read the full address and compare it with a known trusted source. Display names can be copied easily.' },
      { heading: 'Check links safely', body: 'Hover or long-press to inspect the destination. Open important services manually instead of using message links.' },
      { heading: 'Treat pressure as a signal', body: 'Payment threats, locked-account warnings, surprise prizes, and secrecy requests deserve extra verification.' },
    ],
    checklist: ['Verify the sender through another channel', 'Inspect the destination domain', 'Avoid unexpected attachments', 'Report suspicious messages'],
  },
  'password-hygiene': {
    intro: 'Good password hygiene limits blast radius. If one account is exposed, unique passwords keep the same secret from opening everything else.',
    sections: [
      { heading: 'Make every important password unique', body: 'Reuse turns one breach into many possible takeovers. Start with email, banking, cloud storage, and work accounts.' },
      { heading: 'Use a password manager', body: 'A manager can create long random passwords and reduce the temptation to reuse memorable ones.' },
      { heading: 'Add MFA where it matters most', body: 'Multi-factor authentication adds a second approval step when a password alone is not enough.' },
    ],
    checklist: ['Replace reused passwords', 'Enable MFA on email first', 'Store recovery codes safely', 'Review recovery email and phone settings'],
  },
  'pcap-alerts': {
    intro: 'PCAP alerts help explain network behavior, but they should be reviewed carefully because packet captures can include sensitive context.',
    sections: [
      { heading: 'Start with metadata', body: 'Look at protocol, direction, timestamps, source, destination, and severity before opening deeper evidence.' },
      { heading: 'Use severity as prioritization', body: 'A high severity label means review sooner. It is not proof by itself without supporting context.' },
      { heading: 'Protect raw packet content', body: 'Avoid sharing packet payloads or screenshots that could expose tokens, private messages, or file fragments.' },
    ],
    checklist: ['Confirm affected host and direction', 'Read severity with evidence', 'Prefer metadata first', 'Avoid exposing raw packet content'],
  },
  'identity-leak': {
    intro: 'An identity exposure finding is a prompt to verify and strengthen accounts, not a reason to panic or share more personal details.',
    sections: [
      { heading: 'Secure primary accounts', body: 'Your email account often controls password resets for other services, so protect it first.' },
      { heading: 'Use official pages', body: 'Go directly to the service website or app when changing passwords or reviewing account activity.' },
      { heading: 'Reduce future exposure', body: 'Share fewer public details and remove unnecessary personal data from profiles and old services.' },
    ],
    checklist: ['Update exposed or reused passwords', 'Enable MFA', 'Review account recovery settings', 'Avoid links in warning messages'],
  },
  'encryption-basics': {
    intro: 'Encryption turns readable data into protected data that needs the right key or password to open.',
    sections: [
      { heading: 'Protect files at rest', body: 'Encrypted storage helps keep documents private if a device, drive, backup, or account is accessed without permission.' },
      { heading: 'Protect data in transit', body: 'Modern encrypted connections reduce the chance that information can be read while moving across networks.' },
      { heading: 'Plan recovery', body: 'Keep recovery keys and backup access safe so protection does not become permanent lockout.' },
    ],
    checklist: ['Encrypt sensitive files', 'Use trusted apps', 'Keep recovery keys private', 'Back up important protected data'],
  },
};

const tips = ['Verify before you click', 'Use unique passwords with MFA', 'Protect sensitive files with encryption'];

const tools: ToolCard[] = [
  { title: 'Password Checker', description: 'Evaluate password strength and risk safely.', route: '/password-checker', icon: KeyRound },
  { title: 'Phishing Scanner', description: 'Check suspicious URLs for common warning signs.', route: '/phishing-scanner', icon: MailWarning },
  { title: 'File Vault', description: 'Practice safer storage for sensitive files.', route: '/file-vault', icon: FileLock2 },
  { title: 'Identity Leak Monitor', description: 'Review exposure concepts and safe findings.', route: '/identityleak-monitor', icon: Eye },
  { title: 'PCAP Analyzer', description: 'Explore network alert review and risk summaries.', route: '/pcap-analyzer', icon: Laptop },
];

const quizQuestions = [
  {
    question: 'What should you do before clicking a suspicious link?',
    options: ['Verify the sender and inspect the URL', 'Open it quickly before it expires', 'Forward it to friends'],
    answer: 0,
  },
  {
    question: 'Why should passwords not be reused?',
    options: ['One breach can expose multiple accounts', 'They become too long', 'It slows down browsing'],
    answer: 0,
  },
  {
    question: 'What should you review first when looking at PCAP alerts safely?',
    options: ['Privacy-safe metadata and severity context', 'Unneeded private payload content', 'Random screenshots'],
    answer: 0,
  },
];

const progressStorageKey = 'sentinel-learning-completed-v6';

function matchesSearch(card: LearningCard, query: string) {
  return `${card.title} ${card.description} ${card.category} ${card.difficulty} ${card.objectives.join(' ')}`.toLowerCase().includes(query);
}

export function LearnPage() {
  const { isRtl } = useLanguage();
  const navigate = useNavigate();
  const [activeCategory, setActiveCategory] = useState<Category>('All');
  const [searchTerm, setSearchTerm] = useState('');
  const [completedIds, setCompletedIds] = useState<Set<string>>(() => new Set());
  const [activeGuide, setActiveGuide] = useState<LearningCard | null>(null);
  const [activeTutorial, setActiveTutorial] = useState<LearningCard | null>(null);
  const [quizOpen, setQuizOpen] = useState(false);
  const [quizAnswers, setQuizAnswers] = useState<Record<number, number>>({});
  const [quizSubmitted, setQuizSubmitted] = useState(false);

  useEffect(() => {
    try {
      const stored = window.localStorage.getItem(progressStorageKey);
      const parsed = stored ? JSON.parse(stored) : [];
      if (Array.isArray(parsed)) setCompletedIds(new Set(parsed.map(String)));
    } catch {
      setCompletedIds(new Set());
    }
  }, []);

  useEffect(() => {
    try {
      window.localStorage.setItem(progressStorageKey, JSON.stringify(Array.from(completedIds)));
    } catch {
      // Local learning progress is optional.
    }
  }, [completedIds]);

  const query = searchTerm.trim().toLowerCase();
  const filteredCards = useMemo(
    () => learningCards.filter((card) => (activeCategory === 'All' || card.category === activeCategory) && (!query || matchesSearch(card, query))),
    [activeCategory, query],
  );

  const completedCount = completedIds.size;
  const quizAnswered = Object.keys(quizAnswers).length;
  const quizScore = quizQuestions.reduce((score, question, index) => score + (quizAnswers[index] === question.answer ? 1 : 0), 0);

  const navItems = [
    ['Home', '/'],
    ['Features', '/features'],
    ['Dashboard', '/dashboard'],
    ['Learn', '/learn'],
    ['About', '/about'],
    ['Contact', '/contact'],
    ['Admin', '/admin/login'],
  ];

  const markCompleted = (id: string) => {
    setCompletedIds((current) => {
      const next = new Set(current);
      next.add(id);
      return next;
    });
  };

  const startQuiz = () => {
    setQuizOpen(true);
    setQuizSubmitted(false);
  };

  return (
    <div className="learn-page min-h-screen overflow-x-hidden bg-[#030A14] text-white" dir={isRtl ? 'rtl' : 'ltr'}>
      <LearnPageStyles />
      <AnimatedBackdrop />

      <nav className="sticky top-0 z-50 border-b border-white/10 bg-[#07111F]/88 backdrop-blur-xl">
        <div className="learn-container learn-navbar py-3">
          <button onClick={() => navigate('/')} className="learn-brand rounded-xl focus:outline-none focus:ring-2 focus:ring-cyan-300/70" aria-label="Go to Sentinel AI home">
            <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 shadow-lg shadow-cyan-500/20">
              <Shield className="h-6 w-6" />
            </span>
            <span className="bg-gradient-to-r from-cyan-300 to-blue-300 bg-clip-text text-xl font-semibold text-transparent">
              Sentinel AI
            </span>
          </button>

          <div className="learn-nav-links">
            {navItems.map(([label, route]) => (
              <Button key={route} variant="ghost" onClick={() => navigate(route)} className="learn-nav-button">
                {label}
              </Button>
            ))}
          </div>

          <div className="learn-auth-actions">
            <Button variant="ghost" onClick={() => navigate('/login')} className="text-slate-200 hover:bg-white/5">
              Login
            </Button>
            <Button onClick={() => navigate('/signup')} className="bg-gradient-to-r from-cyan-600 to-blue-600 text-white shadow-lg shadow-cyan-950/25">
              Sign Up
            </Button>
          </div>
        </div>
      </nav>

      <main className="relative z-10">
        <section className="learn-hero learn-container">
          <div className="learn-reveal">
            <div className="mb-4 flex flex-wrap gap-2">
              {['Beginner Friendly', 'Privacy First', 'Practical Guides'].map((badge, index) => (
                <span key={badge} className="learn-badge" style={{ animationDelay: `${120 + index * 90}ms` }}>
                  {badge}
                </span>
              ))}
            </div>
            <h1 className="max-w-3xl text-4xl font-semibold leading-tight tracking-normal sm:text-5xl lg:text-[3.2rem]">
              Learn Cyber Safety with Sentinel AI
            </h1>
            <p className="mt-4 max-w-2xl text-lg leading-8 text-slate-300">
              Short lessons, safe practice, and quick checks to build stronger everyday security habits.
            </p>
            <div className="mt-6 flex flex-col gap-3 sm:flex-row">
              <Button onClick={() => document.getElementById('learning-content')?.scrollIntoView({ behavior: 'smooth', block: 'start' })} className="learn-primary-button h-11 px-5 text-white">
                Start Learning
                <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
              <Button variant="outline" onClick={startQuiz} className="h-11 border-white/15 bg-white/5 px-5 text-white hover:bg-white/10">
                Take Quick Quiz
                <HelpCircle className="ml-2 h-4 w-4" />
              </Button>
            </div>
          </div>

          <div className="learn-hero-console">
            <CyberSafetyConsole completedCount={completedCount} />
          </div>
        </section>

        <section className="learn-container learn-section">
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {[
              ['5', 'Guides', BookOpen],
              ['5', 'Videos', PlayCircle],
              ['3', 'Tips', ShieldCheck],
              [String(completedCount), 'Completed', CheckCircle2],
            ].map(([value, label, Icon], index) => (
              <StatCard key={String(label)} label={String(label)} value={String(value)} icon={Icon as React.ComponentType<{ className?: string }>} index={index} />
            ))}
          </div>
        </section>

        <section id="learning-content" className="learn-container learn-section scroll-mt-24">
          <div className="learn-filter-panel">
            <label className="relative block">
              <span className="sr-only">Search learning content</span>
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
              <input
                value={searchTerm}
                onChange={(event) => setSearchTerm(event.target.value)}
                aria-label="Search learning content"
                placeholder="Search learning content"
                className="h-11 w-full rounded-xl border border-white/10 bg-[#07111F] pl-10 pr-4 text-sm text-white outline-none transition placeholder:text-slate-500 focus:border-cyan-300 focus:shadow-[0_0_0_3px_rgba(34,211,238,0.10)]"
              />
            </label>
            <div className="mt-4 flex flex-wrap gap-2">
              {categories.map((category) => (
                <button
                  key={category}
                  type="button"
                  onClick={() => setActiveCategory(category)}
                  className={`learn-filter-pill ${activeCategory === category ? 'learn-filter-pill-active' : ''}`}
                >
                  {category}
                </button>
              ))}
            </div>
          </div>

          <div className="mt-8 flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <p className="text-sm font-medium text-cyan-300">Featured learning videos</p>
              <h2 className="mt-1 text-3xl font-semibold">Build practical cyber habits</h2>
            </div>
            <p className="text-sm text-slate-400">{filteredCards.length} matching tutorial{filteredCards.length === 1 ? '' : 's'}</p>
          </div>

          {filteredCards.length === 0 ? (
            <div className="learn-empty-state">
              <Search className="mx-auto h-9 w-9 text-slate-500" />
              <h3 className="mt-4 text-lg font-semibold">No tutorials found</h3>
              <p className="mt-2 text-sm text-slate-400">Try All categories or a shorter search.</p>
            </div>
          ) : (
            <div className="learn-card-grid mt-6">
              {filteredCards.map((card, index) => (
                <LearningContentCard
                  key={card.id}
                  card={card}
                  completed={completedIds.has(card.id)}
                  index={index}
                  onRead={() => setActiveGuide(card)}
                  onWatch={() => setActiveTutorial(card)}
                />
              ))}
            </div>
          )}
        </section>

        <section className="learn-container learn-section">
          <div className="learn-quiz-card">
            <div>
              <p className="text-sm font-medium text-purple-200">Knowledge check</p>
              <h2 className="mt-1 text-2xl font-semibold">Quick Cyber Safety Check</h2>
              <p className="mt-2 text-sm leading-6 text-purple-50/80">Three quick questions. No personal data collected.</p>
            </div>
            <Button onClick={startQuiz} className="bg-purple-600 px-5 text-white hover:bg-purple-500">
              Start Quiz
              <Target className="ml-2 h-4 w-4" />
            </Button>
          </div>
        </section>

        <section className="learn-container learn-section">
          <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <p className="text-sm font-medium text-emerald-300">Practice with Sentinel AI Tools</p>
              <h2 className="mt-1 text-3xl font-semibold">Turn lessons into action</h2>
            </div>
            <span className="text-xs text-slate-500">Existing routes only</span>
          </div>
          <div className="learn-tool-grid mt-6">
            {tools.map((tool, index) => (
              <PracticeToolCard key={tool.title} tool={tool} index={index} onNavigate={navigate} />
            ))}
          </div>
        </section>

        <section className="learn-container py-12 sm:py-14">
          <div className="learn-final-cta">
            <ShieldCheck className="mx-auto h-9 w-9 text-cyan-200" />
            <h2 className="mt-4 text-3xl font-semibold">Keep building safer habits</h2>
            <p className="mx-auto mt-2 max-w-xl text-sm leading-6 text-slate-300">
              Watch a lesson, practice with a real Sentinel AI tool, then come back for another quick check.
            </p>
            <div className="mt-6 flex flex-col justify-center gap-3 sm:flex-row">
              <Button onClick={() => document.getElementById('learning-content')?.scrollIntoView({ behavior: 'smooth', block: 'start' })} className="learn-primary-button px-5 text-white">
                Start Another Lesson
              </Button>
              <Button variant="outline" onClick={startQuiz} className="border-white/15 bg-white/5 px-5 text-white hover:bg-white/10">
                Take Quick Quiz
              </Button>
            </div>
          </div>
        </section>
      </main>

      {activeGuide && (
        <GuideDialog
          card={activeGuide}
          article={guideArticles[activeGuide.id]}
          completed={completedIds.has(activeGuide.id)}
          onClose={() => setActiveGuide(null)}
          onMarkRead={() => markCompleted(activeGuide.id)}
        />
      )}

      {activeTutorial && (
        <TutorialDialog
          card={activeTutorial}
          completed={completedIds.has(activeTutorial.id)}
          onClose={() => setActiveTutorial(null)}
          onMarkWatched={() => markCompleted(activeTutorial.id)}
        />
      )}

      {quizOpen && (
        <Dialog title="Quick Cyber Safety Check" eyebrow="Frontend-only quiz" onClose={() => setQuizOpen(false)}>
          <div className="grid gap-4">
            {quizQuestions.map((question, index) => (
              <div key={question.question} className="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
                <p className="text-sm font-medium text-white">{index + 1}. {question.question}</p>
                <div className="mt-3 grid gap-2">
                  {question.options.map((option, optionIndex) => {
                    const selected = quizAnswers[index] === optionIndex;
                    const correct = quizSubmitted && question.answer === optionIndex;
                    return (
                      <button
                        key={option}
                        type="button"
                        onClick={() => {
                          setQuizSubmitted(false);
                          setQuizAnswers((current) => ({ ...current, [index]: optionIndex }));
                        }}
                        className={`rounded-xl border px-3 py-2 text-left text-sm transition ${
                          correct
                            ? 'border-emerald-400/40 bg-emerald-500/15 text-emerald-100'
                            : selected
                              ? 'border-cyan-400/40 bg-cyan-500/15 text-cyan-100'
                              : 'border-white/10 bg-slate-950/30 text-slate-300 hover:bg-white/[0.06]'
                        }`}
                      >
                        {option}
                      </button>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>

          {quizSubmitted && (
            <div className="mt-4 rounded-2xl border border-amber-400/20 bg-amber-500/10 p-4">
              <p className="text-lg font-semibold text-amber-100">Score: {quizScore}/{quizQuestions.length}</p>
              <p className="mt-1 text-sm text-amber-100/80">
                {quizScore === quizQuestions.length ? 'Excellent safety instincts.' : 'Review the cards and try again.'}
              </p>
            </div>
          )}

          <div className="mt-5 flex flex-col gap-3 sm:flex-row">
            <Button
              onClick={() => setQuizSubmitted(true)}
              disabled={quizAnswered < quizQuestions.length}
              className="bg-amber-400 px-5 text-slate-950 hover:bg-amber-300 disabled:cursor-not-allowed disabled:opacity-50"
            >
              Submit Quiz
            </Button>
            <Button variant="outline" onClick={() => setQuizOpen(false)} className="border-white/15 bg-white/5 px-5 text-white hover:bg-white/10">
              Close
            </Button>
          </div>
        </Dialog>
      )}
    </div>
  );
}

function AnimatedBackdrop() {
  return (
    <div className="learn-backdrop" aria-hidden="true">
      <div className="learn-circuit-grid" />
      <div className="learn-glow learn-glow-a" />
      <div className="learn-glow learn-glow-b" />
      <div className="learn-light-line learn-light-line-a" />
      <div className="learn-light-line learn-light-line-b" />
    </div>
  );
}

function CyberSafetyConsole({ completedCount }: { completedCount: number }) {
  return (
    <div className="learn-console learn-reveal-delayed">
      <div className="learn-console-inner">
        <div className="flex items-center justify-between gap-4">
          <div>
            <p className="text-sm text-cyan-200">Cyber Safety Console</p>
            <h2 className="mt-1 text-2xl font-semibold">Learning Hub</h2>
          </div>
          <div className="learn-shield-orbit">
            <Shield className="h-7 w-7 text-cyan-100" />
          </div>
        </div>

        <div className="mt-5 grid grid-cols-2 gap-3">
          {[
            ['Guides', 5, BookOpen],
            ['Videos', 5, Video],
            ['Tips', 3, ShieldCheck],
            ['Done', completedCount, CheckCircle2],
          ].map(([label, value, Icon]) => (
            <div key={String(label)} className="learn-mini-stat">
              {typeof Icon !== 'number' && <Icon className="h-4 w-4 text-cyan-200" />}
              <span className="text-lg font-semibold">{value}</span>
              <span className="text-xs text-slate-400">{label}</span>
            </div>
          ))}
        </div>

        <div className="mt-5 space-y-3">
          {tips.map((tip, index) => (
            <div key={tip} className="learn-signal-row" style={{ animationDelay: `${index * 180}ms` }}>
              <span className="learn-signal-dot" />
              <span className="text-sm text-slate-200">{tip}</span>
              <span className="ml-auto rounded-full border border-white/10 bg-white/[0.04] px-2.5 py-1 text-xs text-slate-300">tip</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function StatCard({ label, value, icon: Icon, index }: { label: string; value: string; icon: React.ComponentType<{ className?: string }>; index: number }) {
  return (
    <div className="learn-stat-card" style={{ animationDelay: `${index * 90}ms` }}>
      <Icon className="h-5 w-5 text-cyan-200" />
      <div className="mt-3 flex items-end gap-2">
        <p className="text-2xl font-semibold">{value}</p>
        <p className="pb-1 text-sm text-slate-400">{label}</p>
      </div>
    </div>
  );
}

function LearningContentCard({
  card,
  completed,
  index,
  onRead,
  onWatch,
}: {
  card: LearningCard;
  completed: boolean;
  index: number;
  onRead: () => void;
  onWatch: () => void;
}) {
  const Icon = card.icon;

  return (
    <article className="learn-card group" style={{ animationDelay: `${index * 70}ms` }}>
      <div className="flex items-start justify-between gap-3">
        <span className="learn-card-icon border border-cyan-300/20 bg-cyan-400/10 text-cyan-100">
          <Icon className="h-5 w-5 transition-transform duration-300 group-hover:-translate-y-0.5 group-hover:scale-110" />
        </span>
        <span className="rounded-full border border-white/10 bg-white/[0.04] px-2.5 py-1 text-xs text-slate-300">{card.category}</span>
      </div>
      <div className="mt-4 flex flex-wrap items-center gap-2">
        <span className="rounded-full bg-purple-400/10 px-2.5 py-1 text-xs text-purple-100">Video</span>
        {completed && <span className="rounded-full bg-emerald-400/10 px-2.5 py-1 text-xs text-emerald-200">Completed</span>}
      </div>
      <h3 className="mt-4 text-lg font-semibold leading-snug">{card.title}</h3>
      <p className="learn-card-description mt-2 text-sm leading-6 text-slate-400">{card.description}</p>
      <div className="mt-4 flex flex-wrap gap-2 text-xs text-slate-300">
        <span className="inline-flex items-center gap-1 rounded-full bg-white/[0.05] px-2.5 py-1">
          <Clock className="h-3.5 w-3.5" />
          {card.duration}
        </span>
        <span className="rounded-full bg-white/[0.05] px-2.5 py-1">{card.difficulty}</span>
      </div>
      <div className="mt-5 flex flex-wrap gap-3">
        <Button onClick={onWatch} className="bg-purple-600 px-4 text-white hover:bg-purple-500">
          Watch Tutorial
          <PlayCircle className="ml-2 h-4 w-4" />
        </Button>
        <Button variant="outline" onClick={onRead} className="border-white/15 bg-white/5 px-4 text-white hover:bg-white/10">
          Read Guide
          <BookOpen className="ml-2 h-4 w-4" />
        </Button>
      </div>
    </article>
  );
}

function PracticeToolCard({ tool, index, onNavigate }: { tool: ToolCard; index: number; onNavigate: (route: string) => void }) {
  const Icon = tool.icon;
  const enabled = Boolean(tool.route);

  return (
    <article className="learn-tool-card" style={{ animationDelay: `${index * 70}ms` }}>
      <div className="flex items-start justify-between gap-3">
        <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-emerald-400/10 text-emerald-200">
          <Icon className="h-5 w-5" />
        </span>
        <span className={`rounded-full border px-2.5 py-1 text-xs ${enabled ? 'border-emerald-300/20 bg-emerald-400/10 text-emerald-100' : 'border-slate-500/20 bg-slate-500/10 text-slate-400'}`}>
          {enabled ? 'Available' : 'Coming Soon'}
        </span>
      </div>
      <h3 className="mt-4 text-base font-semibold">{tool.title}</h3>
      <p className="mt-2 flex-1 text-sm leading-5 text-slate-400">{tool.description}</p>
      <Button
        variant="outline"
        disabled={!enabled}
        onClick={() => tool.route && onNavigate(tool.route)}
        className="mt-4 w-fit border-white/10 bg-white/[0.04] px-4 text-white hover:bg-white/10 disabled:cursor-not-allowed disabled:text-slate-500"
      >
        {enabled ? 'Open Tool' : 'Coming Soon'}
      </Button>
    </article>
  );
}

function GuideDialog({
  card,
  article,
  completed,
  onClose,
  onMarkRead,
}: {
  card: LearningCard;
  article: GuideArticle;
  completed: boolean;
  onClose: () => void;
  onMarkRead: () => void;
}) {
  return (
    <Dialog title={card.title} eyebrow={`${card.category} guide`} onClose={onClose}>
      <div className="flex flex-wrap gap-2 text-xs text-slate-300">
        <span className="rounded-full bg-white/[0.05] px-2.5 py-1">{card.duration}</span>
        <span className="rounded-full bg-white/[0.05] px-2.5 py-1">{card.difficulty}</span>
      </div>
      <p className="mt-5 leading-7 text-slate-300">{article.intro}</p>
      <div className="mt-5 grid gap-3">
        {article.sections.map((section) => (
          <section key={section.heading} className="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
            <h3 className="font-semibold text-cyan-100">{section.heading}</h3>
            <p className="mt-2 text-sm leading-6 text-slate-300">{section.body}</p>
          </section>
        ))}
      </div>
      <div className="mt-5 rounded-2xl border border-emerald-300/20 bg-emerald-400/10 p-4">
        <h3 className="font-semibold text-emerald-100">Practical checklist</h3>
        <ul className="mt-3 grid gap-2 text-sm text-emerald-50/90">
          {article.checklist.map((item) => (
            <li key={item} className="flex gap-2">
              <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-200" />
              <span>{item}</span>
            </li>
          ))}
        </ul>
      </div>
      <div className="mt-6 flex flex-col gap-3 sm:flex-row">
        <Button
          onClick={() => {
            onMarkRead();
            onClose();
          }}
          className="bg-emerald-600 px-5 text-white hover:bg-emerald-500"
        >
          {completed ? 'Marked as Read' : 'Mark as Read'}
        </Button>
        <Button variant="outline" onClick={onClose} className="border-white/15 bg-white/5 px-5 text-white hover:bg-white/10">
          Close
        </Button>
      </div>
    </Dialog>
  );
}

function TutorialDialog({
  card,
  completed,
  onClose,
  onMarkWatched,
}: {
  card: LearningCard;
  completed: boolean;
  onClose: () => void;
  onMarkWatched: () => void;
}) {
  const [videoError, setVideoError] = useState(false);

  useEffect(() => {
    setVideoError(false);
  }, [card.videoUrl]);

  return (
    <Dialog title={card.title} eyebrow={`${card.category} tutorial`} onClose={onClose} wide>
      <div className="learn-video-shell">
        {videoError ? (
          <div className="learn-video-fallback">
            <Video className="h-10 w-10 text-slate-500" />
            <p className="mt-3 text-sm text-slate-300">Video could not be loaded. Please check the local video file.</p>
          </div>
        ) : (
          <video
            key={card.videoUrl}
            className="learn-video-player"
            controls
            preload="metadata"
            onError={() => setVideoError(true)}
          >
            <source src={card.videoUrl} type="video/mp4" />
            Video could not be loaded. Please check the local video file.
          </video>
        )}
      </div>
      <div className="mt-5 flex flex-wrap gap-2 text-xs text-slate-300">
        <span className="rounded-full bg-white/[0.05] px-2.5 py-1">{card.category}</span>
        <span className="rounded-full bg-white/[0.05] px-2.5 py-1">{card.duration}</span>
        <span className="rounded-full bg-white/[0.05] px-2.5 py-1">{card.difficulty}</span>
      </div>
      <p className="mt-4 leading-7 text-slate-300">{card.description}</p>
      <div className="mt-5 rounded-2xl border border-purple-300/20 bg-purple-400/10 p-4">
        <h3 className="font-semibold text-purple-50">Learning objectives</h3>
        <ul className="mt-3 grid gap-2 text-sm text-purple-50/85">
          {card.objectives.map((objective) => (
            <li key={objective} className="flex gap-2">
              <Sparkles className="mt-0.5 h-4 w-4 shrink-0 text-purple-200" />
              <span>{objective}</span>
            </li>
          ))}
        </ul>
      </div>
      <div className="mt-6 flex flex-col gap-3 sm:flex-row">
        <Button onClick={onMarkWatched} className="bg-emerald-600 px-5 text-white hover:bg-emerald-500">
          {completed ? 'Marked as Watched' : 'Mark as Watched'}
        </Button>
        <Button variant="outline" onClick={onClose} className="border-white/15 bg-white/5 px-5 text-white hover:bg-white/10">
          Close
        </Button>
      </div>
    </Dialog>
  );
}

function Dialog({
  eyebrow,
  title,
  children,
  onClose,
  wide = false,
}: {
  eyebrow: string;
  title: string;
  children: React.ReactNode;
  onClose: () => void;
  wide?: boolean;
}) {
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  return (
    <div className="learn-modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="learn-dialog-title">
      <div className={`learn-modal ${wide ? 'learn-modal-wide' : ''}`}>
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="text-sm text-cyan-300">{eyebrow}</p>
            <h2 id="learn-dialog-title" className="mt-1 text-xl font-semibold">{title}</h2>
          </div>
          <button type="button" onClick={onClose} className="rounded-xl p-2 text-slate-400 hover:bg-white/10 hover:text-white focus:outline-none focus:ring-2 focus:ring-cyan-300/70" aria-label="Close dialog">
            <X className="h-5 w-5" />
          </button>
        </div>
        <div className="mt-5">{children}</div>
      </div>
    </div>
  );
}

function LearnPageStyles() {
  return (
    <style>{`
      .learn-page {
        --learn-cyan: 34, 211, 238;
        --learn-blue: 59, 130, 246;
        --learn-purple: 168, 85, 247;
        position: relative;
      }

      .learn-container {
        width: min(100% - 2rem, 1160px);
        margin-inline: auto;
      }

      .learn-navbar {
        display: grid;
        grid-template-columns: auto minmax(0, 1fr) auto;
        align-items: center;
        gap: 1rem;
      }

      .learn-brand,
      .learn-auth-actions {
        display: flex;
        align-items: center;
        gap: 0.75rem;
        min-width: 0;
      }

      .learn-auth-actions {
        justify-content: flex-end;
        gap: 0.5rem;
      }

      .learn-nav-links {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 0.1rem;
        overflow-x: auto;
        scrollbar-width: none;
        min-width: 0;
      }

      .learn-nav-links::-webkit-scrollbar {
        display: none;
      }

      .learn-nav-button {
        color: rgb(203, 213, 225);
        white-space: nowrap;
        padding-inline: 0.75rem;
      }

      .learn-nav-button:hover {
        background: rgba(255, 255, 255, 0.05);
        color: white;
      }

      .learn-section {
        padding-block: 1.15rem;
      }

      .learn-hero {
        min-height: 0;
        height: auto;
        display: grid;
        grid-template-columns: minmax(0, 1fr) minmax(280px, 30rem);
        align-items: center;
        gap: 1.5rem;
        padding-block: 1.75rem 1rem;
      }

      .learn-backdrop {
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
        mask-image: linear-gradient(to bottom, black, black 72%, transparent);
      }

      .learn-circuit-grid {
        position: absolute;
        inset: 0;
        background:
          linear-gradient(90deg, transparent 0 16%, rgba(34, 211, 238, 0.08) 16% 16.2%, transparent 16.2% 100%),
          linear-gradient(0deg, transparent 0 28%, rgba(59, 130, 246, 0.06) 28% 28.2%, transparent 28.2% 100%);
        background-size: 220px 180px;
        opacity: 0.45;
        animation: learn-grid-drift 18s linear infinite;
      }

      .learn-glow {
        position: absolute;
        width: 44rem;
        height: 24rem;
        filter: blur(72px);
        opacity: 0.22;
        transform: rotate(-12deg);
      }

      .learn-glow-a {
        top: 2rem;
        right: -12rem;
        background: rgba(var(--learn-cyan), 0.72);
        animation: learn-float 12s ease-in-out infinite;
      }

      .learn-glow-b {
        top: 22rem;
        left: -14rem;
        background: rgba(var(--learn-purple), 0.5);
        animation: learn-float 14s ease-in-out infinite reverse;
      }

      .learn-light-line {
        position: absolute;
        height: 1px;
        width: 32rem;
        background: linear-gradient(90deg, transparent, rgba(34, 211, 238, 0.4), transparent);
        opacity: 0.35;
      }

      .learn-light-line-a {
        top: 11rem;
        right: 5%;
        animation: learn-line-slide 9s ease-in-out infinite;
      }

      .learn-light-line-b {
        top: 42rem;
        left: 8%;
        animation: learn-line-slide 11s ease-in-out infinite reverse;
      }

      .learn-reveal,
      .learn-reveal-delayed,
      .learn-stat-card,
      .learn-card,
      .learn-tool-card {
        opacity: 0;
        animation: learn-rise 680ms cubic-bezier(0.2, 0.8, 0.2, 1) forwards;
      }

      .learn-reveal-delayed {
        animation-delay: 140ms;
      }

      .learn-hero-console {
        min-height: 0;
      }

      .learn-badge {
        opacity: 0;
        animation: learn-rise 520ms ease forwards;
        border: 1px solid rgba(34, 211, 238, 0.25);
        background: rgba(34, 211, 238, 0.1);
        color: #cffafe;
        border-radius: 999px;
        padding: 0.25rem 0.75rem;
        font-size: 0.875rem;
      }

      .learn-primary-button {
        background: linear-gradient(135deg, #0891b2, #2563eb);
        box-shadow: 0 12px 34px rgba(8, 145, 178, 0.26);
        position: relative;
        overflow: hidden;
      }

      .learn-primary-button::after {
        content: "";
        position: absolute;
        inset: 0;
        transform: translateX(-110%);
        background: linear-gradient(90deg, transparent, rgba(255,255,255,0.22), transparent);
        transition: transform 700ms ease;
      }

      .learn-primary-button:hover::after {
        transform: translateX(110%);
      }

      .learn-console,
      .learn-filter-panel,
      .learn-quiz-card,
      .learn-final-cta {
        border: 1px solid rgba(255, 255, 255, 0.1);
        background: linear-gradient(135deg, rgba(15, 23, 42, 0.78), rgba(8, 19, 35, 0.86));
        box-shadow: 0 24px 70px rgba(2, 6, 23, 0.35);
        backdrop-filter: blur(18px);
      }

      .learn-console {
        align-self: center;
        border-radius: 26px;
        padding: 1px;
        max-width: 30rem;
        justify-self: end;
        background:
          linear-gradient(135deg, rgba(34, 211, 238, 0.38), rgba(168, 85, 247, 0.2), rgba(255,255,255,0.08));
        animation: learn-rise 520ms cubic-bezier(0.2, 0.8, 0.2, 1) 140ms forwards, learn-console-float 6s ease-in-out 900ms infinite;
      }

      .learn-console-inner {
        border-radius: 25px;
        background: rgba(7, 17, 31, 0.92);
        padding: 1rem;
      }

      .learn-shield-orbit {
        width: 4rem;
        height: 4rem;
        border-radius: 999px;
        display: flex;
        align-items: center;
        justify-content: center;
        border: 1px solid rgba(34, 211, 238, 0.28);
        background: radial-gradient(circle, rgba(34, 211, 238, 0.22), rgba(37, 99, 235, 0.06));
        box-shadow: 0 0 42px rgba(34, 211, 238, 0.22);
        animation: learn-soft-pulse 2.8s ease-in-out infinite;
      }

      .learn-mini-stat,
      .learn-signal-row,
      .learn-stat-card,
      .learn-card,
      .learn-tool-card {
        border: 1px solid rgba(255, 255, 255, 0.1);
        background: rgba(255, 255, 255, 0.045);
      }

      .learn-mini-stat {
        border-radius: 16px;
        padding: 0.8rem;
        display: flex;
        flex-direction: column;
        gap: 0.15rem;
      }

      .learn-signal-row {
        border-radius: 16px;
        padding: 0.85rem;
        display: flex;
        align-items: center;
        gap: 0.75rem;
        animation: learn-signal-glow 3s ease-in-out infinite;
      }

      .learn-signal-dot {
        width: 0.55rem;
        height: 0.55rem;
        border-radius: 999px;
        background: #22d3ee;
        box-shadow: 0 0 18px rgba(34, 211, 238, 0.75);
      }

      .learn-stat-card {
        min-height: 104px;
        border-radius: 20px;
        padding: 1rem;
        box-shadow: 0 18px 45px rgba(2, 6, 23, 0.22);
        transition: transform 220ms ease, border-color 220ms ease, box-shadow 220ms ease;
      }

      .learn-stat-card:hover,
      .learn-card:hover,
      .learn-tool-card:hover {
        transform: translateY(-5px);
        border-color: rgba(34, 211, 238, 0.38);
        box-shadow: 0 22px 60px rgba(8, 145, 178, 0.13);
      }

      .learn-filter-panel {
        border-radius: 24px;
        padding: 1rem;
      }

      .learn-filter-pill {
        white-space: nowrap;
        border-radius: 999px;
        border: 1px solid rgba(255,255,255,0.1);
        background: rgba(255,255,255,0.035);
        color: rgb(203, 213, 225);
        padding: 0.5rem 0.9rem;
        font-size: 0.875rem;
        transition: background 180ms ease, border-color 180ms ease, color 180ms ease, transform 180ms ease;
      }

      .learn-filter-pill:hover {
        transform: translateY(-1px);
        background: rgba(255,255,255,0.07);
      }

      .learn-filter-pill:focus-visible {
        outline: 2px solid rgba(34,211,238,0.72);
        outline-offset: 2px;
      }

      .learn-filter-pill-active {
        border-color: rgba(34,211,238,0.85);
        background: rgba(34,211,238,0.16);
        color: #cffafe;
        box-shadow: 0 0 24px rgba(34,211,238,0.12);
      }

      .learn-card-grid {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: 1.25rem;
      }

      .learn-tool-grid {
        display: grid;
        grid-template-columns: repeat(5, minmax(0, 1fr));
        gap: 1rem;
      }

      .learn-card {
        position: relative;
        min-height: 286px;
        display: flex;
        flex-direction: column;
        border-radius: 24px;
        padding: 1.15rem;
        background: linear-gradient(180deg, rgba(11, 22, 39, 0.94), rgba(7, 17, 31, 0.96));
        overflow: hidden;
      }

      .learn-card::before {
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

      .learn-card:hover::before {
        opacity: 1;
      }

      .learn-card-icon {
        width: 2.65rem;
        height: 2.65rem;
        border-radius: 0.95rem;
        display: flex;
        align-items: center;
        justify-content: center;
      }

      .learn-card-description {
        display: -webkit-box;
        -webkit-line-clamp: 3;
        -webkit-box-orient: vertical;
        overflow: hidden;
        min-height: 4.5rem;
      }

      .learn-empty-state {
        margin-top: 1.5rem;
        border-radius: 24px;
        border: 1px solid rgba(255,255,255,0.1);
        background: rgba(11, 22, 39, 0.78);
        padding: 2.5rem;
        text-align: center;
      }

      .learn-quiz-card {
        border-radius: 24px;
        padding: 1.25rem;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 1.25rem;
      }

      .learn-tool-card {
        min-height: 190px;
        display: flex;
        flex-direction: column;
        border-radius: 20px;
        padding: 1rem;
        background: linear-gradient(180deg, rgba(11, 22, 39, 0.9), rgba(7, 17, 31, 0.94));
        transition: transform 220ms ease, border-color 220ms ease, box-shadow 220ms ease;
      }

      .learn-final-cta {
        border-radius: 26px;
        padding: 1.75rem;
        text-align: center;
        background:
          linear-gradient(135deg, rgba(34,211,238,0.15), rgba(37,99,235,0.13)),
          rgba(7,17,31,0.82);
      }

      .learn-modal-backdrop {
        position: fixed;
        inset: 0;
        z-index: 80;
        display: flex;
        align-items: center;
        justify-content: center;
        background: rgba(2, 6, 23, 0.82);
        backdrop-filter: blur(10px);
        padding: 1rem;
        animation: learn-fade-in 180ms ease forwards;
      }

      .learn-modal {
        max-height: min(90vh, 780px);
        width: min(100%, 44rem);
        overflow-y: auto;
        border-radius: 24px;
        border: 1px solid rgba(255,255,255,0.1);
        background: linear-gradient(180deg, rgba(11,22,39,0.98), rgba(5,12,24,0.98));
        padding: 1.5rem;
        box-shadow: 0 24px 80px rgba(0,0,0,0.45);
        animation: learn-modal-rise 220ms ease forwards;
      }

      .learn-modal-wide {
        width: min(100%, 58rem);
      }

      .learn-video-shell {
        position: relative;
        overflow: hidden;
        border-radius: 22px;
        border: 1px solid rgba(34,211,238,0.18);
        background:
          radial-gradient(circle at 20% 20%, rgba(34,211,238,0.18), transparent 34%),
          radial-gradient(circle at 82% 18%, rgba(168,85,247,0.14), transparent 34%),
          #050c18;
        aspect-ratio: 16 / 9;
      }

      .learn-video-player,
      .learn-video-fallback {
        width: 100%;
        height: 100%;
      }

      .learn-video-player {
        display: block;
        background: transparent;
      }

      .learn-video-fallback {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        padding: 1rem;
        text-align: center;
      }

      @keyframes learn-rise {
        from { opacity: 0; transform: translateY(18px); }
        to { opacity: 1; transform: translateY(0); }
      }

      @keyframes learn-console-float {
        0%, 100% { transform: translateY(0); }
        50% { transform: translateY(-8px); }
      }

      @keyframes learn-float {
        0%, 100% { transform: translate3d(0, 0, 0) rotate(-12deg); }
        50% { transform: translate3d(18px, -20px, 0) rotate(-8deg); }
      }

      @keyframes learn-grid-drift {
        from { background-position: 0 0; }
        to { background-position: 220px 180px; }
      }

      @keyframes learn-line-slide {
        0%, 100% { transform: translateX(-20px); opacity: 0.14; }
        50% { transform: translateX(28px); opacity: 0.38; }
      }

      @keyframes learn-soft-pulse {
        0%, 100% { transform: scale(1); box-shadow: 0 0 34px rgba(34,211,238,0.16); }
        50% { transform: scale(1.025); box-shadow: 0 0 54px rgba(34,211,238,0.27); }
      }

      @keyframes learn-signal-glow {
        0%, 100% { border-color: rgba(255,255,255,0.1); }
        50% { border-color: rgba(34,211,238,0.24); }
      }

      @keyframes learn-fade-in {
        from { opacity: 0; }
        to { opacity: 1; }
      }

      @keyframes learn-modal-rise {
        from { opacity: 0; transform: translateY(12px) scale(0.98); }
        to { opacity: 1; transform: translateY(0) scale(1); }
      }

      @media (max-width: 1024px) {
        .learn-navbar {
          grid-template-columns: 1fr auto;
        }

        .learn-nav-links {
          grid-column: 1 / -1;
          width: 100%;
          padding-top: 0.25rem;
          justify-content: flex-start;
        }

        .learn-hero {
          grid-template-columns: 1fr;
          padding-block: 1.5rem 0.75rem;
        }

        .learn-console {
          justify-self: stretch;
          max-width: none;
        }

        .learn-card-grid {
          grid-template-columns: repeat(2, minmax(0, 1fr));
        }

        .learn-tool-grid {
          grid-template-columns: repeat(2, minmax(0, 1fr));
        }
      }

      @media (max-width: 640px) {
        .learn-container {
          width: min(100% - 1rem, 1160px);
        }

        .learn-section {
          padding-block: 1rem;
        }

        .learn-hero {
          padding-block: 1.25rem 0.5rem;
        }

        .learn-card-grid,
        .learn-tool-grid {
          grid-template-columns: 1fr;
        }

        .learn-quiz-card {
          align-items: stretch;
          flex-direction: column;
        }

        .learn-modal {
          max-height: 92vh;
          padding: 1.1rem;
          border-radius: 20px;
        }
      }

      @media (prefers-reduced-motion: reduce) {
        .learn-page *,
        .learn-page *::before,
        .learn-page *::after {
          animation-duration: 1ms !important;
          animation-iteration-count: 1 !important;
          transition-duration: 1ms !important;
          scroll-behavior: auto !important;
        }
      }
    `}</style>
  );
}
