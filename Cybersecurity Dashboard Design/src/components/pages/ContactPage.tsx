import React, { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  AlertTriangle,
  CheckCircle,
  ChevronDown,
  Clock,
  HelpCircle,
  Loader2,
  Mail,
  MapPin,
  Send,
  Shield,
  ShieldCheck,
} from 'lucide-react';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Textarea } from '../ui/textarea';
import { useLanguage } from '../../contexts/LanguageContext';

const API_BASE_URL =
  import.meta.env.DEV ? '' : (import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000');

const SUPPORT_EMAIL = 'sentinel.ai.app@gmail.com';

const SUPPORT_CATEGORIES = [
  'General Support',
  'Account Access',
  'Password Checker',
  'Identity Leak Monitor',
  'PCAP Analysis',
  'Reports Center',
  'File Vault',
  'Phishing Scanner',
];

type ContactForm = {
  fullName: string;
  email: string;
  category: string;
  subject: string;
  message: string;
  honeypot: string;
};

type ContactErrors = Partial<Record<keyof ContactForm, string>>;

const initialForm: ContactForm = {
  fullName: '',
  email: '',
  category: 'General Support',
  subject: '',
  message: '',
  honeypot: '',
};

function validateEmail(value: string) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim());
}

function validateForm(form: ContactForm): ContactErrors {
  const errors: ContactErrors = {};
  if (!form.fullName.trim()) errors.fullName = 'Full Name is required.';
  if (!form.email.trim()) errors.email = 'Email Address is required.';
  else if (!validateEmail(form.email)) errors.email = 'Enter a valid email address.';
  if (!form.category.trim()) errors.category = 'Support category is required.';
  if (!form.subject.trim()) errors.subject = 'Subject is required.';
  if (!form.message.trim()) errors.message = 'Message is required.';
  else if (form.message.trim().length < 10) errors.message = 'Message must be at least 10 characters.';
  return errors;
}

export function ContactPage() {
  const { language, isRtl } = useLanguage();
  const navigate = useNavigate();
  const [formData, setFormData] = useState<ContactForm>(initialForm);
  const [errors, setErrors] = useState<ContactErrors>({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [status, setStatus] = useState<'idle' | 'success' | 'error'>('idle');

  const navItems = [
    ['Home', '/'],
    ['Features', '/features'],
    ['Dashboard', '/dashboard'],
    ['Learn', '/learn'],
    ['About', '/about'],
    ['Contact', '/contact'],
  ];

  const faqItems = useMemo(
    () => [
      {
        question: 'How fast does support respond?',
        answer: 'Most support requests are reviewed within one business day. Urgent access issues are prioritized first.',
      },
      {
        question: 'Can I report a security issue?',
        answer: 'Yes. Share a clear summary, affected feature, steps to reproduce, and safe screenshots if needed.',
      },
      {
        question: 'What information should I include?',
        answer: 'Include your name, contact email, support category, a short subject, and a safe description of the issue.',
      },
      {
        question: 'Should I include passwords or tokens?',
        answer: 'No. Do not include passwords, private keys, tokens, raw PCAP contents, or sensitive files in this form.',
      },
    ],
    [],
  );

  const handleChange = (event: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    const { name, value } = event.target;
    setFormData((current) => ({ ...current, [name]: value }));
    setErrors((current) => ({ ...current, [name]: undefined }));
    setStatus('idle');
  };

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    const nextErrors = validateForm(formData);
    setErrors(nextErrors);
    setStatus('idle');
    if (Object.keys(nextErrors).length > 0) return;

    setIsSubmitting(true);
    try {
      const response = await fetch(`${API_BASE_URL || ''}/api/contact/support`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          full_name: formData.fullName.trim(),
          email: formData.email.trim(),
          category: formData.category,
          subject: formData.subject.trim(),
          message: formData.message.trim(),
          honeypot: formData.honeypot,
        }),
      });

      if (!response.ok) {
        throw new Error('Contact request failed');
      }

      setFormData(initialForm);
      setErrors({});
      setStatus('success');
    } catch {
      setStatus('error');
    } finally {
      setIsSubmitting(false);
    }
  };

  const fieldClass = (field: keyof ContactForm) =>
    `w-full bg-[#0F172A]/90 border rounded-xl text-white h-12 transition-all duration-300 placeholder:text-slate-500 ${
      errors[field]
        ? 'border-red-400/60 focus:border-red-300 focus:ring-2 focus:ring-red-400/20'
        : 'border-white/10 focus:border-cyan-300 focus:ring-2 focus:ring-cyan-300/20'
    }`;

  return (
    <div className="contact-page min-h-screen bg-[#030A14] text-white" dir={isRtl ? 'rtl' : 'ltr'}>
      <ContactPageStyles />
      <ContactBackdrop />

      <nav className="sticky top-0 z-50 border-b border-white/10 bg-[#07111F]/88 backdrop-blur-xl">
        <div className="contact-container contact-navbar py-3">
          <button onClick={() => navigate('/')} className="contact-brand rounded-xl focus:outline-none focus:ring-2 focus:ring-cyan-300/70" aria-label="Go to Sentinel AI home">
            <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 shadow-lg shadow-cyan-500/20">
              <Shield className="h-6 w-6" />
            </span>
            <span className="bg-gradient-to-r from-cyan-300 to-blue-300 bg-clip-text text-xl font-semibold text-transparent">
              Sentinel AI
            </span>
          </button>

          <div className="contact-nav-links">
            {navItems.map(([label, route]) => (
              <Button key={route} variant="ghost" onClick={() => navigate(route)} className="contact-nav-button">
                {label}
              </Button>
            ))}
          </div>

          <div className="contact-auth-actions">
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
        <section className="contact-container contact-hero">
          <div className="contact-badge">
            <ShieldCheck className="h-4 w-4" />
            Sentinel AI Support
          </div>
          <h1 className="mt-5 text-4xl font-semibold leading-tight tracking-normal sm:text-5xl lg:text-[3.35rem]">
            Contact Sentinel AI Support
          </h1>
          <p className="mx-auto mt-4 max-w-2xl text-lg leading-8 text-slate-300">
            Send a safe support request and our team will review it without asking for secrets or sensitive evidence.
          </p>
        </section>

        <section className="contact-container pb-10">
          <div className="grid gap-6 lg:grid-cols-[1.05fr_0.95fr]">
            <div className="contact-card p-6 sm:p-8">
              <form onSubmit={handleSubmit} noValidate className="space-y-5">
                <input
                  type="text"
                  name="honeypot"
                  value={formData.honeypot}
                  onChange={handleChange}
                  className="hidden"
                  tabIndex={-1}
                  autoComplete="off"
                  aria-hidden="true"
                />

                <div className="rounded-2xl border border-amber-300/20 bg-amber-400/10 p-4 text-sm leading-6 text-amber-50/90">
                  <div className="flex gap-3">
                    <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-amber-200" />
                    <span>Do not include passwords, private keys, tokens, or sensitive files in this message.</span>
                  </div>
                </div>

                {status === 'success' && (
                  <div className="rounded-2xl border border-emerald-300/20 bg-emerald-400/10 p-4 text-sm text-emerald-100">
                    <div className="flex items-center gap-3">
                      <CheckCircle className="h-5 w-5" />
                      <span>Your message has been sent successfully.</span>
                    </div>
                  </div>
                )}

                {status === 'error' && (
                  <div className="rounded-2xl border border-red-300/20 bg-red-400/10 p-4 text-sm text-red-100">
                    <div className="flex items-center gap-3">
                      <AlertTriangle className="h-5 w-5" />
                      <span>We could not send your message. Please try again.</span>
                    </div>
                  </div>
                )}

                <FormField label="Full Name" error={errors.fullName}>
                  <Input
                    id="fullName"
                    name="fullName"
                    type="text"
                    value={formData.fullName}
                    onChange={handleChange}
                    disabled={isSubmitting}
                    className={fieldClass('fullName')}
                    placeholder="John Doe"
                  />
                </FormField>

                <FormField label="Email Address" error={errors.email}>
                  <Input
                    id="email"
                    name="email"
                    type="email"
                    value={formData.email}
                    onChange={handleChange}
                    disabled={isSubmitting}
                    className={fieldClass('email')}
                    placeholder="john@example.com"
                  />
                </FormField>

                <FormField label="Support Category" error={errors.category}>
                  <div className="relative">
                    <select
                      id="category"
                      name="category"
                      value={formData.category}
                      onChange={handleChange}
                      disabled={isSubmitting}
                      className={`${fieldClass('category')} appearance-none px-3`}
                    >
                      {SUPPORT_CATEGORIES.map((category) => (
                        <option key={category} value={category} className="bg-[#0F172A] text-white">
                          {category}
                        </option>
                      ))}
                    </select>
                    <ChevronDown className="pointer-events-none absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
                  </div>
                </FormField>

                <FormField label="Subject" error={errors.subject}>
                  <Input
                    id="subject"
                    name="subject"
                    type="text"
                    value={formData.subject}
                    onChange={handleChange}
                    disabled={isSubmitting}
                    className={fieldClass('subject')}
                    placeholder="How can we help?"
                  />
                </FormField>

                <FormField label="Message" error={errors.message}>
                  <Textarea
                    id="message"
                    name="message"
                    value={formData.message}
                    onChange={handleChange}
                    disabled={isSubmitting}
                    rows={6}
                    className={`min-h-[150px] resize-none ${fieldClass('message')}`}
                    placeholder="Describe the issue using safe details only..."
                  />
                </FormField>

                <Button
                  type="submit"
                  disabled={isSubmitting}
                  className="contact-primary-button h-12 w-full rounded-xl text-white disabled:cursor-not-allowed disabled:opacity-70"
                >
                  {isSubmitting ? (
                    <Loader2 className="mr-2 h-5 w-5 animate-spin" />
                  ) : (
                    <Send className="mr-2 h-5 w-5" />
                  )}
                  {isSubmitting ? 'Sending...' : 'Send Message'}
                </Button>
              </form>
            </div>

            <div className="space-y-6">
              <div className="contact-card p-6 sm:p-8">
                <h2 className="text-3xl font-semibold text-white">Get in Touch</h2>
                <div className="mt-7 space-y-5">
                  <ContactInfo icon={MapPin} title="Address">
                    <p>Alexandria National University</p>
                    <p>Cybersecurity Department</p>
                  </ContactInfo>

                  <ContactInfo icon={Mail} title="Email">
                    <a href={`mailto:${SUPPORT_EMAIL}`} className="text-cyan-200 hover:text-cyan-100">
                      {SUPPORT_EMAIL}
                    </a>
                  </ContactInfo>
                </div>
              </div>

              <div className="contact-support-card">
                <div className="flex items-start gap-4">
                  <span className="flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl bg-gradient-to-br from-cyan-500 to-blue-600 shadow-lg shadow-cyan-500/25">
                    <Clock className="h-6 w-6 text-white" />
                  </span>
                  <div>
                    <h3 className="text-xl font-semibold text-white">24/7 Support Available</h3>
                    <p className="mt-2 text-sm leading-6 text-slate-300">
                      Send a message any time. Support requests are reviewed safely and routed to the right team.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className="contact-container pb-14">
          <div className="contact-card p-6 sm:p-8">
            <div className="flex items-center gap-3">
              <HelpCircle className="h-6 w-6 text-cyan-200" />
              <h2 className="text-2xl font-semibold">Support FAQ</h2>
            </div>
            <div className="mt-6 grid gap-4 md:grid-cols-2">
              {faqItems.map((item) => (
                <article key={item.question} className="rounded-2xl border border-white/10 bg-white/[0.035] p-4">
                  <h3 className="font-semibold text-white">{item.question}</h3>
                  <p className="mt-2 text-sm leading-6 text-slate-400">{item.answer}</p>
                </article>
              ))}
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}

function FormField({ label, error, children }: { label: string; error?: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="mb-2 block text-sm font-medium text-slate-300">{label}</label>
      {children}
      {error && <p className="mt-2 text-sm text-red-300">{error}</p>}
    </div>
  );
}

function ContactInfo({
  icon: Icon,
  title,
  children,
}: {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex items-start gap-4">
      <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-cyan-300/20 bg-cyan-400/10 text-cyan-200">
        <Icon className="h-5 w-5" />
      </span>
      <div>
        <h3 className="font-semibold text-white">{title}</h3>
        <div className="mt-1 text-sm leading-6 text-slate-400">{children}</div>
      </div>
    </div>
  );
}

function ContactBackdrop() {
  return (
    <div className="contact-backdrop" aria-hidden="true">
      <div className="contact-circuit-grid" />
      <div className="contact-glow contact-glow-a" />
      <div className="contact-glow contact-glow-b" />
    </div>
  );
}

function ContactPageStyles() {
  return (
    <style>{`
      .contact-page {
        position: relative;
        overflow-x: hidden;
      }

      .contact-container {
        width: min(100% - 2rem, 1160px);
        margin-inline: auto;
      }

      .contact-navbar {
        display: grid;
        grid-template-columns: auto minmax(0, 1fr) auto;
        align-items: center;
        gap: 1rem;
      }

      .contact-brand,
      .contact-auth-actions {
        display: flex;
        align-items: center;
        gap: 0.75rem;
        min-width: 0;
      }

      .contact-auth-actions {
        justify-content: flex-end;
        gap: 0.5rem;
      }

      .contact-nav-links {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 0.1rem;
        overflow-x: auto;
        scrollbar-width: none;
        min-width: 0;
      }

      .contact-nav-links::-webkit-scrollbar {
        display: none;
      }

      .contact-nav-button {
        color: rgb(203, 213, 225);
        white-space: nowrap;
        padding-inline: 0.75rem;
      }

      .contact-nav-button:hover {
        background: rgba(255, 255, 255, 0.05);
        color: white;
      }

      .contact-hero {
        padding-block: 2.75rem 2rem;
        text-align: center;
      }

      .contact-badge {
        margin-inline: auto;
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

      .contact-backdrop {
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

      .contact-circuit-grid {
        position: absolute;
        inset: 0;
        background:
          linear-gradient(90deg, transparent 0 16%, rgba(34, 211, 238, 0.08) 16% 16.2%, transparent 16.2% 100%),
          linear-gradient(0deg, transparent 0 28%, rgba(59, 130, 246, 0.06) 28% 28.2%, transparent 28.2% 100%);
        background-size: 220px 180px;
        opacity: 0.45;
        animation: contact-grid-drift 18s linear infinite;
      }

      .contact-glow {
        position: absolute;
        width: 44rem;
        height: 24rem;
        filter: blur(72px);
        opacity: 0.22;
        transform: rotate(-12deg);
      }

      .contact-glow-a {
        top: 2rem;
        right: -12rem;
        background: rgba(34, 211, 238, 0.72);
        animation: contact-float 12s ease-in-out infinite;
      }

      .contact-glow-b {
        top: 30rem;
        left: -14rem;
        background: rgba(168, 85, 247, 0.5);
        animation: contact-float 14s ease-in-out infinite reverse;
      }

      .contact-card,
      .contact-support-card {
        border: 1px solid rgba(255, 255, 255, 0.1);
        background: linear-gradient(135deg, rgba(15, 23, 42, 0.78), rgba(8, 19, 35, 0.86));
        box-shadow: 0 24px 70px rgba(2, 6, 23, 0.35);
        backdrop-filter: blur(18px);
        border-radius: 24px;
      }

      .contact-support-card {
        padding: 1.5rem;
        background:
          linear-gradient(135deg, rgba(34,211,238,0.13), rgba(37,99,235,0.12)),
          rgba(7,17,31,0.82);
      }

      .contact-primary-button {
        background: linear-gradient(135deg, #0891b2, #2563eb);
        box-shadow: 0 12px 34px rgba(8, 145, 178, 0.26);
      }

      .contact-card {
        animation: contact-rise 620ms cubic-bezier(0.2, 0.8, 0.2, 1) forwards;
      }

      @keyframes contact-rise {
        from { opacity: 0; transform: translateY(18px); }
        to { opacity: 1; transform: translateY(0); }
      }

      @keyframes contact-float {
        0%, 100% { transform: translate3d(0, 0, 0) rotate(-12deg); }
        50% { transform: translate3d(18px, -20px, 0) rotate(-8deg); }
      }

      @keyframes contact-grid-drift {
        from { background-position: 0 0; }
        to { background-position: 220px 180px; }
      }

      @media (max-width: 1024px) {
        .contact-navbar {
          grid-template-columns: 1fr auto;
        }

        .contact-nav-links {
          grid-column: 1 / -1;
          width: 100%;
          padding-top: 0.25rem;
          justify-content: flex-start;
        }
      }

      @media (max-width: 640px) {
        .contact-container {
          width: min(100% - 1rem, 1160px);
        }

        .contact-hero {
          padding-block: 1.5rem;
        }
      }

      @media (prefers-reduced-motion: reduce) {
        .contact-page *,
        .contact-page *::before,
        .contact-page *::after {
          animation-duration: 1ms !important;
          animation-iteration-count: 1 !important;
          transition-duration: 1ms !important;
          scroll-behavior: auto !important;
        }
      }
    `}</style>
  );
}
