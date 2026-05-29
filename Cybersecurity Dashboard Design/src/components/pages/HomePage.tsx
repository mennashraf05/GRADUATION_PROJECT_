import React, { useState } from 'react';
import { motion } from 'motion/react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Activity,
  ArrowRight,
  BarChart3,
  Book,
  CheckCircle,
  ChevronDown,
  ClipboardList,
  Eye,
  FileCheck,
  FileLock2,
  FileSearch,
  Lock,
  MailWarning,
  Menu,
  MessageCircle,
  Phone,
  Search,
  Shield,
  ShieldCheck,
  Sparkles,
  X,
} from 'lucide-react';
import { Button } from '../ui/button';
import { Card } from '../ui/card';
import { useLanguage } from '../../contexts/LanguageContext';
import { useAppSettings } from '../../contexts/AppSettingsContext';

export function HomePage() {
  const { language, isRtl } = useLanguage();
  const { applicationName } = useAppSettings();
  const navigate = useNavigate();
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [isDropdownOpen, setIsDropdownOpen] = useState(false);

  const features = [
    {
      icon: Shield,
      title: 'Password Checker',
      description: 'Check password strength, hygiene, and breach-style risk signals without exposing raw passwords in reports.',
      color: 'text-[#00D4FF]',
      glow: 'shadow-[0_0_20px_rgba(0,212,255,0.3)]',
      page: '/password-checker',
    },
    {
      icon: Eye,
      title: 'Identity Leak Monitor',
      description: 'Review identity exposure summaries safely without displaying raw leaked values.',
      color: 'text-[#FF6B8A]',
      glow: 'shadow-[0_0_20px_rgba(255,107,138,0.28)]',
      page: '/identityleak-monitor',
    },
    {
      icon: FileSearch,
      title: 'PCAP Analyzer',
      description: 'Analyze uploaded packet captures and review network alerts using privacy-safe metadata and severity summaries.',
      color: 'text-[#38BDF8]',
      glow: 'shadow-[0_0_20px_rgba(56,189,248,0.3)]',
      page: '/pcap-analyzer',
    },
    {
      icon: FileLock2,
      title: 'File Vault',
      description: 'Support safer encrypted handling of sensitive files.',
      color: 'text-[#00FF94]',
      glow: 'shadow-[0_0_20px_rgba(0,255,148,0.3)]',
      page: '/file-vault',
    },
    {
      icon: MailWarning,
      title: 'Phishing Scanner',
      description: 'Check suspicious links and phishing indicators before interacting.',
      color: 'text-[#A855F7]',
      glow: 'shadow-[0_0_20px_rgba(168,85,247,0.3)]',
      page: '/phishing-scanner',
    },
    {
      icon: ClipboardList,
      title: 'Reports Center',
      description: 'Export safe summaries for password, activity, incident, and monthly security review.',
      color: 'text-[#FBBF24]',
      glow: 'shadow-[0_0_20px_rgba(251,191,36,0.25)]',
      page: '/monthly-reports',
    },
  ];

  const valueProps = [
    {
      icon: Sparkles,
      title: 'AI-Assisted Threat Analysis',
      description: 'AI-assisted threat analysis using trained detection models and safe alert summaries.',
      color: 'text-[#A855F7]',
    },
    {
      icon: ShieldCheck,
      title: 'Privacy-Safe Reporting',
      description: 'Reports focus on safe summaries, labels, counts, timestamps, and recommendations.',
      color: 'text-[#00D4FF]',
    },
    {
      icon: Eye,
      title: 'Password & Identity Protection',
      description: 'Help users review password risk and identity exposure without publishing sensitive evidence.',
      color: 'text-[#FF6B8A]',
    },
    {
      icon: FileSearch,
      title: 'PCAP Alert Review',
      description: 'Review packet-capture alerts through metadata, severity, and supporting context.',
      color: 'text-[#38BDF8]',
    },
    {
      icon: FileCheck,
      title: 'Secure File Handling',
      description: 'Strong encryption workflows for handling sensitive files more safely.',
      color: 'text-[#00FF94]',
    },
    {
      icon: ClipboardList,
      title: 'Admin Security Review',
      description: 'High-level review workflows for reports, alerts, and user-facing security signals.',
      color: 'text-[#FBBF24]',
    },
  ];

  const dropdownFeatures = [
    { name: 'Password Checker', icon: Shield, page: '/password-checker' },
    { name: 'File Vault', icon: Lock, page: '/file-vault' },
    { name: 'Phishing Scanner', icon: MailWarning, page: '/phishing-scanner' },
    { name: 'Identity Leak Monitor', icon: Search, page: '/identityleak-monitor' },
    { name: 'PCAP Analyzer', icon: FileSearch, page: '/pcap-analyzer' },
    { name: 'Reports Center', icon: ClipboardList, page: '/monthly-reports' },
  ];

  const projectHighlights = [
    { icon: Shield, title: 'Modular Security Platform', description: 'Multiple cybersecurity workflows in one graduation project.' },
    { icon: ClipboardList, title: 'Privacy-Safe Reports', description: 'Designed to summarize risk without exposing raw secrets.' },
    { icon: Sparkles, title: 'AI-Assisted Analysis', description: 'Uses trained models and rule-based context to support review.' },
    { icon: Activity, title: 'Admin & User Workflows', description: 'Includes public learning, user tools, and review-oriented dashboards.' },
  ];

  const notificationChannels = [
    { icon: MessageCircle, title: 'In-App Notifications', status: 'Supported', description: 'Used for dashboard alerts and security updates.' },
    { icon: MailWarning, title: 'Email Alerts', status: 'Environment-configured', description: 'Available when SMTP settings are configured with environment variables.' },
  ];

  const productLinks = [
    ['Password Checker', '/password-checker'],
    ['File Vault', '/file-vault'],
    ['Phishing Scanner', '/phishing-scanner'],
    ['Identity Leak Monitor', '/identityleak-monitor'],
    ['PCAP Analyzer', '/pcap-analyzer'],
    ['Reports Center', '/monthly-reports'],
  ];

  const handleProtectedNavigate = (targetPage: string) => {
    try {
      localStorage.setItem('sentinel_intended_page', targetPage);
    } catch {
      // ignore localStorage errors
    }
    navigate('/login');
  };

  const scrollToSection = (id: string) => {
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  return (
    <div className="min-h-screen overflow-hidden bg-[#0B0F19] text-white" dir={isRtl ? 'rtl' : 'ltr'}>
      <nav className="fixed left-0 right-0 top-0 z-50 border-b border-[#374151]/30 bg-[#0B0F19]/90 backdrop-blur-md">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <button onClick={() => navigate('/')} className="flex items-center">
              <Shield className={`h-8 w-8 text-[#00D4FF] ${isRtl ? 'ml-3' : 'mr-3'}`} />
              <span className="bg-gradient-to-r from-[#00D4FF] to-[#00FF94] bg-clip-text text-2xl font-bold text-transparent">
                {applicationName}
              </span>
            </button>

            <div className="hidden items-center space-x-8 md:flex">
              <button onClick={() => navigate('/')} className="text-white transition-colors hover:text-[#00D4FF]">
                Home
              </button>
              <div className="relative">
                <button onClick={() => setIsDropdownOpen(!isDropdownOpen)} className="flex items-center text-gray-300 transition-colors hover:text-white">
                  Features
                  <ChevronDown className={`h-4 w-4 ${isRtl ? 'mr-1' : 'ml-1'} transition-transform ${isDropdownOpen ? 'rotate-180' : ''}`} />
                </button>

                {isDropdownOpen && (
                  <>
                    <div className="fixed inset-0 z-10" onClick={() => setIsDropdownOpen(false)} />
                    <motion.div
                      initial={{ opacity: 0, y: -10 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -10 }}
                      className="absolute left-0 top-full z-20 mt-2 w-72 overflow-hidden rounded-xl border border-[#374151] bg-[#111827] shadow-2xl"
                    >
                      {dropdownFeatures.map((feature) => (
                        <button
                          key={feature.page}
                          onClick={() => {
                            handleProtectedNavigate(feature.page);
                            setIsDropdownOpen(false);
                          }}
                          className="group flex w-full items-center px-4 py-3 text-left transition-colors hover:bg-[#1F2937]"
                        >
                          <feature.icon className={`h-5 w-5 text-[#00D4FF] ${isRtl ? 'ml-3' : 'mr-3'} transition-colors group-hover:text-[#00FF94]`} />
                          <span className="text-gray-300 transition-colors group-hover:text-white">{feature.name}</span>
                        </button>
                      ))}
                    </motion.div>
                  </>
                )}
              </div>
              <button onClick={() => handleProtectedNavigate('/dashboard')} className="text-gray-300 transition-colors hover:text-white">
                Dashboard
              </button>
              <button onClick={() => navigate('/learn')} className="flex items-center text-gray-300 transition-colors hover:text-white">
                <Book className={`h-4 w-4 ${isRtl ? 'ml-1' : 'mr-1'}`} />
                Learn
              </button>
              <button onClick={() => navigate('/about')} className="text-gray-300 transition-colors hover:text-white">
                About
              </button>
              <button onClick={() => navigate('/contact')} className="flex items-center text-gray-300 transition-colors hover:text-white">
                <Phone className={`h-4 w-4 ${isRtl ? 'ml-1' : 'mr-1'}`} />
                Contact
              </button>
              <button onClick={() => navigate('/admin/login')} className="text-gray-300 transition-colors hover:text-white">
                Admin
              </button>
            </div>

            <div className="hidden items-center space-x-4 md:flex">
              <Button onClick={() => navigate('/login')} variant="ghost" className="text-gray-300 transition-colors hover:bg-[#1F2937] hover:text-white">
                Login
              </Button>
              <Button onClick={() => navigate('/signup')} className="bg-gradient-to-r from-[#00D4FF] to-[#00FF94] px-6 py-2 text-black transition-all duration-300 hover:shadow-[0_0_20px_rgba(0,212,255,0.4)]">
                Sign Up
              </Button>
            </div>

            <button onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)} className="text-white md:hidden">
              {isMobileMenuOpen ? <X className="h-6 w-6" /> : <Menu className="h-6 w-6" />}
            </button>
          </div>

          {isMobileMenuOpen && (
            <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} className="mt-4 border-t border-[#374151] pb-4 pt-4 md:hidden">
              <div className="space-y-4">
                {[
                  ['Home', '/'],
                  ['Features', '/features'],
                  ['Dashboard', '/dashboard'],
                  ['Learn', '/learn'],
                  ['About', '/about'],
                  ['Contact', '/contact'],
                  ['Admin', '/admin/login'],
                ].map(([label, route]) => (
                  <button
                    key={route}
                    onClick={() => {
                      if (route === '/dashboard') handleProtectedNavigate(route);
                      else navigate(route);
                      setIsMobileMenuOpen(false);
                    }}
                    className="block text-gray-300 transition-colors hover:text-white"
                  >
                    {label}
                  </button>
                ))}
                <div className="space-y-2 pt-4">
                  <Button onClick={() => navigate('/login')} variant="ghost" className="w-full text-gray-300 hover:bg-[#1F2937] hover:text-white">
                    Login
                  </Button>
                  <Button onClick={() => navigate('/signup')} className="w-full bg-gradient-to-r from-[#00D4FF] to-[#00FF94] text-black">
                    Sign Up
                  </Button>
                </div>
              </div>
            </motion.div>
          )}
        </div>
      </nav>

      <div className="pointer-events-none fixed inset-0 opacity-10">
        <div
          className="absolute inset-0"
          style={{
            backgroundImage: `
              linear-gradient(rgba(59, 130, 246, 0.1) 1px, transparent 1px),
              linear-gradient(90deg, rgba(59, 130, 246, 0.1) 1px, transparent 1px)
            `,
            backgroundSize: '50px 50px',
          }}
        />
      </div>

      <section className="relative flex min-h-screen items-center justify-center px-4 pb-20 pt-32">
        <div className="container relative z-10 mx-auto max-w-6xl text-center">
          <motion.div
            className="absolute inset-0 flex items-center justify-center opacity-5"
            animate={{ rotate: 360 }}
            transition={{ duration: 60, repeat: Infinity, ease: 'linear' }}
          >
            <Shield className="h-96 w-96 text-[#00D4FF]" />
          </motion.div>

          <motion.div initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.8 }} className="relative z-20">
            <motion.div
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              transition={{ delay: 0.2, duration: 0.5 }}
              className="mb-8 inline-flex items-center rounded-full border border-[#00D4FF]/30 bg-gradient-to-r from-[#00D4FF]/20 to-[#00FF94]/20 px-4 py-2"
            >
              <Sparkles className={`h-4 w-4 ${isRtl ? 'ml-2' : 'mr-2'} text-[#00D4FF]`} />
              <span className="text-sm">Cybersecurity graduation project platform</span>
            </motion.div>

            <h1 className="mb-6 bg-gradient-to-r from-white via-[#00D4FF] to-[#00FF94] bg-clip-text text-5xl font-bold text-transparent md:text-7xl">
              Protect Your Digital World with {applicationName}
            </h1>

            <p className="mx-auto mb-12 max-w-4xl text-xl leading-relaxed text-gray-300 md:text-2xl">
              A graduation-project cybersecurity platform for password safety, phishing awareness, identity exposure review, secure file handling, PCAP analysis, and privacy-safe reporting.
            </p>

            <div className="flex flex-col items-center justify-center gap-6 sm:flex-row">
              <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
                <Button onClick={() => navigate('/signup')} className="bg-gradient-to-r from-[#00D4FF] to-[#00FF94] px-8 py-4 text-black transition-all duration-300 hover:shadow-[0_0_30px_rgba(0,212,255,0.5)]" size="lg">
                  Get Started
                  <ArrowRight className={`${isRtl ? 'mr-2' : 'ml-2'} h-5 w-5`} />
                </Button>
              </motion.div>

              <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
                <Button onClick={() => scrollToSection('dashboard-preview')} variant="outline" className="border-[#00D4FF] px-8 py-4 text-[#00D4FF] transition-all duration-300 hover:bg-[#00D4FF]/10 hover:shadow-[0_0_20px_rgba(0,212,255,0.3)]" size="lg">
                  Explore Platform
                </Button>
              </motion.div>
            </div>
          </motion.div>
        </div>

        <div className="absolute inset-0 overflow-hidden">
          {[...Array(20)].map((_, i) => (
            <motion.div
              key={i}
              className="absolute h-1 w-1 rounded-full bg-[#00D4FF] opacity-30"
              style={{ left: `${(i * 37) % 100}%`, top: `${(i * 53) % 100}%` }}
              animate={{ y: [-10, 10, -10], opacity: [0.3, 0.8, 0.3] }}
              transition={{ duration: 3 + (i % 3), repeat: Infinity, delay: (i % 5) * 0.3 }}
            />
          ))}
        </div>
      </section>

      <section id="security-suite" className="relative px-4 py-20">
        <div className="container mx-auto max-w-6xl">
          <motion.div initial={{ opacity: 0, y: 30 }} whileInView={{ opacity: 1, y: 0 }} transition={{ duration: 0.8 }} viewport={{ once: true }} className="mb-16 text-center">
            <h2 className="mb-6 bg-gradient-to-r from-white to-[#00D4FF] bg-clip-text text-4xl font-bold text-transparent md:text-5xl">
              Security Suite
            </h2>
            <p className="mx-auto max-w-3xl text-xl text-gray-300">
              Practical cybersecurity modules built for demonstration, learning, and safer review workflows.
            </p>
          </motion.div>

          <div className="grid gap-8 md:grid-cols-2 lg:grid-cols-3">
            {features.map((feature, index) => (
              <motion.div key={feature.title} initial={{ opacity: 0, y: 30 }} whileInView={{ opacity: 1, y: 0 }} transition={{ duration: 0.6, delay: index * 0.08 }} viewport={{ once: true }} whileHover={{ y: -10 }}>
                <Card className="group h-full border-[#374151] bg-gradient-to-br from-[#111827] to-[#1F2937] p-6 transition-all duration-300 hover:border-[#00D4FF]/50 hover:shadow-[0_0_30px_rgba(0,212,255,0.2)]">
                  <div className={`mb-6 inline-flex rounded-2xl bg-[#0B0F19] p-4 ${feature.glow}`}>
                    <feature.icon className={`h-8 w-8 ${feature.color}`} />
                  </div>
                  <h3 className="mb-4 text-2xl font-bold text-white">{feature.title}</h3>
                  <p className="mb-6 leading-relaxed text-gray-300">{feature.description}</p>
                  <Button onClick={() => handleProtectedNavigate(feature.page)} variant="ghost" className={`${feature.color} p-0 hover:bg-transparent hover:text-white`}>
                    Open Module
                    <ArrowRight className={`${isRtl ? 'mr-2' : 'ml-2'} h-4 w-4 transition-transform group-hover:translate-x-1`} />
                  </Button>
                </Card>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      <section id="dashboard-preview" className="relative bg-gradient-to-br from-[#111827]/50 to-[#1F2937]/50 px-4 py-20">
        <div className="container mx-auto max-w-6xl">
          <div className="grid items-center gap-12 lg:grid-cols-2">
            <motion.div initial={{ opacity: 0, x: -30 }} whileInView={{ opacity: 1, x: 0 }} transition={{ duration: 0.8 }} viewport={{ once: true }}>
              <h2 className="mb-6 bg-gradient-to-r from-white to-[#00FF94] bg-clip-text text-4xl font-bold text-transparent md:text-5xl">
                All Your Security Insights in One Place
              </h2>
              <p className="mb-8 text-xl leading-relaxed text-gray-300">
                The dashboard preview brings together security score, alert sources, trends, password risk, identity findings, PCAP alerts, and safe reports in one demo-ready workspace.
              </p>
              <div className="grid gap-4 sm:grid-cols-2">
                {[
                  'Security Score',
                  'Alert Sources',
                  'Alerts Over Time',
                  'Password Risk Summary',
                  'Identity Findings',
                  'PCAP Alerts',
                  'Safe Reports',
                ].map((item) => (
                  <div key={item} className="flex items-center">
                    <CheckCircle className={`h-5 w-5 text-[#00FF94] ${isRtl ? 'ml-3' : 'mr-3'}`} />
                    <span className="text-gray-300">{item}</span>
                  </div>
                ))}
              </div>
            </motion.div>

            <motion.div initial={{ opacity: 0, x: 30 }} whileInView={{ opacity: 1, x: 0 }} transition={{ duration: 0.8 }} viewport={{ once: true }} className="relative">
              <div className="rounded-3xl border border-[#374151] bg-gradient-to-br from-[#111827] to-[#1F2937] p-6 shadow-2xl">
                <div className="mb-6 flex items-center justify-between">
                  <h3 className="text-2xl font-bold text-white">Dashboard Preview</h3>
                  <div className="flex space-x-2">
                    <div className="h-3 w-3 rounded-full bg-[#FF3B71]" />
                    <div className="h-3 w-3 rounded-full bg-[#FFD600]" />
                    <div className="h-3 w-3 rounded-full bg-[#00FF94]" />
                  </div>
                </div>
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <PreviewCard icon={ShieldCheck} label="Security Score" value="Demo metric" color="text-[#00D4FF]" />
                    <PreviewCard icon={Activity} label="Alert Sources" value="Password, PCAP, Identity" color="text-[#00FF94]" />
                  </div>
                  <div className="rounded-xl bg-[#0B0F19] p-4">
                    <div className="mb-3 flex items-center justify-between">
                      <span className="text-gray-300">Alerts Over Time</span>
                      <span className="text-sm text-gray-500">Demo UI</span>
                    </div>
                    <div className="flex h-24 items-end space-x-2">
                      {[40, 65, 35, 82, 58, 74, 48].map((height, i) => (
                        <motion.div
                          key={i}
                          className="flex-1 rounded-t bg-gradient-to-t from-[#00D4FF] to-[#00FF94]"
                          initial={{ height: 0 }}
                          whileInView={{ height: `${height}%` }}
                          transition={{ duration: 0.8, delay: i * 0.1 }}
                          viewport={{ once: true }}
                        />
                      ))}
                    </div>
                  </div>
                  <div className="grid grid-cols-3 gap-3">
                    {['Password Risk', 'Identity Findings', 'PCAP Alerts'].map((label) => (
                      <div key={label} className="rounded-xl bg-[#0B0F19] p-3 text-center">
                        <div className="mb-1 text-sm font-semibold text-white">{label}</div>
                        <div className="text-xs text-gray-500">Safe summary</div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </motion.div>
          </div>
        </div>
      </section>

      <section className="relative px-4 py-20">
        <div className="container mx-auto max-w-6xl">
          <motion.div initial={{ opacity: 0, y: 30 }} whileInView={{ opacity: 1, y: 0 }} transition={{ duration: 0.8 }} viewport={{ once: true }} className="mb-16 text-center">
            <h2 className="mb-6 bg-gradient-to-r from-white to-[#A855F7] bg-clip-text text-4xl font-bold text-transparent md:text-5xl">
              Why Choose {applicationName}
            </h2>
            <p className="mx-auto max-w-3xl text-xl text-gray-300">
              Designed for academic demonstration, security awareness, and practical cybersecurity workflows.
            </p>
          </motion.div>

          <div className="grid gap-8 md:grid-cols-2 lg:grid-cols-3">
            {valueProps.map((prop, index) => (
              <motion.div key={prop.title} initial={{ opacity: 0, y: 30 }} whileInView={{ opacity: 1, y: 0 }} transition={{ duration: 0.6, delay: index * 0.08 }} viewport={{ once: true }} className="text-center">
                <div className="rounded-3xl border border-[#374151] bg-gradient-to-br from-[#111827] to-[#1F2937] p-8 transition-all duration-300 hover:border-[#00D4FF]/50 hover:shadow-[0_0_30px_rgba(0,212,255,0.2)]">
                  <prop.icon className={`mx-auto mb-6 h-12 w-12 ${prop.color}`} />
                  <h3 className="mb-4 text-2xl font-bold text-white">{prop.title}</h3>
                  <p className="text-lg leading-relaxed text-gray-300">{prop.description}</p>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      <section className="relative px-4 py-20">
        <div className="container mx-auto max-w-6xl text-center">
          <motion.div initial={{ opacity: 0, y: 30 }} whileInView={{ opacity: 1, y: 0 }} transition={{ duration: 0.8 }} viewport={{ once: true }}>
            <h2 className="mb-4 bg-gradient-to-r from-white to-[#00D4FF] bg-clip-text text-3xl font-bold text-transparent md:text-4xl">
              Built as a cybersecurity graduation project
            </h2>
            <p className="mx-auto mb-10 max-w-3xl text-lg text-gray-300">
              Designed for academic demonstration, security awareness, and practical cybersecurity workflows.
            </p>
            <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
              {projectHighlights.map((item, index) => (
                <motion.div key={item.title} initial={{ opacity: 0, y: 30 }} whileInView={{ opacity: 1, y: 0 }} transition={{ duration: 0.6, delay: index * 0.08 }} viewport={{ once: true }}>
                  <div className="h-full rounded-2xl border border-[#374151] bg-gradient-to-br from-[#111827] to-[#1F2937] p-6 transition-all duration-300 hover:border-[#00D4FF]/50">
                    <item.icon className="mx-auto mb-4 h-10 w-10 text-[#00D4FF]" />
                    <div className="mb-2 text-lg font-bold text-white">{item.title}</div>
                    <div className="text-sm leading-6 text-gray-300">{item.description}</div>
                  </div>
                </motion.div>
              ))}
            </div>
          </motion.div>
        </div>
      </section>

      <section className="bg-gradient-to-br from-[#111827]/50 to-[#1F2937]/50 px-4 py-16">
        <div className="container mx-auto max-w-6xl">
          <motion.div initial={{ opacity: 0, y: 30 }} whileInView={{ opacity: 1, y: 0 }} transition={{ duration: 0.8 }} viewport={{ once: true }} className="mb-10 text-center">
            <h2 className="mb-4 bg-gradient-to-r from-white to-[#00D4FF] bg-clip-text text-3xl font-bold text-transparent md:text-4xl">
              Notification Channels
            </h2>
            <p className="text-gray-400">Shown according to implemented or safely configurable project capabilities.</p>
          </motion.div>
          <div className="mx-auto grid max-w-4xl gap-6 md:grid-cols-2">
            {notificationChannels.map((channel) => (
              <div key={channel.title} className="rounded-2xl border border-[#374151] bg-[#111827] p-5">
                <channel.icon className="mb-4 h-8 w-8 text-[#00D4FF]" />
                <div className="flex items-center justify-between gap-3">
                  <h3 className="font-semibold text-white">{channel.title}</h3>
                  <span className="rounded-full border border-[#00D4FF]/25 bg-[#00D4FF]/10 px-2.5 py-1 text-xs text-[#A5F3FC]">{channel.status}</span>
                </div>
                <p className="mt-3 text-sm leading-6 text-gray-400">{channel.description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="relative px-4 py-20">
        <div className="container mx-auto max-w-4xl">
          <motion.div initial={{ opacity: 0, scale: 0.9 }} whileInView={{ opacity: 1, scale: 1 }} transition={{ duration: 0.8 }} viewport={{ once: true }} className="relative overflow-hidden rounded-3xl border border-[#374151] bg-gradient-to-br from-[#111827] to-[#1F2937] p-12 text-center">
            <div className="absolute inset-0 bg-gradient-to-r from-[#00D4FF]/10 via-transparent to-[#00FF94]/10" />
            <div className="relative z-10">
              <h2 className="mb-6 bg-gradient-to-r from-white via-[#00D4FF] to-[#00FF94] bg-clip-text text-4xl font-bold text-transparent md:text-5xl">
                Ready to Explore {applicationName}?
              </h2>
              <p className="mx-auto mb-10 max-w-2xl text-xl text-gray-300">
                Start checking passwords, learning phishing safety, reviewing identity exposure, and exploring privacy-safe security reports.
              </p>
              <div className="flex flex-col items-center justify-center gap-4 sm:flex-row">
                <Button onClick={() => navigate('/signup')} className="bg-gradient-to-r from-[#00D4FF] to-[#00FF94] px-10 py-4 text-lg text-black transition-all duration-300 hover:shadow-[0_0_40px_rgba(0,212,255,0.6)]" size="lg">
                  Get Started
                  <ArrowRight className="ml-2 h-6 w-6" />
                </Button>
                <Button onClick={() => navigate('/learn')} variant="outline" className="border-[#00D4FF] px-10 py-4 text-lg text-[#00D4FF] hover:bg-[#00D4FF]/10" size="lg">
                  Learn Cyber Safety
                </Button>
              </div>
            </div>
          </motion.div>
        </div>
      </section>

      <footer className="relative z-20 border-t border-[#374151] bg-gradient-to-br from-[#0B0F19] to-[#111827] px-4 py-16">
        <div className="container mx-auto max-w-6xl">
          <div className="mb-12 grid gap-8 md:grid-cols-4">
            <FooterColumn title="PRODUCT">
              {productLinks.map(([label, route]) => (
                <FooterLink key={route} to={route}>
                  {label}
                </FooterLink>
              ))}
            </FooterColumn>

            <FooterColumn title="RESOURCES">
              <FooterLink to="/learn">
                Learn Cyber Safety
              </FooterLink>
              <FooterLink to="/contact">
                FAQs
              </FooterLink>
            </FooterColumn>

            <FooterColumn title="COMPANY">
              <FooterLink to="/about">
                About
              </FooterLink>
              <FooterLink to="/contact">
                Contact & Support
              </FooterLink>
            </FooterColumn>

            <FooterColumn title="SECURITY">
              <FooterLink to="/about">
                Security Principles
              </FooterLink>
              <FooterLink to="/about">
                Privacy-safe summaries
              </FooterLink>
              <FooterLink to="/learn">
                No raw passwords in reports
              </FooterLink>
            </FooterColumn>
          </div>

          <div className="border-t border-[#374151] pt-8">
            <div className="flex flex-col items-center justify-between md:flex-row">
              <div className="mb-4 flex items-center md:mb-0">
                <Shield className="mr-3 h-8 w-8 text-[#00D4FF]" />
                <div>
                  <span className="bg-gradient-to-r from-[#00D4FF] to-[#00FF94] bg-clip-text text-2xl font-bold text-transparent">
                    {applicationName}
                  </span>
                  <p className="mt-1 text-sm text-gray-400">
                    © 2025 {applicationName}. Graduation project cybersecurity platform.
                  </p>
                </div>
              </div>
            </div>
          </div>

          <div className="mt-8 text-center">
            <div className="inline-flex items-center rounded-full border border-[#00D4FF]/20 bg-gradient-to-r from-[#00D4FF]/10 to-[#00FF94]/10 px-4 py-2">
              <Lock className="mr-2 h-4 w-4 text-[#00D4FF]" />
              <span className="text-sm text-gray-300">Designed around privacy-safe summaries and practical cybersecurity workflows.</span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}

function PreviewCard({
  icon: Icon,
  label,
  value,
  color,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: string;
  color: string;
}) {
  return (
    <div className="rounded-xl bg-[#0B0F19] p-4">
      <Icon className={`mb-2 h-6 w-6 ${color}`} />
      <div className="text-sm text-gray-400">{label}</div>
      <div className="font-bold text-white">{value}</div>
    </div>
  );
}

function FooterColumn({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="mb-6 text-lg font-bold text-white">{title}</h3>
      <div className="space-y-4">{children}</div>
    </div>
  );
}

function FooterLink({ children, to }: { children: React.ReactNode; to: string }) {
  return (
    <Link
      to={to}
      className="group inline-flex w-fit cursor-pointer items-center gap-2 rounded-lg border border-[#00D4FF]/15 bg-[#00D4FF]/5 px-3 py-2 text-left text-[#B8D8F2] underline-offset-4 transition-all duration-300 hover:-translate-y-0.5 hover:border-[#00D4FF]/45 hover:bg-[#00D4FF]/12 hover:text-white hover:shadow-[0_0_18px_rgba(0,212,255,0.16)] focus:outline-none focus:ring-2 focus:ring-[#00D4FF]/50"
    >
      <span className="border-b border-[#00D4FF]/35 pb-0.5 group-hover:border-white/70">{children}</span>
      <ArrowRight className="h-3.5 w-3.5 text-[#00D4FF] transition-transform group-hover:translate-x-1" />
    </Link>
  );
}
