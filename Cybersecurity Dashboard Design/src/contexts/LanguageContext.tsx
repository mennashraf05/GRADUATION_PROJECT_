import React, { createContext, useContext, useEffect, useMemo, useState } from "react";

export type SupportedLanguage = "english" | "arabic";

type TranslationParams = Record<string, string | number>;
type TranslationValue = string | ((params?: TranslationParams) => string);

type FormatDateOptions = Intl.DateTimeFormatOptions & {
  fallback?: string;
};

type LanguageContextValue = {
  language: SupportedLanguage;
  locale: string;
  setLanguage: (language: SupportedLanguage) => void;
  t: (key: string, params?: TranslationParams) => string;
  isRtl: boolean;
  formatDate: (
    value: string | number | Date | null | undefined,
    options?: FormatDateOptions
  ) => string;
  formatDateTime: (
    value: string | number | Date | null | undefined,
    options?: FormatDateOptions
  ) => string;
  formatNumber: (value: number, options?: Intl.NumberFormatOptions) => string;
};

const LANGUAGE_STORAGE_KEY = "sentinel_language";

const localeByLanguage: Record<SupportedLanguage, string> = {
  english: "en-US",
  arabic: "ar",
};

const translations: Record<SupportedLanguage, Record<string, TranslationValue>> = {
  english: {
    "layout.brandSubtitle": "Cybersecurity Platform",
    "layout.nav.dashboard": "Dashboard",
    "layout.nav.passwordChecker": "Password Checker",
    "layout.nav.fileVault": "File Vault",
    "layout.nav.phishingScanner": "Phishing Scanner",
    "layout.nav.identityLeakMonitor": "Identity Leak Monitor",
    "layout.nav.aiThreatDetector": "AI Threat Detector",
    "layout.nav.pcapAnalyzer": "PCAP Analyzer",
    "layout.nav.chatbot": "Chatbot",
    "layout.nav.settings": "Settings",
    "layout.userFallbackName": "Active Account",
    "layout.userFallbackSession": "Authenticated session",
    "layout.logout": "Logout",

    "settings.headerTitle": "Settings",
    "settings.headerDescription": "Manage your account and security preferences",
    "settings.profile.title": "Profile Information",
    "settings.profile.fullName": "Full Name",
    "settings.profile.email": "Email Address",
    "settings.profile.jobTitle": "Job Title",
    "settings.profile.company": "Company",
    "settings.profile.update": "Update Profile",
    "settings.security.title": "Security Settings",
    "settings.security.twoFactor": "Two-Factor Authentication",
    "settings.security.twoFactorDesc": "Add an extra layer of security to your account",
    "settings.security.autoLock": "Auto-lock (minutes)",
    "settings.security.autoLockDesc": "Automatically lock screen after inactivity",
    "settings.security.sessionTimeout": "Session Timeout (minutes)",
    "settings.security.sessionTimeoutDesc": "Automatically sign out after inactivity",
    "settings.notifications.title": "Notification Preferences",
    "settings.notifications.email": "Email Alerts",
    "settings.notifications.emailDesc": "Receive security alerts via email",
    "settings.notifications.push": "Push Notifications",
    "settings.notifications.pushDesc": "Browser push notifications",
    "settings.notifications.weekly": "Weekly Reports",
    "settings.notifications.weeklyDesc": "Weekly security summary reports",
    "settings.language.title": "Language",
    "settings.language.interface": "Interface Language",
    "settings.language.english": "English",
    "settings.language.arabic": "Arabic",
    "settings.channels.title": "Notification Channels",
    "settings.channels.add": "Add Channel",
    "settings.accounts.title": "Multi-Account Management",
    "settings.accounts.add": "Add Account",
    "settings.accounts.email": "Email",
    "settings.accounts.type": "Type",
    "settings.accounts.status": "Status",
    "settings.accounts.twoFactor": "2FA",
    "settings.accounts.lastAccess": "Last Access",
    "settings.accounts.actions": "Actions",
    "settings.accountType.primary": "Primary",
    "settings.accountType.secondary": "Secondary",
    "settings.accountType.work": "Work",
    "settings.status.verified": "Verified",
    "settings.status.pending": "Pending",
    "settings.status.unknown": "Unknown",
    "settings.misc.never": "Never",
    "settings.channel.email": "Email",
    "settings.channel.telegram": "Telegram",
    "settings.time.minutes": ({ value }) => `${value} min`,
    "settings.time.hour": ({ value }) => `${value} hour`,
    "settings.time.hours": ({ value }) => `${value} hours`,

    "dashboard.headerTitle": "Security Dashboard",
    "dashboard.headerDescription": "Real-time cybersecurity monitoring and analytics",
    "dashboard.securityScore": "Security Score",
    "dashboard.fromLastWeek": "+2% from last week",
    "dashboard.activeMonitoring": "Active Monitoring",
    "dashboard.realTimeProtection": "Real-time protection",
    "dashboard.protectedAssets": "Protected Assets",
    "dashboard.devicesAccounts": "Devices & accounts",
    "dashboard.threatDistribution": "Threat Distribution",
    "dashboard.weeklyThreatStatistics": "Weekly Threat Statistics",
    "dashboard.systemPerformance": "System Performance",
    "dashboard.threatsDetected": "Threats Detected",
    "dashboard.threatsBlocked": "Threats Blocked",
    "dashboard.cpuPercent": "CPU %",
    "dashboard.memoryPercent": "Memory %",
    "dashboard.networkPercent": "Network %",
    "dashboard.day.mon": "Mon",
    "dashboard.day.tue": "Tue",
    "dashboard.day.wed": "Wed",
    "dashboard.day.thu": "Thu",
    "dashboard.day.fri": "Fri",
    "dashboard.day.sat": "Sat",
    "dashboard.day.sun": "Sun",
    "dashboard.threat.malware": "Malware",
    "dashboard.threat.phishing": "Phishing",
    "dashboard.threat.ransomware": "Ransomware",
    "dashboard.threat.dataBreach": "Data Breach",
    "dashboard.threat.safe": "Safe",

    "login2fa.sessionExpired": "Your 2FA login session has expired. Please sign in again.",
    "login2fa.invalidServerResponse": "Invalid server response. Make sure the backend is running.",
    "login2fa.invalidCode": "Invalid 2FA code",
    "login2fa.cannotConnect": "Cannot connect to server. Make sure the backend is running.",
    "login2fa.genericError": "Something went wrong. Please try again.",
    "login2fa.title": "Two-Factor Authentication",
    "login2fa.description": ({ email }) =>
      `Enter the 6-digit code from your authenticator app to complete sign-in for ${email}.`,
    "login2fa.codeLabel": "2FA Code",
    "login2fa.codePlaceholder": "Enter 6-digit code",
    "login2fa.verifying": "Verifying...",
    "login2fa.completeSignIn": "Complete Sign-In",

    "riskPerIp.title": "Risk per IP",
    "riskPerIp.subtitle": "IPs contributing most to current analysis risk",
    "riskPerIp.badgeCount": ({ count }) => `${count} IPs`,
    "riskPerIp.noIpData": "No IP data",
    "riskPerIp.mostExposedIp": "Most Exposed IP",
    "riskPerIp.noRankedIps": "No ranked IPs",
    "riskPerIp.noDominantLabel": "no dominant label",
    "riskPerIp.mostExposedDescription": ({ score, label }) =>
      `${score} risk score with ${label}.`,
    "riskPerIp.mostExposedEmpty":
      "Per-IP risk ranking will appear after the analyzer scores network entities.",
    "riskPerIp.highestConfidence": "Highest Confidence",
    "riskPerIp.highestConfidenceDescription": ({ ip }) =>
      `${ip} carries the strongest current confidence signal.`,
    "riskPerIp.highestConfidenceEmpty":
      "Confidence bars will populate when IP-level evidence is available.",
    "riskPerIp.elevatedRiskEntities": "Elevated Risk Entities",
    "riskPerIp.elevatedRiskDescription":
      "IPs currently associated with high or critical promoted findings.",
    "riskPerIp.table.ip": "IP",
    "riskPerIp.table.role": "Role",
    "riskPerIp.table.threats": "Threats",
    "riskPerIp.table.topSeverity": "Top Severity",
    "riskPerIp.table.confidence": "Confidence",
    "riskPerIp.table.riskScore": "Risk Score",
    "riskPerIp.table.topAttack": "Top Attack",
    "riskPerIp.emptyTitle": "No IP risk data available for this analysis.",
    "riskPerIp.emptyDescription":
      "Risk scoring details will appear after the analyzer evaluates source and destination entities.",
    "riskPerIp.awaitingDominantLabel": "Awaiting dominant label",
    "riskPerIp.suspiciousCount": ({ count }) => `${count} suspicious`,
    "riskPerIp.unknownThreat": "Unknown threat",
    "riskPerIp.topAttackHelp": "Primary observed label for this entity.",
    "riskPerIp.role.source": "Source",
    "riskPerIp.role.destination": "Destination",
    "riskPerIp.role.both": "Both",
    "riskPerIp.severity.low": "Low",
    "riskPerIp.severity.medium": "Medium",
    "riskPerIp.severity.high": "High",
    "riskPerIp.severity.critical": "Critical",
  },
  arabic: {
    "layout.brandSubtitle": "منصة الأمن السيبراني",
    "layout.nav.dashboard": "لوحة التحكم",
    "layout.nav.passwordChecker": "فاحص كلمات المرور",
    "layout.nav.fileVault": "خزنة الملفات",
    "layout.nav.phishingScanner": "فاحص التصيد",
    "layout.nav.identityLeakMonitor": "مراقبة تسرب الهوية",
    "layout.nav.aiThreatDetector": "كاشف التهديدات بالذكاء الاصطناعي",
    "layout.nav.pcapAnalyzer": "محلل PCAP",
    "layout.nav.chatbot": "المساعد",
    "layout.nav.settings": "الإعدادات",
    "layout.userFallbackName": "الحساب النشط",
    "layout.userFallbackSession": "جلسة موثقة",
    "layout.logout": "تسجيل الخروج",

    "settings.headerTitle": "الإعدادات",
    "settings.headerDescription": "إدارة الحساب وتفضيلات الأمان",
    "settings.profile.title": "معلومات الملف الشخصي",
    "settings.profile.fullName": "الاسم الكامل",
    "settings.profile.email": "البريد الإلكتروني",
    "settings.profile.jobTitle": "المسمى الوظيفي",
    "settings.profile.company": "الشركة",
    "settings.profile.update": "تحديث الملف الشخصي",
    "settings.security.title": "إعدادات الأمان",
    "settings.security.twoFactor": "المصادقة الثنائية",
    "settings.security.twoFactorDesc": "أضف طبقة حماية إضافية إلى حسابك",
    "settings.security.autoLock": "القفل التلقائي (بالدقائق)",
    "settings.security.autoLockDesc": "قفل الشاشة تلقائيًا بعد عدم النشاط",
    "settings.security.sessionTimeout": "مهلة الجلسة (بالدقائق)",
    "settings.security.sessionTimeoutDesc": "تسجيل الخروج تلقائيًا بعد عدم النشاط",
    "settings.notifications.title": "تفضيلات الإشعارات",
    "settings.notifications.email": "تنبيهات البريد",
    "settings.notifications.emailDesc": "استلام تنبيهات الأمان عبر البريد الإلكتروني",
    "settings.notifications.push": "إشعارات المتصفح",
    "settings.notifications.pushDesc": "إشعارات فورية داخل المتصفح",
    "settings.notifications.weekly": "تقارير أسبوعية",
    "settings.notifications.weeklyDesc": "ملخصات أسبوعية عن حالة الأمان",
    "settings.language.title": "اللغة",
    "settings.language.interface": "لغة الواجهة",
    "settings.language.english": "English",
    "settings.language.arabic": "العربية",
    "settings.channels.title": "قنوات الإشعارات",
    "settings.channels.add": "إضافة قناة",
    "settings.accounts.title": "إدارة الحسابات المتعددة",
    "settings.accounts.add": "إضافة حساب",
    "settings.accounts.email": "البريد الإلكتروني",
    "settings.accounts.type": "النوع",
    "settings.accounts.status": "الحالة",
    "settings.accounts.twoFactor": "2FA",
    "settings.accounts.lastAccess": "آخر دخول",
    "settings.accounts.actions": "الإجراءات",
    "settings.accountType.primary": "أساسي",
    "settings.accountType.secondary": "ثانوي",
    "settings.accountType.work": "العمل",
    "settings.status.verified": "موثق",
    "settings.status.pending": "قيد الانتظار",
    "settings.status.unknown": "غير معروف",
    "settings.misc.never": "أبدًا",
    "settings.channel.email": "البريد الإلكتروني",
    "settings.channel.telegram": "تيليجرام",
    "settings.time.minutes": ({ value }) => `${value} دقيقة`,
    "settings.time.hour": ({ value }) => `${value} ساعة`,
    "settings.time.hours": ({ value }) => `${value} ساعات`,

    "dashboard.headerTitle": "لوحة الأمن",
    "dashboard.headerDescription": "مراقبة وتحليلات الأمن السيبراني في الوقت الفعلي",
    "dashboard.securityScore": "درجة الأمان",
    "dashboard.fromLastWeek": "+2% مقارنة بالأسبوع الماضي",
    "dashboard.activeMonitoring": "مراقبة نشطة",
    "dashboard.realTimeProtection": "حماية لحظية",
    "dashboard.protectedAssets": "الأصول المحمية",
    "dashboard.devicesAccounts": "الأجهزة والحسابات",
    "dashboard.threatDistribution": "توزيع التهديدات",
    "dashboard.weeklyThreatStatistics": "إحصاءات التهديدات الأسبوعية",
    "dashboard.systemPerformance": "أداء النظام",
    "dashboard.threatsDetected": "التهديدات المكتشفة",
    "dashboard.threatsBlocked": "التهديدات المحجوبة",
    "dashboard.cpuPercent": "المعالج %",
    "dashboard.memoryPercent": "الذاكرة %",
    "dashboard.networkPercent": "الشبكة %",
    "dashboard.day.mon": "الاثنين",
    "dashboard.day.tue": "الثلاثاء",
    "dashboard.day.wed": "الأربعاء",
    "dashboard.day.thu": "الخميس",
    "dashboard.day.fri": "الجمعة",
    "dashboard.day.sat": "السبت",
    "dashboard.day.sun": "الأحد",
    "dashboard.threat.malware": "برمجيات خبيثة",
    "dashboard.threat.phishing": "تصيد",
    "dashboard.threat.ransomware": "فدية",
    "dashboard.threat.dataBreach": "اختراق بيانات",
    "dashboard.threat.safe": "آمن",

    "login2fa.sessionExpired": "انتهت جلسة تسجيل الدخول بالمصادقة الثنائية. يرجى تسجيل الدخول مرة أخرى.",
    "login2fa.invalidServerResponse": "استجابة الخادم غير صالحة. تأكد من أن الخادم الخلفي يعمل.",
    "login2fa.invalidCode": "رمز المصادقة الثنائية غير صحيح",
    "login2fa.cannotConnect": "تعذر الاتصال بالخادم. تأكد من أن الخادم الخلفي يعمل.",
    "login2fa.genericError": "حدث خطأ ما. يرجى المحاولة مرة أخرى.",
    "login2fa.title": "المصادقة الثنائية",
    "login2fa.description": ({ email }) =>
      `أدخل الرمز المكون من 6 أرقام من تطبيق المصادقة لإكمال تسجيل الدخول للحساب ${email}.`,
    "login2fa.codeLabel": "رمز 2FA",
    "login2fa.codePlaceholder": "أدخل الرمز المكون من 6 أرقام",
    "login2fa.verifying": "جارٍ التحقق...",
    "login2fa.completeSignIn": "إكمال تسجيل الدخول",

    "riskPerIp.title": "المخاطر لكل عنوان IP",
    "riskPerIp.subtitle": "عناوين IP الأكثر مساهمة في مخاطر التحليل الحالي",
    "riskPerIp.badgeCount": ({ count }) => `${count} عنوان IP`,
    "riskPerIp.noIpData": "لا توجد بيانات IP",
    "riskPerIp.mostExposedIp": "أكثر عنوان مكشوف",
    "riskPerIp.noRankedIps": "لا توجد عناوين مصنفة",
    "riskPerIp.noDominantLabel": "لا توجد تسمية مهيمنة",
    "riskPerIp.mostExposedDescription": ({ score, label }) =>
      `درجة المخاطر ${score} مع ${label}.`,
    "riskPerIp.mostExposedEmpty":
      "سيظهر ترتيب المخاطر لكل عنوان IP بعد أن يقيم المحلل كيانات الشبكة.",
    "riskPerIp.highestConfidence": "أعلى ثقة",
    "riskPerIp.highestConfidenceDescription": ({ ip }) =>
      `يحمل ${ip} أقوى إشارة ثقة حالية.`,
    "riskPerIp.highestConfidenceEmpty":
      "ستظهر أشرطة الثقة عند توفر أدلة على مستوى عنوان IP.",
    "riskPerIp.elevatedRiskEntities": "كيانات مرتفعة المخاطر",
    "riskPerIp.elevatedRiskDescription":
      "عناوين IP المرتبطة حاليًا بنتائج عالية أو حرجة تمت ترقيتها.",
    "riskPerIp.table.ip": "عنوان IP",
    "riskPerIp.table.role": "الدور",
    "riskPerIp.table.threats": "التهديدات",
    "riskPerIp.table.topSeverity": "أعلى شدة",
    "riskPerIp.table.confidence": "الثقة",
    "riskPerIp.table.riskScore": "درجة المخاطر",
    "riskPerIp.table.topAttack": "أبرز هجوم",
    "riskPerIp.emptyTitle": "لا توجد بيانات مخاطر لعناوين IP لهذا التحليل.",
    "riskPerIp.emptyDescription":
      "ستظهر تفاصيل تقييم المخاطر بعد أن يقيّم المحلل الكيانات المصدر والوجهة.",
    "riskPerIp.awaitingDominantLabel": "بانتظار التسمية المهيمنة",
    "riskPerIp.suspiciousCount": ({ count }) => `${count} مشبوه`,
    "riskPerIp.unknownThreat": "تهديد غير معروف",
    "riskPerIp.topAttackHelp": "أبرز تسمية تمت ملاحظتها لهذا الكيان.",
    "riskPerIp.role.source": "مصدر",
    "riskPerIp.role.destination": "وجهة",
    "riskPerIp.role.both": "كلاهما",
    "riskPerIp.severity.low": "منخفض",
    "riskPerIp.severity.medium": "متوسط",
    "riskPerIp.severity.high": "مرتفع",
    "riskPerIp.severity.critical": "حرج",
  },
};

const LanguageContext = createContext<LanguageContextValue | undefined>(undefined);

function getStoredLanguage(): SupportedLanguage {
  if (typeof window === "undefined") return "english";
  const stored = window.localStorage.getItem(LANGUAGE_STORAGE_KEY);
  return stored === "arabic" ? "arabic" : "english";
}

function formatWithLocale(
  language: SupportedLanguage,
  value: string | number | Date | null | undefined,
  options?: FormatDateOptions
) {
  if (value === null || value === undefined || value === "") {
    return options?.fallback ?? "";
  }

  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) {
    return options?.fallback ?? String(value);
  }

  const { fallback: _fallback, ...intlOptions } = options ?? {};
  return new Intl.DateTimeFormat(localeByLanguage[language], intlOptions).format(date);
}

export function LanguageProvider({ children }: { children: React.ReactNode }) {
  const [language, setLanguage] = useState<SupportedLanguage>(getStoredLanguage);

  useEffect(() => {
    const locale = localeByLanguage[language];
    window.localStorage.setItem(LANGUAGE_STORAGE_KEY, language);
    document.documentElement.lang = language === "arabic" ? "ar" : "en";
    document.documentElement.dir = language === "arabic" ? "rtl" : "ltr";
    document.documentElement.dataset.locale = locale;
    document.body.dir = language === "arabic" ? "rtl" : "ltr";
  }, [language]);

  const value = useMemo<LanguageContextValue>(() => {
    const locale = localeByLanguage[language];

    const t = (key: string, params?: TranslationParams) => {
      const entry = translations[language][key] ?? translations.english[key];
      if (!entry) return key;
      return typeof entry === "function" ? entry(params) : entry;
    };

    return {
      language,
      locale,
      setLanguage,
      t,
      isRtl: language === "arabic",
      formatDate: (value, options) => formatWithLocale(language, value, options),
      formatDateTime: (value, options) =>
        formatWithLocale(language, value, {
          dateStyle: "medium",
          timeStyle: "short",
          ...options,
        }),
      formatNumber: (value, options) => new Intl.NumberFormat(locale, options).format(value),
    };
  }, [language]);

  return <LanguageContext.Provider value={value}>{children}</LanguageContext.Provider>;
}

export function useLanguage() {
  const context = useContext(LanguageContext);
  if (!context) {
    throw new Error("useLanguage must be used within a LanguageProvider");
  }
  return context;
}
