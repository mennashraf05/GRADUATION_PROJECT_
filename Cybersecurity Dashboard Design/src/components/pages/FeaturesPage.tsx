import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Lock, FileText, Eye, ArrowRight, Zap, Bell, CheckCircle, Network } from 'lucide-react';
import { Button } from '../ui/button';
import { useLanguage } from '../../contexts/LanguageContext';
import { useAppSettings } from '../../contexts/AppSettingsContext';

export function FeaturesPage() {
  const { language, isRtl } = useLanguage();
  const { applicationName } = useAppSettings();
  const navigate = useNavigate();
  const features = [
    {
      id: 'password-checker',
      path: '/password-checker',
      icon: Lock,
      emoji: '🔐',
      title: language === 'arabic' ? 'فاحص كلمات المرور المسربة' : 'Password Breach Checker',
      description: language === 'arabic' ? 'اكتشف ما إذا كانت بيانات اعتمادك قد تسربت في اختراقات سابقة.' : 'Detect if your credentials were leaked in past data breaches.',
      gradient: 'from-blue-500 to-cyan-500',
      glowColor: 'shadow-blue-500/50',
    },
    {
      id: 'file-vault',
      path: '/file-vault',
      icon: FileText,
      emoji: '📁',
      title: language === 'arabic' ? 'خزنة ملفات مشفرة' : 'Encrypted File Vault',
      description: language === 'arabic' ? 'أمّن ملفاتك بتشفير AES/RSA وادخل إليها بأمان في أي وقت.' : 'Secure your files with AES/RSA encryption and access them anytime safely.',
      gradient: 'from-green-500 to-emerald-500',
      glowColor: 'shadow-green-500/50',
    },
    {
      id: 'phishing-scanner',
      path: '/phishing-scanner',
      icon: Shield,
      emoji: '🔗',
      title: language === 'arabic' ? 'فاحص روابط التصيد' : 'Phishing Link Scanner',
      description: language === 'arabic' ? 'حلّل الروابط واكتشف محاولات التصيد قبل أن تصلك.' : 'Analyze links and detect phishing attempts before they reach you.',
      gradient: 'from-purple-500 to-pink-500',
      glowColor: 'shadow-purple-500/50',
    },
    {
      id: 'identity-leak-monitor',
      path: '/identityleak-monitor',
      icon: Eye,
      emoji: '🌑',
      title: language === 'arabic' ? 'مراقبة تسرب الهوية' : 'Identity Leak Monitor',
      description: language === 'arabic' ? 'افحص تعرض بيانات الهوية للتسريب.' : 'Scan for identity data exposure.',
      gradient: 'from-red-500 to-orange-500',
      glowColor: 'shadow-red-500/50',
    },
    {
      id: 'pcap-analyzer',
      path: '/pcap-analyzer',
      icon: Network,
      emoji: 'PCAP',
      title: language === 'arabic' ? 'Ù…Ø­Ù„Ù„ PCAP' : 'PCAP Analyzer',
      description: language === 'arabic' ? 'Ø­Ù„Ù„ Ù…Ù„ÙØ§Øª Ø§Ù„Ø´Ø¨ÙƒØ© ÙˆØ±Ø§Ø¬Ø¹ Ø§Ù„ØªÙ†Ø¨ÙŠÙ‡Ø§Øª Ø¨Ø³ÙŠØ§Ù‚ Ø¢Ù…Ù†.' : 'Analyze network captures and review alerts with safe context.',
      gradient: 'from-cyan-500 to-indigo-500',
      glowColor: 'shadow-cyan-500/50',
    },
  ];

  const whyCards = [
    {
      icon: Shield,
      title: language === 'arabic' ? 'الأمان' : 'Security',
      description: language === 'arabic' ? 'حماية بمستوى المؤسسات مع تشفير قوي للغاية' : 'Enterprise-grade protection with military-grade encryption',
      gradient: 'from-blue-600 to-cyan-600',
    },
    {
      icon: Zap,
      title: language === 'arabic' ? 'الأتمتة' : 'Automation',
      description: language === 'arabic' ? 'مراقبة مدعومة بالذكاء الاصطناعي تعمل 24/7 لحمايتك' : 'AI-powered monitoring works 24/7 to keep you protected',
      gradient: 'from-purple-600 to-pink-600',
    },
    {
      icon: Bell,
      title: language === 'arabic' ? 'تنبيهات فورية' : 'Real-time Alerts',
      description: language === 'arabic' ? 'إشعارات فورية عند اكتشاف التهديدات' : 'Instant notifications when threats are detected',
      gradient: 'from-green-600 to-emerald-600',
    },
  ];

  return (
    <div className="min-h-screen bg-[#0F172A] relative overflow-hidden" dir={isRtl ? 'rtl' : 'ltr'}>
      {/* Animated Background Dots */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-20 left-10 w-2 h-2 bg-blue-500 rounded-full animate-pulse" />
        <div className="absolute top-40 right-20 w-2 h-2 bg-green-500 rounded-full animate-pulse" style={{ animationDelay: '1s' }} />
        <div className="absolute bottom-40 left-1/4 w-2 h-2 bg-purple-500 rounded-full animate-pulse" style={{ animationDelay: '2s' }} />
        <div className="absolute top-1/3 right-1/3 w-2 h-2 bg-cyan-500 rounded-full animate-pulse" style={{ animationDelay: '1.5s' }} />
      </div>

      {/* Navigation */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-[#0F172A]/80 backdrop-blur-xl border-b border-gray-800/50">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <button
              onClick={() => navigate('/')}
              className="flex items-center gap-2 group"
            >
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-500 to-green-500 flex items-center justify-center group-hover:shadow-lg group-hover:shadow-blue-500/50 transition-all duration-300">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <span className="text-xl bg-gradient-to-r from-blue-400 to-green-400 bg-clip-text text-transparent">
                {applicationName}
              </span>
            </button>
            <div className="flex items-center gap-4">
              <Button
                variant="ghost"
                onClick={() => navigate('/')}
                className="text-gray-300 hover:text-white hover:bg-white/5"
              >
                {language === 'arabic' ? 'الرئيسية' : 'Home'}
              </Button>
              <Button
                variant="ghost"
                onClick={() => navigate('/dashboard')}
                className="text-gray-300 hover:text-white hover:bg-white/5"
              >
                {language === 'arabic' ? 'لوحة التحكم' : 'Dashboard'}
              </Button>
              <Button
                variant="ghost"
                onClick={() => navigate('/learn')}
                className="text-gray-300 hover:text-white hover:bg-white/5"
              >
                {language === 'arabic' ? 'تعلّم' : 'Learn'}
              </Button>
              <Button
                variant="ghost"
                onClick={() => navigate('/about')}
                className="text-gray-300 hover:text-white hover:bg-white/5"
              >
                {language === 'arabic' ? 'حول' : 'About'}
              </Button>
              <Button
                variant="ghost"
                onClick={() => navigate('/contact')}
                className="text-gray-300 hover:text-white hover:bg-white/5"
              >
                {language === 'arabic' ? 'اتصل بنا' : 'Contact'}
              </Button>
              <Button
                onClick={() => navigate('/login')}
                className="text-white hover:bg-white/10"
                variant="ghost"
              >
                {language === 'arabic' ? 'تسجيل الدخول' : 'Login'}
              </Button>
              <Button
                onClick={() => navigate('/signup')}
                className="bg-gradient-to-r from-blue-600 to-green-600 hover:from-blue-500 hover:to-green-500 text-white shadow-lg hover:shadow-blue-500/50 transition-all duration-300"
              >
                {language === 'arabic' ? 'إنشاء حساب' : 'Sign Up'}
              </Button>
            </div>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <div className="relative pt-32 pb-20 px-6">
        <div className="max-w-7xl mx-auto text-center">
          <h1 className="text-5xl md:text-6xl lg:text-7xl mb-6 bg-gradient-to-r from-white via-blue-100 to-green-100 bg-clip-text text-transparent">
            {language === 'arabic' ? `استكشف مزايا ${applicationName}` : `Explore ${applicationName} Features`}
          </h1>
          <p className="text-xl md:text-2xl text-gray-400 max-w-3xl mx-auto">
            {language === 'arabic' ? 'أدوات مدعومة بالذكاء الاصطناعي لحماية بياناتك وهويتك.' : 'AI-powered tools to protect your data and identity.'}
          </p>
        </div>
      </div>

      {/* Features Grid */}
      <div className="relative max-w-7xl mx-auto px-6 pb-24">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {features.map((feature, index) => {
            const Icon = feature.icon;
            return (
              <div
                key={feature.id}
                className="group relative"
                style={{ 
                  animation: 'fadeInUp 0.6s ease-out forwards',
                  animationDelay: `${index * 100}ms`,
                  opacity: 0
                }}
              >
                <style jsx>{`
                  @keyframes fadeInUp {
                    from {
                      opacity: 0;
                      transform: translateY(20px);
                    }
                    to {
                      opacity: 1;
                      transform: translateY(0);
                    }
                  }
                `}</style>
                
                {/* Glow effect on hover */}
                <div className={`absolute -inset-1 bg-gradient-to-r ${feature.gradient} opacity-0 group-hover:opacity-20 blur-xl transition-opacity duration-500 rounded-2xl`} />
                
                {/* Card */}
                <div className="relative h-full p-8 rounded-2xl bg-[#1E293B] border border-gray-700/50 backdrop-blur-sm hover:border-gray-600/70 transition-all duration-300">
                  {/* Icon */}
                  <div className="mb-6">
                    <div className={`inline-flex p-4 rounded-xl bg-gradient-to-br ${feature.gradient} shadow-lg ${feature.glowColor} group-hover:shadow-2xl group-hover:scale-110 transition-all duration-300`}>
                      <Icon className="w-8 h-8 text-white" />
                    </div>
                  </div>

                  {/* Content */}
                  <h3 className="text-2xl mb-4 text-white flex items-center gap-2">
                    <span>{feature.emoji}</span> {feature.title}
                  </h3>
                  <p className="text-gray-400 mb-6 leading-relaxed">
                    {feature.description}
                  </p>

                  {/* CTA Button */}
                  <Button
                    onClick={() => navigate(feature.path)}
                    className={`group/btn w-full bg-gradient-to-r ${feature.gradient} hover:shadow-lg hover:${feature.glowColor} transition-all duration-300 text-white`}
                  >
                    {language === 'arabic' ? 'جرّب الآن' : 'Try Now'}
                    <ArrowRight className={`w-4 h-4 ${isRtl ? 'mr-2' : 'ml-2'} group-hover/btn:translate-x-1 transition-transform duration-300`} />
                  </Button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Why Sentinel AI Section */}
      <div className="relative max-w-7xl mx-auto px-6 pb-32">
        <div className="text-center mb-16">
          <h2 className="text-4xl md:text-5xl mb-4 text-white">
            {language === 'arabic' ? `لماذا ${applicationName}؟` : `Why ${applicationName}?`}
          </h2>
          <div className="h-1 w-24 bg-gradient-to-r from-blue-500 to-green-500 rounded-full mx-auto" />
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          {whyCards.map((card, index) => {
            const Icon = card.icon;
            return (
              <div
                key={index}
                className="group relative"
                style={{ 
                  animation: 'fadeInUp 0.6s ease-out forwards',
                  animationDelay: `${index * 150}ms`,
                  opacity: 0
                }}
              >
                {/* Glow effect */}
                <div className={`absolute -inset-1 bg-gradient-to-r ${card.gradient} opacity-0 group-hover:opacity-20 blur-xl transition-opacity duration-500 rounded-2xl`} />
                
                {/* Card */}
                <div className="relative h-full p-8 rounded-2xl bg-[#1E293B] border border-gray-700/50 backdrop-blur-sm hover:border-gray-600/70 transition-all duration-300 text-center">
                  {/* Icon */}
                  <div className="mb-6">
                    <div className={`inline-flex p-6 rounded-2xl bg-gradient-to-br ${card.gradient} shadow-lg shadow-blue-500/30 group-hover:shadow-2xl group-hover:scale-110 transition-all duration-300`}>
                      <Icon className="w-10 h-10 text-white" />
                    </div>
                  </div>

                  {/* Content */}
                  <h3 className="text-2xl mb-4 text-white">
                    {card.title}
                  </h3>
                  <p className="text-gray-400 leading-relaxed">
                    {card.description}
                  </p>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Footer */}
      <footer className="relative border-t border-gray-800 bg-[#0F172A]">
        <div className="max-w-7xl mx-auto px-6 py-12">
          <div className="text-center text-gray-400">
            <p>© 2025 {applicationName} - All Rights Reserved.</p>
          </div>
        </div>
      </footer>
    </div>
  );
}
