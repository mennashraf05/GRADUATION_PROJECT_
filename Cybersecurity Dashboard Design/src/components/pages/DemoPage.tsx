import React, { useState } from 'react';
import { motion } from 'motion/react';
import { useNavigate } from 'react-router-dom';
import { 
  Shield, 
  Lock, 
  Eye, 
  Zap, 
  Play, 
  ArrowLeft,
  CheckCircle,
  Globe,
  FileCheck,
  Sparkles
} from 'lucide-react';
import { Button } from '../ui/button';
import { Card } from '../ui/card';
import { useLanguage } from '../../contexts/LanguageContext';

export function DemoPage() {
  const navigate = useNavigate();
  const { language, isRtl } = useLanguage();
  const isArabic = language === 'arabic';
  const [isPlaying, setIsPlaying] = useState(false);

  const features = [
    {
      icon: Shield,
      title: isArabic ? 'كشف التهديدات في الوقت الفعلي' : 'Real-Time Threat Detection',
      description: isArabic
        ? 'خوارزميات الذكاء الاصطناعي تراقب التهديدات الأمنية المحتملة وتتعرف عليها فورًا'
        : 'AI algorithms monitor and identify potential security threats instantly',
      color: "text-[#00D4FF]"
    },
    {
      icon: Lock,
      title: isArabic ? 'تشفير من الطرف إلى الطرف' : 'End-to-End Encryption',
      description: isArabic
        ? 'تشفير بمستوى عسكري لملفاتك الحساسة واتصالاتك'
        : 'Military-grade encryption for your sensitive files and communications',
      color: "text-[#00FF94]"
    },
    {
      icon: Eye,
      title: isArabic ? 'مراقبة استباقية' : 'Proactive Monitoring',
      description: isArabic
        ? 'متابعة مستمرة لبصمتك الرقمية عبر الويب'
        : 'Continuous surveillance of your digital footprint across the web',
      color: "text-[#A855F7]"
    }
  ];

  return (
    <div dir={isRtl ? 'rtl' : 'ltr'} className="min-h-screen bg-[#0B0F19] text-white">
      {/* Navigation */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-[#0B0F19]/90 backdrop-blur-md border-b border-[#374151]/30">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <Shield className={`w-8 h-8 text-[#00D4FF] ${isRtl ? 'ml-3' : 'mr-3'}`} />
              <span className="text-2xl font-bold bg-gradient-to-r from-[#00D4FF] to-[#00FF94] bg-clip-text text-transparent">
                Sentinel AI
              </span>
            </div>
            <Button
              onClick={() => navigate('/')}
              variant="ghost"
              className="text-gray-300 hover:text-white hover:bg-[#1F2937] transition-colors"
            >
              <ArrowLeft className={`w-4 h-4 ${isRtl ? 'ml-2' : 'mr-2'}`} />
              {isArabic ? 'العودة إلى الرئيسية' : 'Back to Home'}
            </Button>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <div className="pt-20">
        {/* Header Section */}
        <section className="py-16 px-4">
          <div className="container mx-auto max-w-4xl text-center">
            <motion.div
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8 }}
            >
              <div className="mb-6">
                <div className="inline-flex items-center px-4 py-2 rounded-full bg-gradient-to-r from-[#00D4FF]/20 to-[#00FF94]/20 border border-[#00D4FF]/30 mb-8">
                  <Play className={`w-4 h-4 text-[#00D4FF] ${isRtl ? 'ml-2' : 'mr-2'}`} />
                  <span className="text-sm">
                    {isArabic ? 'عرض توضيحي للمنتج' : 'Product Demonstration'}
                  </span>
                </div>
              </div>

              <h1 className="text-4xl md:text-6xl font-bold mb-6 bg-gradient-to-r from-white via-[#00D4FF] to-[#00FF94] bg-clip-text text-transparent">
                {isArabic ? 'شاهد Sentinel AI أثناء العمل' : 'See Sentinel AI in Action'}
              </h1>
              
              <p className="text-xl md:text-2xl text-gray-300 mb-12 max-w-3xl mx-auto leading-relaxed">
                {isArabic
                  ? 'اكتشف كيف ترصد منصتنا التهديدات وتحمي الملفات وتحافظ على هويتك الرقمية بأمان عبر الأمن السيبراني المدعوم بالذكاء الاصطناعي.'
                  : 'Explore how our platform detects threats, protects files, and keeps your digital identity safe with AI-powered cybersecurity.'}
              </p>
            </motion.div>
          </div>
        </section>

        {/* Video Player Section */}
        <section className="py-16 px-4">
          <div className="container mx-auto max-w-6xl">
            <motion.div
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.8 }}
              className="relative"
            >
              <div className="relative bg-gradient-to-br from-[#111827] to-[#1F2937] rounded-2xl border border-[#374151] overflow-hidden shadow-2xl">
                <div className="absolute inset-0 bg-gradient-to-r from-[#00D4FF]/10 to-[#00FF94]/10" />
                
                {/* Video Placeholder */}
                <div className="relative aspect-video bg-gradient-to-br from-[#1F2937] to-[#111827] flex items-center justify-center">
                  {!isPlaying ? (
                    <motion.button
                      onClick={() => setIsPlaying(true)}
                      className="flex items-center justify-center w-24 h-24 rounded-full bg-gradient-to-r from-[#00D4FF] to-[#00FF94] text-black hover:scale-110 transition-all duration-300 shadow-[0_0_30px_rgba(0,212,255,0.5)]"
                      whileHover={{ scale: 1.1 }}
                      whileTap={{ scale: 0.95 }}
                    >
                      <Play className={`w-8 h-8 ${isRtl ? 'mr-1' : 'ml-1'}`} />
                    </motion.button>
                  ) : (
                    <div className="w-full h-full bg-black flex items-center justify-center">
                      <div className="text-center">
                        <div className="animate-spin w-12 h-12 border-4 border-[#00D4FF] border-t-transparent rounded-full mx-auto mb-4"></div>
                        <p className="text-gray-300">
                          {isArabic ? 'جارٍ تحميل الفيديو التجريبي...' : 'Loading demo video...'}
                        </p>
                        <p className="text-sm text-gray-500 mt-2">
                          {isArabic
                            ? 'هذا مجرد عنصر تجريبي مؤقت. في بيئة الإنتاج سيظهر هنا الاستعراض الحقيقي للمنتج.'
                            : 'This is a demo placeholder. In production, this would show the actual product walkthrough.'}
                        </p>
                      </div>
                    </div>
                  )}
                </div>

                {/* Video Controls Overlay */}
                {isPlaying && (
                  <div className="absolute bottom-4 left-4 right-4">
                    <div className="bg-black/50 backdrop-blur-md rounded-lg p-4 flex items-center justify-between">
                      <div className="flex items-center space-x-4">
                        <button
                          onClick={() => setIsPlaying(false)}
                          className="text-white hover:text-[#00D4FF] transition-colors"
                        >
                          <Play className="w-5 h-5" />
                        </button>
                        <div className="text-sm text-gray-300">2:34 / 5:42</div>
                      </div>
                      <div className="text-sm text-gray-300">
                        {isArabic ? 'جولة داخل لوحة التحكم' : 'Dashboard Walkthrough'}
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Glow Effect */}
              <div className="absolute inset-0 bg-gradient-to-r from-[#00D4FF]/20 to-[#00FF94]/20 rounded-2xl blur-xl -z-10" />
            </motion.div>
          </div>
        </section>

        {/* Feature Highlights */}
        <section className="py-20 px-4">
          <div className="container mx-auto max-w-6xl">
            <motion.div
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8 }}
              viewport={{ once: true }}
              className="text-center mb-16"
            >
              <h2 className="text-3xl md:text-4xl font-bold mb-6 bg-gradient-to-r from-white to-[#00D4FF] bg-clip-text text-transparent">
                {isArabic ? 'ما الذي ستشاهده في العرض التجريبي' : "What You'll See in the Demo"}
              </h2>
              <p className="text-xl text-gray-300 max-w-3xl mx-auto">
                {isArabic
                  ? 'اطلع على نظرة شاملة لكيفية حماية Sentinel AI لعالمك الرقمي'
                  : 'Get a comprehensive look at how Sentinel AI protects your digital world'}
              </p>
            </motion.div>

            <div className="grid md:grid-cols-3 gap-8">
              {features.map((feature, index) => (
                <motion.div
                  key={feature.title}
                  initial={{ opacity: 0, y: 30 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.6, delay: index * 0.1 }}
                  viewport={{ once: true }}
                  whileHover={{ y: -10 }}
                  className="group"
                >
                  <Card className="p-8 bg-gradient-to-br from-[#111827] to-[#1F2937] border-[#374151] hover:border-[#00D4FF]/50 transition-all duration-300 h-full text-center">
                    <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-gray-800 to-gray-900 flex items-center justify-center mx-auto mb-6 group-hover:shadow-[0_0_20px_rgba(0,212,255,0.3)] transition-all duration-300">
                      <feature.icon className={`w-8 h-8 ${feature.color}`} />
                    </div>
                    <h3 className="text-xl font-bold mb-4 text-white">{feature.title}</h3>
                    <p className="text-gray-300 leading-relaxed">{feature.description}</p>
                  </Card>
                </motion.div>
              ))}
            </div>
          </div>
        </section>

        {/* Demo Benefits */}
        <section className="py-20 px-4 bg-gradient-to-br from-[#111827]/50 to-[#1F2937]/50">
          <div className="container mx-auto max-w-4xl">
            <motion.div
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8 }}
              viewport={{ once: true }}
              className="text-center"
            >
              <h2 className="text-3xl md:text-4xl font-bold mb-12 bg-gradient-to-r from-white to-[#00FF94] bg-clip-text text-transparent">
                {isArabic ? 'لماذا تشاهد العرض التجريبي؟' : 'Why Watch the Demo?'}
              </h2>

              <div className={`grid md:grid-cols-2 gap-8 ${isRtl ? 'text-right' : 'text-left'}`}>
                <div className="space-y-6">
                  <div className="flex items-start">
                    <CheckCircle className={`w-6 h-6 text-[#00FF94] mt-1 flex-shrink-0 ${isRtl ? 'ml-4' : 'mr-4'}`} />
                    <div>
                      <h3 className="text-lg font-semibold text-white mb-2">
                        {isArabic ? 'جولة حية داخل لوحة التحكم' : 'Live Dashboard Walkthrough'}
                      </h3>
                      <p className="text-gray-300">
                        {isArabic
                          ? 'شاهد كشف التهديدات والمراقبة الأمنية لحظيًا أثناء العمل'
                          : 'See real-time threat detection and security monitoring in action'}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-start">
                    <CheckCircle className={`w-6 h-6 text-[#00FF94] mt-1 flex-shrink-0 ${isRtl ? 'ml-4' : 'mr-4'}`} />
                    <div>
                      <h3 className="text-lg font-semibold text-white mb-2">
                        {isArabic ? 'ميزات مدعومة بالذكاء الاصطناعي' : 'AI-Powered Features'}
                      </h3>
                      <p className="text-gray-300">
                        {isArabic
                          ? 'اكتشف كيف يعزز التعلم الآلي مستوى أمنك السيبراني'
                          : 'Discover how machine learning enhances your cybersecurity'}
                      </p>
                    </div>
                  </div>
                </div>
                <div className="space-y-6">
                  <div className="flex items-start">
                    <CheckCircle className={`w-6 h-6 text-[#00FF94] mt-1 flex-shrink-0 ${isRtl ? 'ml-4' : 'mr-4'}`} />
                    <div>
                      <h3 className="text-lg font-semibold text-white mb-2">
                        {isArabic ? 'تكامل على مستوى المؤسسات' : 'Enterprise Integration'}
                      </h3>
                      <p className="text-gray-300">
                        {isArabic
                          ? 'تعرّف كيف ينسجم Sentinel AI مع منظومة الأمان الحالية لديك'
                          : 'Learn how Sentinel AI fits into your existing security stack'}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-start">
                    <CheckCircle className={`w-6 h-6 text-[#00FF94] mt-1 flex-shrink-0 ${isRtl ? 'ml-4' : 'mr-4'}`} />
                    <div>
                      <h3 className="text-lg font-semibold text-white mb-2">
                        {isArabic ? 'العائد والتوفير' : 'ROI & Savings'}
                      </h3>
                      <p className="text-gray-300">
                        {isArabic
                          ? 'افهم الفوائد المالية للوقاية الاستباقية من التهديدات'
                          : 'Understand the cost benefits of proactive threat prevention'}
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </motion.div>
          </div>
        </section>

        {/* CTA Section */}
        <section className="py-20 px-4">
          <div className="container mx-auto max-w-4xl">
            <motion.div
              initial={{ opacity: 0, scale: 0.9 }}
              whileInView={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.8 }}
              viewport={{ once: true }}
              className="text-center bg-gradient-to-br from-[#111827] to-[#1F2937] rounded-3xl p-12 border border-[#374151] relative overflow-hidden"
            >
              <div className="absolute inset-0 bg-gradient-to-r from-[#00D4FF]/10 via-transparent to-[#00FF94]/10" />
              <div className="relative z-10">
                <h2 className="text-3xl md:text-4xl font-bold mb-6 bg-gradient-to-r from-white via-[#00D4FF] to-[#00FF94] bg-clip-text text-transparent">
                  {isArabic ? 'جاهز للانطلاق؟' : 'Ready to Get Started?'}
                </h2>
                <p className="text-xl text-gray-300 mb-10 max-w-2xl mx-auto">
                  {isArabic
                    ? 'اختبر قوة الأمن السيبراني المدعوم بالذكاء الاصطناعي وابدأ حماية عالمك الرقمي اليوم.'
                    : 'Experience the power of AI-driven cybersecurity. Start protecting your digital world today.'}
                </p>
                <div className="flex flex-col sm:flex-row gap-4 justify-center">
                  <motion.div
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                  >
                    <Button
                      onClick={() => navigate('/signup')}
                      className="px-8 py-4 bg-gradient-to-r from-[#00D4FF] to-[#00FF94] text-black hover:shadow-[0_0_40px_rgba(0,212,255,0.6)] transition-all duration-300"
                      size="lg"
                    >
                      {isArabic ? 'ابدأ الآن' : 'Get Started'}
                    </Button>
                  </motion.div>
                  <motion.div
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                  >
                    <Button
                      onClick={() => navigate('/login')}
                      variant="outline"
                      className="px-8 py-4 border-[#374151] text-gray-300 hover:bg-[#1F2937] hover:border-[#00D4FF]/50 transition-all duration-300"
                      size="lg"
                    >
                      {isArabic ? 'تسجيل الدخول' : 'Sign In'}
                    </Button>
                  </motion.div>
                </div>
                <p className="text-sm text-gray-400 mt-4">100% Free • Enterprise-grade security</p>
              </div>
            </motion.div>
          </div>
        </section>
      </div>
    </div>
  );
}

