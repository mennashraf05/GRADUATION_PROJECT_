// src/components/pages/SignUpPage.tsx
import React, { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { useNavigate } from 'react-router-dom';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { Checkbox } from '../ui/checkbox';
import { Button } from '../ui/button';
import { CheckedState } from '@radix-ui/react-checkbox';
import { useLanguage } from '../../contexts/LanguageContext';
import {
  Eye,
  EyeOff,
  Mail,
  Lock,
  User,
  CheckCircle,
  Loader2,
  Sparkles,
  ArrowLeft,
  Shield,
  ArrowRight,
  Zap,
  Brain,
  Globe,
} from 'lucide-react';

const API_BASE_URL =
  import.meta.env.DEV ? '' : (import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000');

export function SignUpPage() {
  const navigate = useNavigate();
  const { language, isRtl } = useLanguage();
  const isArabic = language === 'arabic';
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);
  const [focusedField, setFocusedField] = useState<string | null>(null);
  const [validationErrors, setValidationErrors] = useState<
    Record<string, string>
  >({});
  const [serverError, setServerError] = useState<string | null>(null);
  const [formData, setFormData] = useState({
    fullName: '',
    email: '',
    password: '',
    confirmPassword: '',
    acceptTerms: false,
  });

  // ================== Validation helpers ==================
  const clearFieldError = (field: string) => {
    setValidationErrors((prev) => {
      if (!prev[field]) return prev;
      const next = { ...prev };
      delete next[field];
      return next;
    });
  };

  const validateField = (field: string, value: string) => {
    let error = '';

    switch (field) {
      case 'fullName':
        if (!value.trim()) {
          error = isArabic ? 'الاسم الكامل مطلوب' : 'Full name is required';
        } else if (value.trim().length < 3) {
          error = isArabic
            ? 'يجب أن يتكون الاسم الكامل من 3 أحرف على الأقل'
            : 'Full name must be at least 3 characters';
        }
        break;

      case 'email':
        if (!value.trim()) {
          error = isArabic ? 'البريد الإلكتروني مطلوب' : 'Email is required';
        } else if (!/^\S+@\S+\.\S+$/.test(value.trim())) {
          error = isArabic
            ? 'يرجى إدخال بريد إلكتروني صحيح'
            : 'Please enter a valid email address';
        }
        break;

      case 'password':
        if (value.length < 8) {
          error = isArabic
            ? 'يجب أن تتكون كلمة المرور من 8 أحرف على الأقل'
            : 'Password must be at least 8 characters';
        } else if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(value)) {
          error = isArabic
            ? 'يجب أن تحتوي كلمة المرور على حرف كبير وحرف صغير ورقم'
            : 'Password must contain uppercase, lowercase, and number';
        }
        break;

      case 'confirmPassword':
        if (!value) {
          error = isArabic
            ? 'يرجى تأكيد كلمة المرور'
            : 'Please confirm your password';
        } else if (value !== formData.password) {
          error = isArabic
            ? 'كلمتا المرور غير متطابقتين'
            : 'Passwords do not match';
        }
        break;
    }

    setValidationErrors((prev) => {
      const next = { ...prev };
      if (error) {
        next[field] = error;
      } else {
        delete next[field];
      }
      return next;
    });

    return !error;
  };

  const handleInputChange = (field: string, value: string | boolean) => {
    setFormData((prev) => ({ ...prev, [field]: value }));

    if (serverError) setServerError(null);

    if (typeof value === 'string') {
      if (
        ['fullName', 'email', 'password', 'confirmPassword'].includes(
          field,
        )
      ) {
        validateField(field, value);
      }
    }

    if (field === 'acceptTerms' && value === true) {
      clearFieldError('acceptTerms');
    }
  };

  const getPasswordStrength = (password: string) => {
    let strength = 0;
    if (password.length >= 8) strength++;
    if (/[a-z]/.test(password)) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/\d/.test(password)) strength++;
    if (/[^A-Za-z0-9]/.test(password)) strength++;
    return strength;
  };

  const passwordStrength = getPasswordStrength(formData.password);
  const strengthColors = ['#EF4444', '#F59E0B', '#F59E0B', '#10B981', '#059669'];
  const strengthLabels = isArabic
    ? ['ضعيفة جدًا', 'ضعيفة', 'متوسطة', 'جيدة', 'قوية']
    : ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'];

  // ================== Animated background helpers ==================
  const gridPoints = Array.from({ length: 120 }, (_, i) => ({
    id: i,
    x: (i % 12) * 8.33,
    y: Math.floor(i / 12) * 10,
    delay: Math.random() * 4,
  }));


  const particles = Array.from({ length: 20 }, (_, i) => ({
    id: i,
    x: Math.random() * 100,
    y: Math.random() * 100,
    delay: Math.random() * 6,
    duration: 4 + Math.random() * 3,
  }));

  
  const features = [
    {
      icon: Shield,
      text: isArabic ? 'حماية بمستوى المؤسسات' : 'Enterprise-Grade Security',
      color: '#3B82F6',
      delay: 0.8,
    },
    {
      icon: Zap,
      text: isArabic ? 'مراقبة التهديدات لحظيًا' : 'Real-time Threat Monitoring',
      color: '#64FFDA',
      delay: 1.0,
    },
    {
      icon: Brain,
      text: isArabic ? 'كشف مدعوم بالذكاء الاصطناعي' : 'AI-Powered Detection',
      color: '#A855F7',
      delay: 1.2,
    },
  ];

  // ================== Submit ==================
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    const fullNameValid = validateField('fullName', formData.fullName);
    const emailValid = validateField('email', formData.email);
    const passwordValid = validateField('password', formData.password);
    const confirmValid = validateField(
      'confirmPassword',
      formData.confirmPassword,
    );

    if (!formData.acceptTerms) {
      setValidationErrors((prev) => ({
        ...prev,
        acceptTerms: isArabic
          ? 'يجب الموافقة على الشروط لإنشاء الحساب'
          : 'You must accept the terms to create an account',
      }));
    }

    const isValid =
      fullNameValid &&
      emailValid &&
      passwordValid &&
      confirmValid &&
      formData.acceptTerms;

    if (!isValid) return;

    setIsLoading(true);
    setServerError(null);

 const payload = {
  fullName: formData.fullName.trim(),
  email: formData.email.trim().toLowerCase(),
  password: formData.password,
};
    try {

      const response = await fetch(`${API_BASE_URL || ''}/api/auth/signup`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        // مافيش cookies هنا
        body: JSON.stringify(payload),
      });

      const data = (await response.json().catch(() => null)) as
        | { success?: boolean; message?: string }
        | null;

      if (!response.ok || data?.success === false) {
        let message =
          data?.message ||
          (isArabic
            ? 'تعذر إنشاء حسابك. يرجى المحاولة مرة أخرى.'
            : 'We could not create your account. Please try again.');
        setServerError(message);
        return;
      }

      // هنا الـ backend أنشأ اليوزر وبعت الإيميل
      setIsSuccess(true);

      // Redirect to email-sent page with email
      navigate(`/email-sent?email=${encodeURIComponent(formData.email.trim().toLowerCase())}`);

    } catch (err) {
      setServerError(
        isArabic
          ? 'حدث خطأ في الشبكة. يرجى التحقق من الاتصال والمحاولة مرة أخرى.'
          : 'Network error. Please check your connection and try again.',
      );
    } finally {
      setIsLoading(false);
    }
  };

  // ================== Success Screen ==================
  if (isSuccess) {
    return (
       <div dir={isRtl ? 'rtl' : 'ltr'} className="min-h-screen bg-[#0F172A] flex items-center justify-center relative overflow-hidden">
        <div className="absolute inset-0">
          <div className="absolute inset-0 bg-gradient-to-br from-[#3B82F6]/10 via-transparent to-[#64FFDA]/10" />
          {particles.slice(0, 10).map((particle) => (
            <motion.div
              key={particle.id}
              className="absolute w-1 h-1 rounded-full bg-[#64FFDA]"
              style={{
                left: `${particle.x}%`,
                top: `${particle.y}%`,
              }}
              animate={{
                opacity: [0, 1, 0],
                scale: [0, 1.5, 0],
                y: [-10, 10, -10],
              }}
              transition={{
                duration: 3,
                repeat: Infinity,
                delay: particle.delay,
                ease: 'easeInOut',
              }}
            />
          ))}
        </div>

        <motion.div
          initial={{ opacity: 0, scale: 0.8 }}
          animate={{ opacity: 1, scale: 1 }}
          className="relative z-10 text-center bg-black/20 backdrop-blur-xl border border-white/10 rounded-3xl p-12 max-w-md mx-4"
        >
          <motion.div
            className="w-24 h-24 mx-auto mb-6 bg-gradient-to-r from-[#64FFDA] to-[#3B82F6] rounded-full flex items-center justify-center"
            animate={{
              boxShadow: [
                '0 0 0 0 rgba(100, 255, 218, 0.4)',
                '0 0 0 20px rgba(100, 255, 218, 0)',
                '0 0 0 0 rgba(100, 255, 218, 0)',
              ],
            }}
            transition={{ duration: 2, repeat: Infinity }}
          >
            <CheckCircle className="w-12 h-12 text-black" />
          </motion.div>

          <motion.h3
            className="text-3xl font-bold text-white mb-4"
            initial={{ y: 20, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            transition={{ delay: 0.3 }}
          >
            {isArabic ? 'مرحبًا بك في Sentinel AI!' : 'Welcome to Sentinel AI!'}
          </motion.h3>

          <motion.p
            className="text-gray-300 mb-6"
            initial={{ y: 20, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            transition={{ delay: 0.5 }}
          >
            {isArabic
              ? 'تم إنشاء حسابك بنجاح. يرجى مراجعة بريدك الإلكتروني لتأكيد الحساب. سيتم توجيهك إلى خطوة التحقق بعد لحظات.'
              : "Your account has been created successfully. Please check your email to verify your account. You'll be redirected to the verification step shortly."}
          </motion.p>

          <motion.div
            className="flex justify-center"
            initial={{ y: 20, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            transition={{ delay: 0.7 }}
          >
            <motion.div
              className="w-8 h-8 border-2 border-[#64FFDA] border-t-transparent rounded-full"
              animate={{ rotate: 360 }}
              transition={{
                duration: 1,
                repeat: Infinity,
                ease: 'linear',
              }}
            />
          </motion.div>
        </motion.div>
      </div>
    );
  }

  // ================== Main Sign Up Screen ==================
  return (
    <div
      dir={isRtl ? 'rtl' : 'ltr'}
      className="min-h-screen bg-[#0F172A] relative overflow-hidden flex"
    >
      {/* Left Panel */}
        <div className="flex-1 relative">
        <div className="absolute inset-0">
          {/* Grid */}
          <svg className="absolute inset-0 w-full h-full opacity-15">
            <defs>
              <pattern
                id="signup-grid"
                width="50"
                height="50"
                patternUnits="userSpaceOnUse"
              >
                <path
                  d="M 50 0 L 0 0 0 50"
                  fill="none"
                  stroke="#64FFDA"
                  strokeWidth="1"
                  opacity="0.3"
                />
              </pattern>
            </defs>
            <rect width="100%" height="100%" fill="url(#signup-grid)" />
          </svg>

          {/* Grid points */}
          {gridPoints.map((point) => (
            <motion.div
              key={point.id}
              className="absolute w-1 h-1 rounded-full"
              style={{
                left: `${point.x}%`,
                top: `${point.y}%`,
              }}
              initial={{ opacity: 0, scale: 0 }}
              animate={{
                opacity: [0.2, 0.8, 0.2],
                scale: [0.5, 1.2, 0.5],
                backgroundColor: ['#64FFDA', '#3B82F6', '#A855F7', '#64FFDA'],
              }}
              transition={{
                duration: 5,
                repeat: Infinity,
                delay: point.delay,
                ease: 'easeInOut',
              }}
            />
          ))}

          {/* Neon particles */}
          {particles.map((particle) => (
            <motion.div
              key={particle.id}
              className="absolute w-2 h-2 rounded-full"
              style={{
                left: `${particle.x}%`,
                top: `${particle.y}%`,
              }}
              initial={{ opacity: 0, scale: 0 }}
              animate={{
                opacity: [0, 1, 0],
                scale: [0, 1.5, 0],
                y: [-30, 30, -30],
                backgroundColor: ['#64FFDA', '#3B82F6', '#A855F7'],
                boxShadow: [
                  '0 0 10px #64FFDA',
                  '0 0 20px #3B82F6',
                  '0 0 15px #A855F7',
                ],
              }}
              transition={{
                duration: particle.duration,
                repeat: Infinity,
                delay: particle.delay,
                ease: 'easeInOut',
              }}
            />
          ))}

          {/* Scanning lines */}
          <motion.div
            className="absolute inset-0"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
          >
            <motion.div
              className="absolute w-full h-0.5 bg-gradient-to-r from-transparent via-[#64FFDA] to-transparent"
              animate={{
                y: ['-10%', '110%'],
                opacity: [0, 1, 0],
              }}
              transition={{
                duration: 10,
                repeat: Infinity,
                ease: 'linear',
              }}
            />
            <motion.div
              className="absolute w-0.5 h-full bg-gradient-to-b from-transparent via-[#3B82F6] to-transparent"
              animate={{
                x: ['-10%', '110%'],
                opacity: [0, 1, 0],
              }}
              transition={{
                duration: 8,
                repeat: Infinity,
                ease: 'linear',
                delay: 3,
              }}
            />
          </motion.div>
        </div>

        {/* Left content */}
        <div className="relative z-10 flex flex-col justify-center items-center h-full p-12 text-center">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 1, delay: 0.5 }}
            className="max-w-lg"
          >
            {/* Logo */}
            <div className="flex items-center justify-center mb-8">
              <motion.div
                animate={{
                  rotate: [0, 360],
                  scale: [1, 1.1, 1],
                }}
                transition={{
                  duration: 10,
                  repeat: Infinity,
                  ease: 'linear',
                }}
                className="relative"
              >
                <Shield className="w-20 h-20 text-[#64FFDA]" />
                <motion.div
                  className="absolute inset-0 w-20 h-20"
                  animate={{
                    boxShadow: [
                      '0 0 20px #64FFDA',
                      '0 0 40px #64FFDA',
                      '0 0 60px #64FFDA',
                      '0 0 40px #64FFDA',
                      '0 0 20px #64FFDA',
                    ],
                  }}
                  transition={{
                    duration: 3,
                    repeat: Infinity,
                    ease: 'easeInOut',
                  }}
                />
              </motion.div>
            </div>

            {/* Title */}
            <motion.h1
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.7 }}
              className="text-5xl font-bold mb-4 bg-gradient-to-r from-white via-[#64FFDA] to-[#3B82F6] bg-clip-text text-transparent"
            >
              Sentinel AI
            </motion.h1>

            {/* Tagline */}
            <motion.p
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.9 }}
              className="text-xl text-gray-300 mb-12 leading-relaxed"
            >
              {isArabic
                ? 'منصة الجيل القادم للأمن السيبراني'
                : 'Next-Generation Cybersecurity Platform'}
            </motion.p>

            {/* Features */}
            <div className="space-y-6">
              {features.map((feature, index) => (
                <motion.div
                  key={feature.text}
                  initial={{ opacity: 0, x: -30 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: feature.delay, duration: 0.6 }}
                  className={`flex items-center text-left ${isRtl ? 'space-x-reverse space-x-4' : 'space-x-4'}`}
                >
                  <motion.div
                    animate={{
                      scale: [1, 1.2, 1],
                      rotateY: [0, 180, 360],
                    }}
                    transition={{
                      duration: 3,
                      repeat: Infinity,
                      delay: index * 0.5,
                      ease: 'easeInOut',
                    }}
                    className="flex-shrink-0 w-12 h-12 rounded-xl bg-gradient-to-br from-black/40 to-black/20 backdrop-blur-sm border border-white/10 flex items-center justify-center"
                    style={{
                      boxShadow: `0 0 20px ${feature.color}40`,
                    }}
                  >
                    <feature.icon
                      className="w-6 h-6"
                      style={{ color: feature.color }}
                    />
                  </motion.div>
                  <motion.span
                    className="text-lg text-gray-200"
                    animate={{
                      color: [feature.color, '#ffffff', feature.color],
                    }}
                    transition={{
                      duration: 4,
                      repeat: Infinity,
                      delay: index * 0.3,
                      ease: 'easeInOut',
                    }}
                  >
                    {feature.text}
                  </motion.span>
                </motion.div>
              ))}
            </div>

            {/* Badge */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 1.5 }}
              className={`flex items-center justify-center mt-12 text-sm text-gray-400 ${isRtl ? 'space-x-reverse space-x-2' : 'space-x-2'}`}
            >
              <Globe className="w-4 h-4 text-[#64FFDA]" />
              <span>
                {isArabic
                  ? 'انضم إلى أكثر من 5,000 متخصص أمني حول العالم'
                  : 'Join 5,000+ security professionals worldwide'}
              </span>
            </motion.div>
          </motion.div>
        </div>
      </div>

      {/* Right Panel - Form */}
      <div className="w-full max-w-lg flex items-center justify-center p-8">
        <motion.div
          initial={{ opacity: 0, x: 50, scale: 0.9 }}
          animate={{ opacity: 1, x: 0, scale: 1 }}
          transition={{ duration: 0.8, type: 'spring', stiffness: 100 }}
          className="w-full max-w-md"
          >
           <div className="relative">
            <div className="absolute -inset-1 bg-gradient-to-r from-[#64FFDA] via-[#3B82F6] to-[#A855F7] rounded-2xl blur opacity-20" />

            <div className="relative bg-black/20 backdrop-blur-xl border border-white/10 rounded-2xl p-8 shadow-2xl">
              {/* Header */}
              <div className="text-center mb-8">
                <motion.button
                  onClick={() => navigate('/')}
                  className="absolute top-6 left-6 p-2 text-gray-400 hover:text-white transition-colors rounded-lg hover:bg-white/5"
                  whileHover={{ scale: 1.1 }}
                  whileTap={{ scale: 0.9 }}
                >
                  <ArrowLeft className="w-5 h-5" />
                </motion.button>

                <motion.h2
                  initial={{ opacity: 0, y: -20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.2 }}
                  className="text-2xl font-bold text-white mb-2"
                >
                  {isArabic ? 'إنشاء حساب' : 'Create Account'}
                </motion.h2>

                <motion.p
                  initial={{ opacity: 0, y: -10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.3 }}
                  className="text-gray-400"
                >
                  {isArabic
                    ? 'انضم إلى Sentinel AI للحصول على حماية سيبرانية متقدمة'
                    : 'Join Sentinel AI for advanced cybersecurity protection'}
                </motion.p>
              </div>

              {/* Server error */}
              <AnimatePresence>
                {serverError && (
                  <motion.div
                    initial={{ opacity: 0, y: -10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -10 }}
                    className="mb-4 rounded-lg bg-red-500/10 border border-red-500/40 px-4 py-2 text-sm text-red-300"
                  >
                    {serverError}
                  </motion.div>
                )}
              </AnimatePresence>

              {/* Form */}
              <form onSubmit={handleSubmit} className="space-y-5">
                {/* Full Name */}
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.4 }}
                >
                  <Label htmlFor="fullName" className="text-white mb-2 block">
                    {isArabic ? 'الاسم الكامل' : 'Full Name'}
                  </Label>
                  <div className="relative">
                    <User
                      className={`absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 transition-all duration-300 ${
                        focusedField === 'fullName'
                          ? 'text-[#64FFDA]'
                          : 'text-gray-400'
                      }`}
                    />
                    <Input
                      id="fullName"
                      type="text"
                      placeholder={isArabic ? 'أدخل اسمك الكامل' : 'Enter your full name'}
                      autoComplete="name"
                      value={formData.fullName}
                      onChange={(e) =>
                        handleInputChange('fullName', e.target.value)
                      }
                      onFocus={() => setFocusedField('fullName')}
                      onBlur={() => setFocusedField(null)}
                      className={`pl-12 h-12 bg-white/5 border-white/10 text-white placeholder-gray-400 
                        rounded-xl transition-all duration-300 backdrop-blur-sm
                        focus:border-[#64FFDA] focus:ring-2 focus:ring-[#64FFDA]/20 focus:bg-white/10
                        hover:border-white/20 hover:bg-white/5
                        ${
                          focusedField === 'fullName'
                            ? 'shadow-lg shadow-[#64FFDA]/20'
                            : ''
                        }
                        ${
                          validationErrors.fullName ? 'border-red-500' : ''
                        }`}
                      required
                    />
                  </div>
                  <AnimatePresence>
                    {validationErrors.fullName && (
                      <motion.p
                        initial={{ opacity: 0, y: -10 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -10 }}
                        className="text-red-400 text-sm mt-1"
                      >
                        {validationErrors.fullName}
                      </motion.p>
                    )}
                  </AnimatePresence>
                </motion.div>

                {/* Email */}
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.5 }}
                >
                  <Label htmlFor="email" className="text-white mb-2 block">
                    {isArabic ? 'البريد الإلكتروني' : 'Email Address'}
                  </Label>
                  <div className="relative">
                    <Mail
                      className={`absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 transition-all duration-300 ${
                        focusedField === 'email'
                          ? 'text-[#64FFDA]'
                          : 'text-gray-400'
                      }`}
                    />
                    <Input
                      id="email"
                      type="email"
                      placeholder={isArabic ? 'أدخل بريدك الإلكتروني' : 'Enter your email'}
                      autoComplete="email"
                      value={formData.email}
                      onChange={(e) =>
                        handleInputChange('email', e.target.value)
                      }
                      onFocus={() => setFocusedField('email')}
                      onBlur={() => setFocusedField(null)}
                      className={`pl-12 h-12 bg-white/5 border-white/10 text-white placeholder-gray-400 
                        rounded-xl transition-all duration-300 backdrop-blur-sm
                        focus:border-[#64FFDA] focus:ring-2 focus:ring-[#64FFDA]/20 focus:bg-white/10
                        hover:border-white/20 hover:bg-white/5
                        ${
                          focusedField === 'email'
                            ? 'shadow-lg shadow-[#64FFDA]/20'
                            : ''
                        }
                        ${
                          validationErrors.email ? 'border-red-500' : ''
                        }`}
                      required
                    />
                    <AnimatePresence>
                      {validationErrors.email && (
                        <motion.p
                          initial={{ opacity: 0, y: -10 }}
                          animate={{ opacity: 1, y: 0 }}
                          exit={{ opacity: 0, y: -10 }}
                          className="text-red-400 text-sm mt-1"
                        >
                          {validationErrors.email}
                        </motion.p>
                      )}
                    </AnimatePresence>
                  </div>
                </motion.div>

                {/* Password */}
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.7 }}
                >
                  <Label htmlFor="password" className="text-white mb-2 block">
                    {isArabic ? 'كلمة المرور' : 'Password'}
                  </Label>
                  <div className="relative">
                    <Lock
                      className={`absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 transition-all duration-300 ${
                        focusedField === 'password'
                          ? 'text-[#64FFDA]'
                          : 'text-gray-400'
                      }`}
                    />
                    <Input
                      id="password"
                      type={showPassword ? 'text' : 'password'}
                      placeholder={isArabic ? 'أنشئ كلمة مرور قوية' : 'Create a strong password'}
                      autoComplete="new-password"
                      value={formData.password}
                      onChange={(e) =>
                        handleInputChange('password', e.target.value)
                      }
                      onFocus={() => setFocusedField('password')}
                      onBlur={() => setFocusedField(null)}
                      className={`pl-12 pr-12 h-12 bg-white/5 border-white/10 text-white placeholder-gray-400 
                        rounded-xl transition-all duration-300 backdrop-blur-sm
                        focus:border-[#64FFDA] focus:ring-2 focus:ring-[#64FFDA]/20 focus:bg-white/10
                        hover:border-white/20 hover:bg-white/5
                        ${
                          focusedField === 'password'
                            ? 'shadow-lg shadow-[#64FFDA]/20'
                            : ''
                        }
                        ${
                          validationErrors.password ? 'border-red-500' : ''
                        }`}
                      required
                    />
                    <motion.button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-4 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-[#64FFDA] transition-colors duration-300"
                      whileHover={{ scale: 1.1 }}
                      whileTap={{ scale: 0.9 }}
                    >
                      {showPassword ? (
                        <EyeOff className="w-5 h-5" />
                      ) : (
                        <Eye className="w-5 h-5" />
                      )}
                    </motion.button>
                  </div>

                  {/* Password strength */}
                  {formData.password && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: 'auto' }}
                      className="mt-3"
                    >
                      <div className="flex space-x-1 mb-2">
                        {[1, 2, 3, 4, 5].map((level) => (
                          <motion.div
                            key={level}
                            className="h-2 flex-1 rounded-full transition-all duration-300"
                            style={{
                              backgroundColor:
                                passwordStrength >= level
                                  ? strengthColors[passwordStrength - 1]
                                  : '#374151',
                            }}
                            initial={{ scaleX: 0 }}
                            animate={{
                              scaleX: passwordStrength >= level ? 1 : 0.3,
                            }}
                            transition={{ delay: level * 0.1 }}
                          />
                        ))}
                      </div>
                      <p className="text-xs text-gray-400">
                        {isArabic ? 'القوة:' : 'Strength:'}{' '}
                        <span
                          style={{
                            color:
                              passwordStrength > 0
                                ? strengthColors[passwordStrength - 1]
                                : '#9CA3AF',
                          }}
                        >
                          {strengthLabels[passwordStrength - 1] ||
                            (isArabic ? 'ضعيفة جدًا' : 'Very Weak')}
                        </span>
                      </p>
                    </motion.div>
                  )}

                  <AnimatePresence>
                    {validationErrors.password && (
                      <motion.p
                        initial={{ opacity: 0, y: -10 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -10 }}
                        className="text-red-400 text-sm mt-1"
                      >
                        {validationErrors.password}
                      </motion.p>
                    )}
                  </AnimatePresence>
                </motion.div>

                {/* Confirm Password */}
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.8 }}
                >
                  <Label
                    htmlFor="confirmPassword"
                    className="text-white mb-2 block"
                  >
                    {isArabic ? 'تأكيد كلمة المرور' : 'Confirm Password'}
                  </Label>
                  <div className="relative">
                    <Lock
                      className={`absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 transition-all duration-300 ${
                        focusedField === 'confirmPassword'
                          ? 'text-[#64FFDA]'
                          : 'text-gray-400'
                      }`}
                    />
                    <Input
                      id="confirmPassword"
                      type={showConfirmPassword ? 'text' : 'password'}
                      placeholder={isArabic ? 'أكد كلمة المرور' : 'Confirm your password'}
                      autoComplete="new-password"
                      value={formData.confirmPassword}
                      onChange={(e) =>
                        handleInputChange('confirmPassword', e.target.value)
                      }
                      onFocus={() => setFocusedField('confirmPassword')}
                      onBlur={() => setFocusedField(null)}
                      className={`pl-12 pr-12 h-12 bg-white/5 border-white/10 text-white placeholder-gray-400 
                        rounded-xl transition-all duration-300 backdrop-blur-sm
                        focus:border-[#64FFDA] focus:ring-2 focus:ring-[#64FFDA]/20 focus:bg-white/10
                        hover:border-white/20 hover:bg-white/5
                        ${
                          focusedField === 'confirmPassword'
                            ? 'shadow-lg shadow-[#64FFDA]/20'
                            : ''
                        }
                        ${
                          validationErrors.confirmPassword
                            ? 'border-red-500'
                            : ''
                        }
                        ${
                          formData.confirmPassword &&
                          formData.password === formData.confirmPassword
                            ? 'border-[#10B981]'
                            : ''
                        }`}
                      required
                    />
                    <motion.button
                      type="button"
                      onClick={() =>
                        setShowConfirmPassword(!showConfirmPassword)
                      }
                      className="absolute right-4 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-[#64FFDA] transition-colors duration-300"
                      whileHover={{ scale: 1.1 }}
                      whileTap={{ scale: 0.9 }}
                    >
                      {showConfirmPassword ? (
                        <EyeOff className="w-5 h-5" />
                      ) : (
                        <Eye className="w-5 h-5" />
                      )}
                    </motion.button>
                  </div>

                  <AnimatePresence>
                    {validationErrors.confirmPassword && (
                      <motion.p
                        initial={{ opacity: 0, y: -10 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -10 }}
                        className="text-red-400 text-sm mt-1"
                      >
                        {validationErrors.confirmPassword}
                      </motion.p>
                    )}
                  </AnimatePresence>
                </motion.div>

                {/* Terms & Conditions */}
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.9 }}
                  className="flex items-start space-x-3"
                >
                  <Checkbox
                    id="terms"
                    checked={formData.acceptTerms}
                    onCheckedChange={(checked: CheckedState) =>
                      handleInputChange('acceptTerms', checked === true)
                    }
                    className="border-white/20 data-[state=checked]:bg-[#64FFDA] data-[state=checked]:border-[#64FFDA] rounded-md mt-1"
                  />
                  <label
                    htmlFor="terms"
                    className="text-sm text-gray-300 select-none cursor-pointer"
                  >
                    {isArabic ? 'أوافق على ' : 'I agree to the '}
                    <motion.span
                      className="text-[#64FFDA] hover:text-[#3B82F6] cursor-pointer"
                      whileHover={{ scale: 1.05 }}
                    >
                      {isArabic ? 'شروط الخدمة' : 'Terms of Service'}
                    </motion.span>{' '}
                    {isArabic ? ' و' : ' and '}
                    <motion.span
                      className="text-[#64FFDA] hover:text-[#3B82F6] cursor-pointer"
                      whileHover={{ scale: 1.05 }}
                    >
                      {isArabic ? 'سياسة الخصوصية' : 'Privacy Policy'}
                    </motion.span>
                  </label>
                </motion.div>
                <AnimatePresence>
                  {validationErrors.acceptTerms && (
                    <motion.p
                      initial={{ opacity: 0, y: -10 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -10 }}
                      className="text-red-400 text-sm mt-1"
                    >
                      {validationErrors.acceptTerms}
                    </motion.p>
                  )}
                </AnimatePresence>

                {/* Submit Button */}
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 1.0 }}
                >
                  <Button
                    type="submit"
                    disabled={
                      !formData.acceptTerms ||
                      isLoading ||
                      Object.keys(validationErrors).length > 0
                    }
                    className="w-full h-12 bg-gradient-to-r from-[#3B82F6] to-[#64FFDA] hover:from-[#2563EB] hover:to-[#10B981] text-black font-medium rounded-xl transition-all duration-300 shadow-lg disabled:opacity-50 relative overflow-hidden group"
                  >
                    <motion.div
                      className="absolute inset-0 bg-gradient-to-r from-[#64FFDA] to-[#3B82F6] opacity-0 group-hover:opacity-100 transition-opacity duration-300"
                      animate={{
                        x: isLoading ? ['-100%', '100%'] : '0%',
                      }}
                      transition={{
                        duration: 1.5,
                        repeat: isLoading ? Infinity : 0,
                        ease: 'easeInOut',
                      }}
                    />

                    <div className="relative flex items-center justify-center space-x-2">
                      <AnimatePresence mode="wait">
                        {isLoading ? (
                          <motion.div
                            key="loading"
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            className="flex items-center space-x-2"
                          >
                            <motion.div
                              className="w-5 h-5 border-2 border-black border-t-transparent rounded-full"
                              animate={{ rotate: 360 }}
                              transition={{
                                duration: 1,
                                repeat: Infinity,
                                ease: 'linear',
                              }}
                            />
                            <span>
                              {isArabic ? 'جارٍ إنشاء الحساب...' : 'Creating Account...'}
                            </span>
                          </motion.div>
                        ) : (
                          <motion.div
                            key="create"
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            className="flex items-center space-x-2"
                          >
                            <Sparkles className="w-4 h-4 group-hover:animate-pulse" />
                            <span>{isArabic ? 'إنشاء حساب' : 'Create Account'}</span>
                            <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform duration-300" />
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </div>
                  </Button>
                </motion.div>

                {/* Sign In Link */}
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 1.1 }}
                  className="text-center pt-4"
                >
                  <p className="text-gray-400">
                    {isArabic ? 'لديك حساب بالفعل؟ ' : 'Already have an account? '}
                    <motion.button
                      type="button"
                      onClick={() => navigate('/login')}
                      className="text-[#64FFDA] hover:text-[#3B82F6] font-medium transition-colors duration-300"
                      whileHover={{ scale: 1.05 }}
                      whileTap={{ scale: 0.95 }}
                    >
                      {isArabic ? 'تسجيل الدخول' : 'Sign In'}
                    </motion.button>
                  </p>
                </motion.div>
              </form>
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
}


