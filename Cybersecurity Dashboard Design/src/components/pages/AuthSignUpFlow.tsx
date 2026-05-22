import React, { useState } from 'react';
import { motion } from 'motion/react';
import { CheckCircle2 } from 'lucide-react';

import { Button } from '../ui/button';
import { SignUpPage } from './SignUpPage';
import { VerifyEmailPage } from './VerifyEmailPage';
import { TwoFactorPage } from './TwoFactorPage';
import { useLanguage } from '../../contexts/LanguageContext';

type AuthStep = 'signup' | 'verify-email' | '2fa' | 'done';

interface AuthSignUpFlowProps {
  onFinished?: () => void;
}

export const AuthSignUpFlow: React.FC<AuthSignUpFlowProps> = ({ onFinished }) => {
  const [step, setStep] = useState<AuthStep>('signup');
  const [email, setEmail] = useState<string>('');
  const { language, isRtl } = useLanguage();
  const isArabic = language === 'arabic';

  const handleInternalNavigate = (page: string) => {
    switch (page) {
      case 'signup':
        setStep('signup');
        break;
      case 'verify-email':
        if (email) setStep('verify-email');
        break;
      case '2fa':
        if (email) setStep('2fa');
        break;
      case 'login':
      case 'dashboard':
        setStep('done');
        onFinished?.();
        break;
      default:
        break;
    }
  };

  if (step === 'signup') {
    return (
      <SignUpPage
        onNavigate={handleInternalNavigate}
        onSignupSuccess={(userEmail: string) => {
          setEmail(userEmail);
          setStep('verify-email');
        }}
      />
    );
  }

  if (step === 'verify-email') {
    return (
      <VerifyEmailPage
        email={email}
        onNavigate={(page: string) => {
          if (page === '2fa') {
            setStep('2fa');
          } else {
            handleInternalNavigate(page);
          }
        }}
      />
    );
  }

  if (step === '2fa') {
    return (
      <TwoFactorPage
        email={email}
        onNavigate={(page: string) => {
          if (page === 'dashboard' || page === 'login') {
            setStep('done');
            onFinished?.();
          } else {
            handleInternalNavigate(page);
          }
        }}
      />
    );
  }

  return (
    <div dir={isRtl ? 'rtl' : 'ltr'} className="min-h-screen bg-[#0F172A] flex items-center justify-center relative overflow-hidden">
      <div className="absolute inset-0">
        <div className="absolute inset-0 bg-gradient-to-br from-[#10B981]/20 via-[#0F172A] to-[#3B82F6]/20" />
      </div>

      <motion.div
        initial={{ opacity: 0, y: 30, scale: 0.9 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        className="relative z-10 w-full max-w-md mx-4"
      >
        <div className="absolute -inset-1 bg-gradient-to-r from-[#64FFDA] to-[#3B82F6] blur opacity-30 rounded-3xl" />
        <div className="relative bg-black/40 border border-white/10 rounded-3xl p-8 backdrop-blur-xl text-center">
          <motion.div
            className="w-20 h-20 mx-auto mb-5 rounded-full bg-gradient-to-br from-[#64FFDA] to-[#22C55E] flex items-center justify-center shadow-xl"
            animate={{
              scale: [1, 1.1, 1],
              boxShadow: [
                '0 0 20px rgba(34,197,94,0.5)',
                '0 0 40px rgba(34,197,94,0.2)',
                '0 0 20px rgba(34,197,94,0.5)',
              ],
            }}
            transition={{ duration: 2.2, repeat: Infinity, ease: 'easeInOut' }}
          >
            <CheckCircle2 className="w-10 h-10 text-black" />
          </motion.div>

          <h2 className="text-2xl font-bold text-white mb-2">
            {isArabic ? 'اكتمل التسجيل الآمن' : 'Secure Sign-Up Complete'}
          </h2>
          <p className="text-gray-300 mb-4 text-sm">
            {isArabic
              ? 'تم التحقق من حسابك وتأمينه بالمصادقة متعددة العوامل.'
              : 'Your account is now verified and protected with multi-factor security.'}
          </p>
          <p className="text-xs text-gray-400 mb-6">
            {isArabic
              ? 'يمكنك الآن تسجيل الدخول إلى Sentinel AI بأمان.'
              : 'You can now safely log in to Sentinel AI.'}
          </p>

          <Button
            className="w-full h-11 bg-gradient-to-r from-[#3B82F6] to-[#64FFDA] text-black font-medium rounded-xl hover:from-[#2563EB] hover:to-[#10B981] transition-all"
            onClick={() => onFinished?.()}
          >
            {isArabic ? 'الانتقال إلى تسجيل الدخول' : 'Go to Login'}
          </Button>
        </div>
      </motion.div>
    </div>
  );
};
