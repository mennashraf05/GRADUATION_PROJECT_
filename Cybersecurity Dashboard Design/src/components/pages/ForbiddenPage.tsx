import React from 'react';
import { motion } from 'motion/react';
import { useNavigate } from 'react-router-dom';
import { ShieldAlert, Lock, ArrowLeft } from 'lucide-react';
import { Button } from '../ui/button';
import { Card } from '../ui/card';
import { useLanguage } from '../../contexts/LanguageContext';
import { useAppSettings } from '../../contexts/AppSettingsContext';

export const ForbiddenPage: React.FC = () => {
  const navigate = useNavigate();
  const { language, isRtl } = useLanguage();
  const { applicationName } = useAppSettings();
  const isArabic = language === 'arabic';
  return (
    <div dir={isRtl ? 'rtl' : 'ltr'} className="min-h-screen bg-[#0B0F19] flex items-center justify-center p-4">
      {/* Background gradient effects */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-red-500/10 rounded-full blur-3xl"></div>
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-orange-500/10 rounded-full blur-3xl"></div>
      </div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="w-full max-w-2xl relative z-10"
      >
        <Card className="bg-[#1E293B] border-red-500/30 p-12 text-center shadow-2xl">
          {/* Error Icon */}
          <motion.div
            initial={{ scale: 0.5, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ duration: 0.5, delay: 0.1 }}
            className="flex justify-center mb-6"
          >
            <div className="relative">
              <div className="absolute inset-0 bg-red-500/20 rounded-full blur-xl"></div>
              <div className="relative inline-flex items-center justify-center w-24 h-24 rounded-full bg-gradient-to-br from-red-500 to-orange-600 shadow-lg">
                <ShieldAlert className="w-12 h-12 text-white" />
              </div>
            </div>
          </motion.div>

          {/* Error Code */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.2 }}
            className="mb-4"
          >
            <h1 className="text-8xl text-red-400 mb-2 tracking-tight">403</h1>
            <div className="h-1 w-32 mx-auto bg-gradient-to-r from-transparent via-red-500 to-transparent"></div>
          </motion.div>

          {/* Error Message */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="mb-8"
          >
            <h2 className="text-3xl text-white mb-4">{isArabic ? 'الوصول مرفوض' : 'Access Forbidden'}</h2>
            <p className="text-gray-400 text-lg mb-2">
              {isArabic ? 'ليست لديك صلاحية للوصول إلى هذه المنطقة.' : 'You do not have permission to access this area.'}
            </p>
            <p className="text-gray-500">
              {isArabic ? 'هذا القسم يتطلب صلاحيات إدارية.' : 'This section requires administrative privileges.'}
            </p>
          </motion.div>

          {/* Security Notice */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4 }}
            className="mb-8 p-6 bg-red-500/10 border border-red-500/30 rounded-xl"
          >
            <div className={`flex items-start gap-3 ${isRtl ? 'text-right' : 'text-left'}`}>
              <Lock className="w-5 h-5 text-red-400 mt-0.5 flex-shrink-0" />
              <div>
                <h3 className="text-white mb-2">{isArabic ? 'إشعار أمني' : 'Security Notice'}</h3>
                <p className="text-sm text-gray-400">
                  {isArabic
                    ? 'تم تسجيل محاولة الوصول هذه. إذا كنت تعتقد أنه يجب أن يكون لديك وصول إلى هذه المنطقة، يرجى التواصل مع مسؤول النظام أو تسجيل الدخول ببيانات مدير النظام.'
                    : 'This access attempt has been logged. If you believe you should have access to this area, please contact your system administrator or try logging in with administrator credentials.'}
                </p>
              </div>
            </div>
          </motion.div>

          {/* Action Buttons */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.5 }}
            className="flex flex-col sm:flex-row gap-4 justify-center"
          >
            <Button
              onClick={() => navigate('/')}
              variant="outline"
              className="bg-transparent border-white/20 text-white hover:bg-white/10 h-12 px-6 rounded-xl"
            >
              <ArrowLeft className={`w-4 h-4 ${isRtl ? 'ml-2' : 'mr-2'}`} />
              {isArabic ? 'الذهاب إلى الرئيسية' : 'Go to Homepage'}
            </Button>
            <Button
              onClick={() => navigate('/admin/login')}
              className="bg-gradient-to-r from-orange-500 to-red-600 hover:from-orange-600 hover:to-red-700 text-white h-12 px-6 rounded-xl shadow-lg shadow-orange-500/20"
            >
              <Lock className={`w-4 h-4 ${isRtl ? 'ml-2' : 'mr-2'}`} />
              {isArabic ? 'دخول الإدارة' : 'Admin Login'}
            </Button>
          </motion.div>
        </Card>

        {/* Footer */}
        <motion.p
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.6 }}
          className="text-center text-sm text-gray-500 mt-6"
        >
          {applicationName} Security Platform - All access is monitored
        </motion.p>
      </motion.div>
    </div>
  );
};

export default ForbiddenPage;
