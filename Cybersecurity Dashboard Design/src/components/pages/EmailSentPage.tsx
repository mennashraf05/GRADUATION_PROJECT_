// src/components/pages/EmailSentPage.tsx
import React from "react";
import { motion } from "motion/react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Mail, ArrowLeft } from "lucide-react";
import { Button } from "../ui/button";
import { useLanguage } from "../../contexts/LanguageContext";

export const EmailSentPage: React.FC = () => {
  const { language, isRtl } = useLanguage();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const email = searchParams.get('email') || (language === 'arabic' ? 'بريدك الإلكتروني' : 'your email');
  return (
    <div className="min-h-screen bg-[#0F172A] relative overflow-hidden flex items-center justify-center text-white" dir={isRtl ? "rtl" : "ltr"}>

      {/* Background Lines */}
      <div className="absolute inset-0">
        <motion.div
          className="absolute w-full h-0.5 bg-gradient-to-r from-transparent via-[#64FFDA] to-transparent"
          animate={{ y: ["-10%", "110%"], opacity: [0, 1, 0] }}
          transition={{ duration: 10, repeat: Infinity, ease: "linear" }}
        />

        <motion.div
          className="absolute w-0.5 h-full bg-gradient-to-b from-transparent via-[#3B82F6] to-transparent"
          animate={{ x: ["-10%", "110%"], opacity: [0, 1, 0] }}
          transition={{
            duration: 8,
            repeat: Infinity,
            delay: 3,
            ease: "linear",
          }}
        />
      </div>

      {/* Card */}
      <motion.div
        initial={{ opacity: 0, scale: 0.9, y: 20 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        className="relative z-10 w-full max-w-md bg-black/20 backdrop-blur-xl border border-white/10 rounded-2xl p-8 text-center shadow-2xl"
      >
        {/* Back Button */}
        <div className="flex justify-between mb-2">
          <Button
            variant="ghost"
            size="icon"
            onClick={() => navigate("/signup")}
            className="text-gray-400 hover:text-white hover:bg-white/5"
          >
            <ArrowLeft className="w-5 h-5" />
          </Button>
        </div>

        <div className="flex flex-col items-center space-y-4">
          <div className="w-16 h-16 rounded-full bg-blue-500/20 border border-blue-500/40 flex items-center justify-center">
            <Mail className="w-10 h-10 text-blue-400" />
          </div>

          <h1 className="text-2xl font-bold">{language === "arabic" ? "تحقق من بريدك الوارد" : "Check your inbox"}</h1>

          <p className="text-gray-300 text-sm">
            {language === "arabic" ? "تم إرسال رابط التحقق إلى:" : "A verification link has been sent to:"}
          </p>

          <p className="text-[#64FFDA] font-semibold break-all">
            {email}
          </p>

          <p className="text-gray-400 text-sm max-w-xs">
            {language === "arabic"
              ? "اضغط على الرابط داخل البريد لتفعيل حسابك. بعد التحقق ستكمل عملية التسجيل تلقائيًا."
              : "Click the link inside your email to activate your account. After verifying, you'll automatically continue the sign-up process."}
          </p>

          <Button
            onClick={() => navigate("/login")}
            className="w-full h-11 bg-gradient-to-r from-[#3B82F6] to-[#64FFDA] text-black font-medium rounded-xl mt-4"
          >
            {language === "arabic" ? "العودة إلى تسجيل الدخول" : "Back to Sign In"}
          </Button>
        </div>
      </motion.div>

    </div>
  );
};
