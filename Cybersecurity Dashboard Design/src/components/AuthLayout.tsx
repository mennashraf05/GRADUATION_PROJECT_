import React, { ReactNode } from 'react';
import { motion } from 'motion/react';
import { useNavigate } from 'react-router-dom';
import { Shield, Lock, Eye, AlertTriangle, Zap, CheckCircle, ArrowLeft } from 'lucide-react';
import { Button } from './ui/button';
import { useAppSettings } from '../contexts/AppSettingsContext';

interface AuthLayoutProps {
  children: ReactNode;
  title: string;
  subtitle?: string;
  showBackButton?: boolean;
}

export function AuthLayout({ children, title, subtitle, showBackButton = true }: AuthLayoutProps) {
  const navigate = useNavigate();
  const { applicationName } = useAppSettings();
  // Generate animated shield and lock patterns
  const securityIcons = [
    { Icon: Shield, color: 'text-blue-400', size: 'w-4 h-4' },
    { Icon: Lock, color: 'text-green-400', size: 'w-3 h-3' },
    { Icon: Eye, color: 'text-cyan-400', size: 'w-4 h-4' },
    { Icon: Zap, color: 'text-purple-400', size: 'w-3 h-3' },
  ];

  return (
    <div className="min-h-screen bg-[#0F172A] flex relative overflow-hidden">
      {/* Back Button */}
      {showBackButton && (
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.5 }}
          className="absolute top-6 left-6 z-50"
        >
          <Button
            variant="ghost"
            onClick={() => navigate('/')}
            className="text-gray-300 hover:text-white hover:bg-white/10 transition-all duration-300"
          >
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back to Home
          </Button>
        </motion.div>
      )}

      {/* Animated Background Grid */}
      <div className="absolute inset-0 opacity-10">
        <div className="absolute inset-0" style={{
          backgroundImage: `linear-gradient(rgba(59, 130, 246, 0.1) 1px, transparent 1px),
                           linear-gradient(90deg, rgba(59, 130, 246, 0.1) 1px, transparent 1px)`,
          backgroundSize: '50px 50px'
        }}></div>
      </div>

      {/* Left Side - Branding */}
      <div className="hidden lg:flex lg:w-1/2 relative overflow-hidden">
        {/* Gradient Background */}
        <div className="absolute inset-0 bg-gradient-to-br from-[#0F172A] via-blue-600/10 to-cyan-600/20"></div>
        
        {/* Simplified Security Icons Pattern */}
        <div className="absolute inset-0">
          {[...Array(8)].map((_, i) => {
            const iconData = securityIcons[i % securityIcons.length];
            const Icon = iconData.Icon;
            return (
              <div
                key={i}
                className={`absolute ${iconData.color} ${iconData.size} opacity-10`}
                style={{
                  left: `${15 + (i % 4) * 25}%`,
                  top: `${20 + Math.floor(i / 4) * 30}%`,
                }}
              >
                <Icon />
              </div>
            );
          })}
        </div>

        {/* Simplified Floating Particles */}
        <div className="absolute inset-0">
          {[...Array(6)].map((_, i) => (
            <div
              key={`particle-${i}`}
              className="absolute w-1 h-1 bg-cyan-400/20 rounded-full animate-pulse-slow"
              style={{
                left: `${20 + i * 15}%`,
                top: `${30 + (i % 2) * 40}%`,
              }}
            />
          ))}
        </div>

        {/* Content */}
        <div className="relative z-10 flex flex-col justify-center items-center p-12 text-white">
          <motion.div
            initial={{ scale: 0.8, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ duration: 1, ease: "easeOut" }}
            className="text-center"
          >
            {/* Logo */}
            <div className="w-28 h-28 mb-8 mx-auto relative">
              <div className="absolute inset-0 bg-gradient-to-r from-cyan-400 via-blue-500 to-purple-600 rounded-full"></div>
              <div className="absolute inset-1 bg-[#0F172A] rounded-full flex items-center justify-center">
                <Shield className="w-14 h-14 text-cyan-400" />
              </div>
              <div className="absolute inset-0 rounded-full border-2 border-cyan-400/30"></div>
            </div>
            
            <motion.h1 
              className="text-5xl font-bold mb-4 bg-gradient-to-r from-cyan-400 to-blue-400 bg-clip-text text-transparent"
              initial={{ y: 20, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              transition={{ delay: 0.3 }}
            >
              {applicationName}
            </motion.h1>
            
            <motion.p 
              className="text-xl text-gray-300 mb-12"
              initial={{ y: 20, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              transition={{ delay: 0.4 }}
            >
              Next-Generation Cybersecurity Platform
            </motion.p>
            
            <div className="space-y-6">
              <motion.div 
                className="flex items-center space-x-4 justify-start max-w-sm"
                initial={{ x: -50, opacity: 0 }}
                animate={{ x: 0, opacity: 1 }}
                transition={{ delay: 0.6, duration: 0.6 }}
              >
                <div className="w-10 h-10 bg-green-500/20 rounded-full flex items-center justify-center">
                  <CheckCircle className="w-5 h-5 text-green-400" />
                </div>
                <span className="text-gray-300">Enterprise-Grade Security</span>
              </motion.div>
              
              <motion.div 
                className="flex items-center space-x-4 justify-start max-w-sm"
                initial={{ x: -50, opacity: 0 }}
                animate={{ x: 0, opacity: 1 }}
                transition={{ delay: 0.8, duration: 0.6 }}
              >
                <div className="w-10 h-10 bg-blue-500/20 rounded-full flex items-center justify-center">
                  <Eye className="w-5 h-5 text-blue-400" />
                </div>
                <span className="text-gray-300">Real-time Threat Monitoring</span>
              </motion.div>
              
              <motion.div 
                className="flex items-center space-x-4 justify-start max-w-sm"
                initial={{ x: -50, opacity: 0 }}
                animate={{ x: 0, opacity: 1 }}
                transition={{ delay: 1, duration: 0.6 }}
              >
                <div className="w-10 h-10 bg-purple-500/20 rounded-full flex items-center justify-center">
                  <Zap className="w-5 h-5 text-purple-400" />
                </div>
                <span className="text-gray-300">AI-Powered Detection</span>
              </motion.div>
            </div>
          </motion.div>
        </div>
      </div>

      {/* Right Side - Form */}
      <div className="w-full lg:w-1/2 flex items-center justify-center p-8">
        <motion.div 
          className="w-full max-w-md"
          initial={{ opacity: 0, x: 50 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.8, ease: "easeOut" }}
        >
          <div className="bg-gradient-to-br from-[#111827] to-[#1F2937] p-8 rounded-3xl border border-gray-700/50 shadow-2xl backdrop-blur-sm relative">
            {/* Card Glow Effect */}
            <div className="absolute inset-0 bg-gradient-to-r from-cyan-500/5 to-blue-500/5 rounded-3xl"></div>
            
            <div className="relative z-10">
              <div className="text-center mb-8">
                <div className="lg:hidden w-16 h-16 bg-gradient-to-r from-cyan-400 to-blue-500 rounded-full flex items-center justify-center mx-auto mb-4 shadow-lg shadow-cyan-500/25">
                  <Shield className="w-8 h-8 text-white" />
                </div>
                
                <motion.h2 
                  className="text-3xl font-bold text-white mb-2"
                  initial={{ y: -10, opacity: 0 }}
                  animate={{ y: 0, opacity: 1 }}
                  transition={{ delay: 0.2 }}
                >
                  {title}
                </motion.h2>
                
                {subtitle && (
                  <motion.p 
                    className="text-gray-400"
                    initial={{ y: -10, opacity: 0 }}
                    animate={{ y: 0, opacity: 1 }}
                    transition={{ delay: 0.3 }}
                  >
                    {subtitle}
                  </motion.p>
                )}
              </div>
              
              {children}
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
}
