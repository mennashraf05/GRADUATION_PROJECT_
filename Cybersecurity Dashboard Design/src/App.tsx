import React from "react";
import { BrowserRouter, Navigate, Routes, Route } from "react-router-dom";

// Public Pages
import { HomePage } from "./components/pages/HomePage";
import { DemoPage } from "./components/pages/DemoPage";
import { FeaturesPage } from "./components/pages/FeaturesPage";
import { LearnPage } from "./components/pages/LearnPage";
import { AboutPage } from "./components/pages/AboutPage";
import { ContactPage } from "./components/pages/ContactPage";
import { SignUpPage } from "./components/pages/SignUpPage";
import LoginPage from "./components/pages/LoginPage";

// Auth Pages
import VerifyEmailPage from "./components/pages/VerifyEmailPage";
import { EmailSentPage } from "./components/pages/EmailSentPage";
import { Setup2FAPage } from "./components/pages/Setup2FAPage";
import AcceptInvitationPage from "./components/pages/AcceptInvitationPage";
import { Login2FAPage } from "./components/pages/Login2FAPage";
import { EmergencyLockedPage } from "./components/pages/EmergencyLockedPage";

// Internal (protected) pages
import { SimpleDashboard } from "./components/pages/SimpleDashboard";
import { PasswordCheckerPage } from "./components/pages/PasswordCheckerPage";
import { FileVaultPage } from "./components/pages/FileVaultPage";
import { PhishingScannerPage } from "./components/pages/PhishingScannerPage";
//import { IdentityLeakMonitorPage } from "./components/pages/IdentityLeakMonitorPage";
import { ChatbotWorkspacePage } from "./components/pages/ChatbotWorkspacePage";
import { SettingsPage } from "./components/pages/SettingsPage";
import { MonthlyReportsPage } from "./components/pages/MonthlyReportsPage";
import { UserActivityLogsPage } from "./components/pages/UserActivityLogsPage";

// Admin Pages
import AdminConsolePage from "./components/pages/AdminConsolePage";
import AdminLoginPage from "./components/pages/AdminLoginPage";
import { ForbiddenPage } from "./components/pages/ForbiddenPage";

// Layout
import { Layout } from "./components/Layout";
import { IdentityLeakMonitorPage } from "./components/pages/IdentityLeakMonitorPage";
import { PcapAnalyzerPage } from "./components/pages/PcapAnalyzerPage";
import { Toaster } from "./components/ui/sonner";
export default function App() {
  return (
    <BrowserRouter>
      <>
      <Routes>

        {/* ---------- PUBLIC PAGES ---------- */}
        <Route path="/" element={<HomePage />} />
        <Route path="/demo" element={<DemoPage />} />
        <Route path="/features" element={<FeaturesPage />} />
        <Route path="/learn" element={<LearnPage />} />
        <Route path="/about" element={<AboutPage />} />
        <Route path="/contact" element={<ContactPage />} />
        <Route path="/signup" element={<SignUpPage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/emergency-locked" element={<EmergencyLockedPage />} />

        {/* ---------- AUTH FLOW ---------- */}
        <Route path="/email-sent" element={<EmailSentPage />} />
        <Route path="/verify-email" element={<VerifyEmailPage />} />
        <Route path="/accept-invitation" element={<AcceptInvitationPage />} />
        <Route path="/setup-2fa" element={<Setup2FAPage />} />
        <Route path="/login-2fa" element={<Login2FAPage />} />

        {/* ---------- PROTECTED AREA WITH LAYOUT ---------- */}
        <Route
          path="/dashboard"
          element={
            <Layout>
              <SimpleDashboard />
            </Layout>
          }
        />

        <Route
          path="/password-checker"
          element={
            <Layout>
              <PasswordCheckerPage />
            </Layout>
          }
        />

        <Route
          path="/file-vault"
          element={
            <Layout>
              <FileVaultPage />
            </Layout>
          }
        />

        <Route
          path="/phishing-scanner"
          element={
            <Layout>
              <PhishingScannerPage />
            </Layout>
          }
        />

        <Route
          path="/identityleak-monitor"
          element={
            <Layout>
              <IdentityLeakMonitorPage />
            </Layout>
          }
        />

        <Route
          path="/ai-threat-detector"
          element={<Navigate to="/dashboard" replace />}
        />

        <Route
          path="/chatbot"
          element={
            <Layout>
              <ChatbotWorkspacePage />
            </Layout>
          }
        />

        <Route
          path="/settings"
          element={
            <Layout>
              <SettingsPage />
            </Layout>
          }
        />
        <Route
          path="/monthly-reports"
          element={
            <Layout>
              <MonthlyReportsPage />
            </Layout>
          }
        />
        <Route
          path="/user-activity-logs"
          element={
            <Layout>
              <UserActivityLogsPage />
            </Layout>
          }
        />
        <Route
          path="/pcap-analyzer"
          element={
            <Layout hideSearch>
              <PcapAnalyzerPage />
            </Layout>
          }
        />
        {/* ---------- ADMIN ---------- */}
        <Route path="/admin/login" element={<AdminLoginPage />} />
        <Route
          path="/admin/console"
          element={
            localStorage.getItem("sentinel_admin_token") ? (
              <AdminConsolePage />
            ) : (
              <Navigate to="/forbidden" replace />
            )
          }
        />
        <Route path="/forbidden" element={<ForbiddenPage />} />

      </Routes>
      <Toaster
        position="top-right"
        richColors
        closeButton
        toastOptions={{
          style: {
            background: "rgba(8, 17, 31, 0.96)",
            border: "1px solid rgba(148, 163, 184, 0.16)",
            color: "#e2e8f0",
          },
        }}
      />
      </>
    </BrowserRouter>
  );
}
