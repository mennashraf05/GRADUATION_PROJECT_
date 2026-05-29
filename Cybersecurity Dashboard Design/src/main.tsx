// src/main.tsx
import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import "./index.css";
import { LanguageProvider } from "./contexts/LanguageContext";
import { AppSettingsProvider } from "./contexts/AppSettingsContext";

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <LanguageProvider>
      <AppSettingsProvider>
        <App />
      </AppSettingsProvider>
    </LanguageProvider>
  </React.StrictMode>
);
