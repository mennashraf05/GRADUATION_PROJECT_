import React, { ReactNode, createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';

const DEFAULT_APPLICATION_NAME = 'Sentinel AI';
const APPLICATION_NAME_STORAGE_KEY = 'sentinel_application_name';

const API_BASE_URL =
  import.meta.env.DEV ? '' : (import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000');

interface AppSettingsContextValue {
  applicationName: string;
  refreshApplicationName: (nextName?: string) => Promise<void>;
}

const AppSettingsContext = createContext<AppSettingsContextValue | undefined>(undefined);

function normalizeApplicationName(value: unknown): string {
  const candidate = String(value || '').trim().slice(0, 120);
  return candidate || DEFAULT_APPLICATION_NAME;
}

function readCachedApplicationName(): string {
  if (typeof window === 'undefined') {
    return DEFAULT_APPLICATION_NAME;
  }
  return normalizeApplicationName(window.localStorage.getItem(APPLICATION_NAME_STORAGE_KEY));
}

export function AppSettingsProvider({ children }: { children: ReactNode }) {
  const [applicationName, setApplicationName] = useState(readCachedApplicationName);

  const applyApplicationName = useCallback((nextName: unknown) => {
    const normalized = normalizeApplicationName(nextName);
    setApplicationName(normalized);
    if (typeof window !== 'undefined') {
      window.localStorage.setItem(APPLICATION_NAME_STORAGE_KEY, normalized);
    }
    if (typeof document !== 'undefined') {
      document.title = normalized;
    }
  }, []);

  const refreshApplicationName = useCallback(async (nextName?: string) => {
    if (typeof nextName === 'string') {
      applyApplicationName(nextName);
      return;
    }

    const response = await fetch(`${API_BASE_URL || ''}/api/public/app-settings`, {
      cache: 'no-store',
      credentials: 'include',
    });
    if (!response.ok) {
      throw new Error('Application settings could not be loaded.');
    }
    const payload = await response.json();
    applyApplicationName(payload?.settings?.applicationName);
  }, [applyApplicationName]);

  useEffect(() => {
    void refreshApplicationName().catch(() => {
      applyApplicationName(readCachedApplicationName());
    });
  }, [applyApplicationName, refreshApplicationName]);

  const value = useMemo(
    () => ({
      applicationName,
      refreshApplicationName,
    }),
    [applicationName, refreshApplicationName],
  );

  return (
    <AppSettingsContext.Provider value={value}>
      {children}
    </AppSettingsContext.Provider>
  );
}

export function useAppSettings() {
  const context = useContext(AppSettingsContext);
  if (!context) {
    throw new Error('useAppSettings must be used inside AppSettingsProvider');
  }
  return context;
}
