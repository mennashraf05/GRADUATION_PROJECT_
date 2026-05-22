import {
  clearRecentPcapAlertSessionCache,
  setActiveRecentPcapAlertScopeForUser,
} from "./recentPcapAlerts";

export type EmergencyModeState = {
  message: string;
  panicModeUntil: string | null;
};

export const EMERGENCY_MODE_STORAGE_KEY = "sentinel_emergency_mode_state";

export function clearLocalAuthSession(): void {
  localStorage.removeItem("sentinel_auth_token");
  localStorage.removeItem("sentinel_refresh_token");
  localStorage.removeItem("sentinel_admin_token");
  localStorage.removeItem("sentinel_pending_2fa_token");
  localStorage.removeItem("sentinel_intended_page");
  localStorage.removeItem("userEmail");
  clearRecentPcapAlertSessionCache();
  setActiveRecentPcapAlertScopeForUser(null);
}

export function persistEmergencyModeState(state: EmergencyModeState): void {
  localStorage.setItem(EMERGENCY_MODE_STORAGE_KEY, JSON.stringify(state));
}

export function readEmergencyModeState(): EmergencyModeState | null {
  const raw = localStorage.getItem(EMERGENCY_MODE_STORAGE_KEY);
  if (!raw) {
    return null;
  }

  try {
    const parsed = JSON.parse(raw) as Partial<EmergencyModeState>;
    return {
      message:
        typeof parsed.message === "string" && parsed.message.trim()
          ? parsed.message
          : "Emergency Mode activated. All sessions were signed out and your account is temporarily protected.",
      panicModeUntil:
        typeof parsed.panicModeUntil === "string" && parsed.panicModeUntil.trim()
          ? parsed.panicModeUntil
          : null,
    };
  } catch {
    return null;
  }
}

export function clearEmergencyModeState(): void {
  localStorage.removeItem(EMERGENCY_MODE_STORAGE_KEY);
}
