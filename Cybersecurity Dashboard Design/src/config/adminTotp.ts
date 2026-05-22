import { Secret, TOTP } from 'otpauth';

const STORAGE_KEY = 'sentinel_admin_totp_secret_base32';

export function generateNewTotpSecretBase32(): string {
  return new Secret({ size: 20 }).base32;
}

function totpInstance(secretBase32: string, label: string): TOTP {
  return new TOTP({
    issuer: 'Sentinel AI',
    label,
    issuerInLabel: true,
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret: Secret.fromBase32(secretBase32),
  });
}

/** Google Authenticator–compatible otpauth URI for QR. */
export function totpProvisioningUri(secretBase32: string, accountLabel: string): string {
  return totpInstance(secretBase32, accountLabel).toString();
}

/** Must use the same label as in the provisioning URI (usually the admin email). */
export function verifyAdminTotp(secretBase32: string, token: string, accountLabel: string): boolean {
  const totp = totpInstance(secretBase32, accountLabel);
  return totp.validate({ token: token.replace(/\s/g, ''), window: 2 }) !== null;
}

export function getStoredAdminTotpSecret(): string | null {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    return v && v.length > 0 ? v : null;
  } catch {
    return null;
  }
}

export function saveStoredAdminTotpSecret(base32: string): void {
  localStorage.setItem(STORAGE_KEY, base32);
}

export function clearStoredAdminTotpSecret(): void {
  localStorage.removeItem(STORAGE_KEY);
}
