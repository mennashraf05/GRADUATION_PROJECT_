function adminConfig() {
  return {
    email: String(import.meta.env.VITE_ADMIN_EMAIL ?? '').trim(),
    password: String(import.meta.env.VITE_ADMIN_PASSWORD ?? '').trim(),
  };
}

export function isAdminLoginConfigured(): boolean {
  const c = adminConfig();
  return Boolean(c.email && c.password);
}

export function adminCredentialsMatch(email: string, password: string): boolean {
  const c = adminConfig();
  return email.trim() === c.email && password === c.password;
}
