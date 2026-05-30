import React, { useEffect, useRef, useState } from "react";
import {
  AlertTriangle,
  CheckCircle,
  Database,
  Download,
  Eye,
  EyeOff,
  FileText,
  FolderOpen,
  HardDrive,
  KeyRound,
  Loader2,
  Lock,
  RefreshCw,
  Search,
  ShieldCheck,
  Trash2,
  Upload,
  Wifi,
  WifiOff,
} from "lucide-react";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Progress } from "../ui/progress";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../ui/table";
import { useLanguage } from "../../contexts/LanguageContext";
import {
  deleteOfflineFile,
  decryptOfflineBlob,
  encryptOfflineBlob,
  getOfflineFile,
  saveOfflineFile,
} from "../../utils/offlineVault";

const API_BASE_URL = (() => {
  const configured = String((import.meta as any).env?.VITE_API_BASE_URL || "")
    .trim()
    .replace(/\/+$/, "");
  if (configured) return configured;
  if (typeof window !== "undefined") {
    const host =
      window.location.hostname === "127.0.0.1" ? "127.0.0.1" : "localhost";
    const protocol = window.location.protocol === "https:" ? "https:" : "http:";
    return `${protocol}//${host}:5000`;
  }
  return "https://localhost:5000";
})();

const SECURITY_BLOCKED_FILE_TYPE_MESSAGE =
  "This file type is not allowed for security reasons.";

const DEFAULT_ALLOWED_EXTENSIONS = new Set([
  "pdf",
  "doc",
  "docx",
  "txt",
  "xls",
  "xlsx",
  "ppt",
  "pptx",
  "jpg",
  "jpeg",
  "png",
  "gif",
  "webp",
  "csv",
  "py",
  "js",
  "ts",
  "jsx",
  "tsx",
  "java",
  "c",
  "cpp",
  "h",
  "hpp",
  "cs",
  "go",
  "rs",
  "html",
  "css",
  "scss",
  "json",
  "xml",
  "yml",
  "yaml",
  "md",
  "ini",
  "cfg",
  "toml",
]);

const DEFAULT_BLOCKED_EXTENSIONS = new Set([
  "exe",
  "dll",
  "bat",
  "cmd",
  "ps1",
  "sh",
  "php",
  "jsp",
  "asp",
  "aspx",
  "jar",
  "vbs",
  "scr",
  "msi",
  "com",
  "pif",
  "hta",
  "cpl",
  "reg",
  "lnk",
  "env",
  "key",
  "pem",
  "p12",
  "pfx",
  "sqlite",
  "db",
  "sql",
]);

const getAuthHeaders = (): Record<string, string> => {
  const token = localStorage.getItem("sentinel_auth_token");
  if (!token || token === "cookie_based") return {};
  return { Authorization: `Bearer ${token}` };
};

type VaultDoc = {
  id: number;
  filename: string;
  upload_date: string;
  size_bytes: number;
  offline_enabled: boolean;
};

type VaultFile = {
  id: number;
  name: string;
  sizeBytes: number;
  sizeDisplay: string;
  uploadedAt: string;
  type: string;
  offlineEnabled: boolean;
};

type PasswordModalMode = "download" | "delete" | "offline";

type VaultRules = {
  allowed_extensions?: string[];
  blocked_extensions?: string[];
};

export function FileVaultPage() {
  const { isRtl, formatDateTime } = useLanguage();

  const [files, setFiles] = useState<VaultFile[]>([]);
  const [loading, setLoading] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [dragActive, setDragActive] = useState(false);
  const [error, setError] = useState("");
  const [successMsg, setSuccessMsg] = useState("");
  const [vaultPassword, setVaultPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [fileSearch, setFileSearch] = useState("");
  const [allowedExtensions, setAllowedExtensions] = useState(
    DEFAULT_ALLOWED_EXTENSIONS
  );
  const [blockedExtensions, setBlockedExtensions] = useState(
    DEFAULT_BLOCKED_EXTENSIONS
  );

  const [passwordModalOpen, setPasswordModalOpen] = useState(false);
  const [passwordModalMode, setPasswordModalMode] =
    useState<PasswordModalMode>("download");
  const [passwordModalFile, setPasswordModalFile] =
    useState<VaultFile | null>(null);
  const [modalPassword, setModalPassword] = useState("");
  const [modalLoading, setModalLoading] = useState(false);

  const uploadInputRef = useRef<HTMLInputElement | null>(null);

  const validateVaultPassword = (password: string): string | null => {
    if (password.length < 8) return "Password must be at least 8 characters";
    if (!/[A-Z]/.test(password))
      return "Password must contain an uppercase letter";
    if (!/[a-z]/.test(password))
      return "Password must contain a lowercase letter";
    if (!/[0-9]/.test(password)) return "Password must contain a number";
    if (!/[^A-Za-z0-9]/.test(password))
      return "Password must contain a special character";
    return null;
  };

  const formatFileSize = (bytes: number): string => {
    if (!bytes || bytes <= 0) return "0 B";
    const units = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
  };

  const getFileType = (filename: string): string => {
    const parts = filename.split(".");
    return parts.length < 2 ? "file" : parts[parts.length - 1].toLowerCase();
  };

  const parseResponse = async (res: Response) => {
    const text = await res.text();
    try {
      return text ? JSON.parse(text) : {};
    } catch {
      return { raw: text };
    }
  };

  const normalizeExtensions = (items: unknown): string[] => {
    if (!Array.isArray(items)) return [];
    return items
      .map((item) => String(item || "").trim().toLowerCase().replace(/^\.+/, ""))
      .filter(Boolean);
  };

  const refreshAuthSession = async (): Promise<boolean> => {
    const refreshToken = localStorage.getItem("sentinel_refresh_token");
    const res = await fetch(`${API_BASE_URL}/api/auth/refresh`, {
      method: "POST",
      credentials: "include",
      headers: refreshToken ? { "Content-Type": "application/json" } : undefined,
      body: refreshToken ? JSON.stringify({ refresh_token: refreshToken }) : undefined,
    });

    const data = await parseResponse(res);
    if (!res.ok || data.success === false) return false;

    if (typeof data.token === "string" && data.token) {
      localStorage.setItem("sentinel_auth_token", data.token);
    }
    if (typeof data.refresh_token === "string" && data.refresh_token) {
      localStorage.setItem("sentinel_refresh_token", data.refresh_token);
    }
    return true;
  };

  const vaultFetch = async (url: string, init: RequestInit = {}) => {
    const response = await fetch(url, init);
    if (response.status !== 401) return response;

    const refreshed = await refreshAuthSession().catch(() => false);
    if (!refreshed) return response;

    const retryHeaders = new Headers(init.headers || {});
    const authHeaders = getAuthHeaders();
    if (authHeaders.Authorization) {
      retryHeaders.set("Authorization", authHeaders.Authorization);
    }

    return fetch(url, {
      ...init,
      headers: retryHeaders,
    });
  };

  const downloadBlob = (blob: Blob, filename: string) => {
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
  };

  const loadFiles = async () => {
    try {
      setLoading(true);
      setError("");
      const res = await vaultFetch(`${API_BASE_URL}/api/documents`, {
        credentials: "include",
        headers: getAuthHeaders(),
      });
      const data = await parseResponse(res);
      if (!res.ok) {
        throw new Error(
          data.message ||
            data.error ||
            data.raw ||
            `Failed to load files (${res.status})`
        );
      }
      setFiles(
        data.map((doc: VaultDoc) => ({
          id: doc.id,
          name: doc.filename,
          sizeBytes: doc.size_bytes,
          sizeDisplay: formatFileSize(doc.size_bytes),
          uploadedAt: formatDateTime(doc.upload_date),
          type: getFileType(doc.filename),
          offlineEnabled: Boolean(doc.offline_enabled),
        }))
      );
    } catch (err: any) {
      setError(err.message || "Failed to load files");
    } finally {
      setLoading(false);
    }
  };

  const loadVaultRules = async () => {
    try {
      const res = await vaultFetch(`${API_BASE_URL}/api/documents/rules`, {
        credentials: "include",
        headers: getAuthHeaders(),
      });
      const data = (await parseResponse(res)) as VaultRules;
      if (!res.ok) return;

      const allowed = normalizeExtensions(data.allowed_extensions);
      const blocked = normalizeExtensions(data.blocked_extensions);
      if (allowed.length > 0) setAllowedExtensions(new Set(allowed));
      if (blocked.length > 0) setBlockedExtensions(new Set(blocked));
    } catch {
      // Keep the local deny-list fallback if the rules endpoint is unavailable.
    }
  };

  useEffect(() => {
    loadVaultRules();
    loadFiles();
  }, []);

  const uploadSingleFile = async (file: File) => {
    const ext = getFileType(file.name);
    if (ext === "file") {
      throw new Error("Files without an extension are not allowed.");
    }
    if (blockedExtensions.has(ext)) {
      throw new Error(SECURITY_BLOCKED_FILE_TYPE_MESSAGE);
    }
    if (!allowedExtensions.has(ext)) {
      throw new Error(`File type ".${ext}" is not allowed.`);
    }

    const password = vaultPassword.trim();
    const passwordError = validateVaultPassword(password);
    if (passwordError) throw new Error(passwordError);

    const formData = new FormData();
    formData.append("file", file);
    formData.append("password", password);

    const res = await vaultFetch(`${API_BASE_URL}/api/documents`, {
      method: "POST",
      body: formData,
      credentials: "include",
      headers: getAuthHeaders(),
    });
    const data = await parseResponse(res);
    if (!res.ok) {
      throw new Error(
        data.message ||
          data.error ||
          data.raw ||
          `Upload failed with status ${res.status}`
      );
    }

    const doc = data.document as VaultDoc;
    setFiles((prev) => [
      {
        id: doc.id,
        name: doc.filename,
        sizeBytes: doc.size_bytes,
        sizeDisplay: formatFileSize(doc.size_bytes),
        uploadedAt: formatDateTime(doc.upload_date),
        type: getFileType(doc.filename),
        offlineEnabled: Boolean(doc.offline_enabled),
      },
      ...prev,
    ]);
  };

  const handleFilesUpload = async (fileList: FileList | null) => {
    if (!fileList || fileList.length === 0) return;
    setUploading(true);
    setError("");
    setSuccessMsg("");

    try {
      for (let i = 0; i < fileList.length; i++) {
        const file = fileList.item(i);
        if (file) await uploadSingleFile(file);
      }
      setSuccessMsg("Files uploaded and encrypted successfully");
      setVaultPassword("");
      setShowPassword(false);
    } catch (err: any) {
      setError(err.message || "Upload failed");
    } finally {
      setUploading(false);
      setDragActive(false);
    }
  };

  const openPasswordModal = (mode: PasswordModalMode, file: VaultFile) => {
    setPasswordModalMode(mode);
    setPasswordModalFile(file);
    setModalPassword("");
    setError("");
    setSuccessMsg("");
    setPasswordModalOpen(true);
  };

  const closePasswordModal = () => {
    if (modalLoading) return;
    setPasswordModalOpen(false);
    setModalPassword("");
    setPasswordModalFile(null);
  };

  const performToggleOffline = async (file: VaultFile, password: string) => {
    const nextValue = !file.offlineEnabled;

    if (nextValue) {
      const downloadRes = await vaultFetch(
        `${API_BASE_URL}/api/documents/${file.id}/download`,
        {
          method: "POST",
          credentials: "include",
          headers: { ...getAuthHeaders(), "Content-Type": "application/json" },
          body: JSON.stringify({ password }),
        }
      );
      if (!downloadRes.ok) {
        const data = await parseResponse(downloadRes);
        throw new Error(
          data.message ||
            data.error ||
            data.raw ||
            `Offline cache failed (${downloadRes.status})`
        );
      }
      const encryptedOfflineFile = await encryptOfflineBlob({
        id: file.id,
        name: file.name,
        blob: await downloadRes.blob(),
        password,
      });
      await saveOfflineFile(encryptedOfflineFile);
    } else {
      await deleteOfflineFile(file.id);
    }

    const res = await vaultFetch(`${API_BASE_URL}/api/documents/${file.id}/offline`, {
      method: "PATCH",
      credentials: "include",
      headers: { ...getAuthHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ offline_enabled: nextValue }),
    });
    const data = await parseResponse(res);
    if (!res.ok) {
      if (nextValue) {
        await deleteOfflineFile(file.id).catch(() => null);
      }
      throw new Error(
        data.message ||
          data.error ||
          data.raw ||
          `Offline update failed (${res.status})`
      );
    }

    setFiles((prev) =>
      prev.map((item) =>
        item.id === file.id ? { ...item, offlineEnabled: nextValue } : item
      )
    );
    setSuccessMsg(
      nextValue
        ? "Secure offline copy encrypted on this device"
        : "Offline copy removed from this device"
    );
  };

  const downloadEncryptedOfflineCopy = async (
    file: VaultFile,
    password: string
  ) => {
    const offlineFile = await getOfflineFile(file.id);
    if (!offlineFile) throw new Error("No offline copy found for this file");
    const decrypted = await decryptOfflineBlob(offlineFile, password);
    downloadBlob(decrypted, offlineFile.originalName || file.name);
  };

  const performDownload = async (file: VaultFile, password: string) => {
    if (!navigator.onLine && file.offlineEnabled) {
      await downloadEncryptedOfflineCopy(file, password);
      return;
    }

    let res: Response;
    try {
      res = await vaultFetch(`${API_BASE_URL}/api/documents/${file.id}/download`, {
        method: "POST",
        credentials: "include",
        headers: { ...getAuthHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify({ password }),
      });
    } catch (err) {
      if (file.offlineEnabled) {
        await downloadEncryptedOfflineCopy(file, password);
        return;
      }
      throw err;
    }
    if (!res.ok) {
      const data = await parseResponse(res);
      throw new Error(
        data.message || data.error || data.raw || `Download failed (${res.status})`
      );
    }
    downloadBlob(await res.blob(), file.name);
  };

  const performDelete = async (file: VaultFile, password: string) => {
    const res = await vaultFetch(`${API_BASE_URL}/api/documents/${file.id}`, {
      method: "DELETE",
      credentials: "include",
      headers: { ...getAuthHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ password }),
    });
    const data = await parseResponse(res);
    if (!res.ok) {
      throw new Error(
        data.message || data.error || data.raw || `Delete failed (${res.status})`
      );
    }
    await deleteOfflineFile(file.id).catch(() => null);
    setFiles((prev) => prev.filter((item) => item.id !== file.id));
    setSuccessMsg("File deleted successfully");
  };

  const handlePasswordModalConfirm = async () => {
    try {
      if (!passwordModalFile) return;
      setModalLoading(true);
      setError("");
      setSuccessMsg("");

      const password = modalPassword.trim();
      const passwordError = validateVaultPassword(password);
      if (passwordError) throw new Error(passwordError);

      if (passwordModalMode === "download") {
        await performDownload(passwordModalFile, password);
      } else if (passwordModalMode === "delete") {
        await performDelete(passwordModalFile, password);
      } else {
        await performToggleOffline(passwordModalFile, password);
      }

      closePasswordModal();
    } catch (err: any) {
      setError(err.message || "Action failed");
    } finally {
      setModalLoading(false);
    }
  };

  const totalFiles = files.length;
  const totalBytes = files.reduce((sum, file) => sum + file.sizeBytes, 0);
  const offlineFiles = files.filter((file) => file.offlineEnabled).length;
  const storageUsed = formatFileSize(totalBytes);
  const storagePercentage = Math.min(
    100,
    (totalBytes / (100 * 1024 * 1024 * 1024)) * 100 || 0
  );
  const passwordError = validateVaultPassword(vaultPassword.trim());
  const passwordReady = !passwordError && vaultPassword.trim().length > 0;
  const search = fileSearch.trim().toLowerCase();
  const visibleFiles = search
    ? files.filter((file) =>
        [file.name, file.type, file.sizeDisplay, file.uploadedAt]
          .join(" ")
          .toLowerCase()
          .includes(search)
      )
    : files;

  return (
    <div
      className="space-y-6 rounded-3xl bg-[linear-gradient(180deg,rgba(4,20,44,0.72),rgba(8,13,31,0.26)_360px,rgba(2,6,23,0))] p-1"
      dir={isRtl ? "rtl" : "ltr"}
    >
      <section className="relative overflow-hidden rounded-2xl border border-cyan-200/20 bg-[linear-gradient(135deg,rgba(3,10,25,0.99),rgba(6,32,48,0.96)_38%,rgba(47,36,94,0.78)_72%,rgba(86,50,16,0.42))] p-6 shadow-[0_24px_70px_rgba(2,6,23,0.38)]">
        <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-200/90 to-amber-200/40" />
        <div className="absolute inset-y-0 right-0 w-2/5 bg-[linear-gradient(90deg,transparent,rgba(45,212,191,0.12),rgba(245,158,11,0.07))]" />
        <div className="absolute inset-0 bg-[linear-gradient(rgba(125,211,252,0.055)_1px,transparent_1px),linear-gradient(90deg,rgba(125,211,252,0.04)_1px,transparent_1px)] bg-[size:44px_44px] opacity-60" />
        <div className="absolute bottom-0 left-0 h-px w-full bg-gradient-to-r from-amber-300/70 via-teal-200/35 to-transparent" />
        <div className="relative flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
          <div className="max-w-2xl">
            <div className="mb-4 flex items-center gap-3">
              <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-cyan-200/30 bg-[linear-gradient(135deg,rgba(34,211,238,0.22),rgba(16,185,129,0.12))] shadow-[0_14px_36px_rgba(8,145,178,0.24)]">
                <ShieldCheck className="h-6 w-6 text-cyan-100" />
              </div>
              <Badge className="border-emerald-200/35 bg-emerald-300/15 text-emerald-100 shadow-sm shadow-emerald-950/30">
                <Lock className="mr-1 h-3 w-3" />
                Protected
              </Badge>
            </div>
            <h1 className="text-3xl font-semibold tracking-tight text-white">
              Encrypted File Vault
            </h1>
            <p className="mt-2 max-w-xl text-sm leading-6 text-slate-300">
              Upload sensitive files, encrypt them with a strong password, and
              manage secure offline access from one focused workspace.
            </p>
            <p className="mt-2 max-w-xl text-xs leading-5 text-cyan-100/75">
              Offline files are encrypted locally and require your vault password to open.
            </p>
            <div className="mt-5 grid max-w-xl grid-cols-3 overflow-hidden rounded-xl border border-cyan-100/15 bg-slate-950/45 text-xs shadow-inner shadow-black/30">
              {[
                ["01", "Encrypt"],
                ["02", "Store"],
                ["03", "Recover"],
              ].map(([step, label]) => (
                <div key={step} className="border-r border-white/10 px-4 py-3 last:border-r-0">
                  <div className="text-[10px] font-semibold uppercase tracking-[0.22em] text-cyan-100/80">
                    {step}
                  </div>
                  <div className="mt-1 font-medium text-white">{label}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="w-full max-w-md rounded-xl border border-cyan-100/15 bg-[linear-gradient(180deg,rgba(2,12,28,0.78),rgba(12,25,49,0.54))] p-4 shadow-inner shadow-black/30">
            <div className="mb-3 flex items-center justify-between text-sm">
              <span className="text-slate-300">Storage Used</span>
              <span className="font-medium text-white">{storageUsed} / 100 GB</span>
            </div>
            <Progress value={storagePercentage} />
            <div className="mt-2 text-right text-xs text-slate-500">
              {storagePercentage.toFixed(2)}%
            </div>
          </div>
        </div>
      </section>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
        <MetricCard icon={FileText} label="Total Files" value={String(totalFiles)} tone="sky" />
        <MetricCard icon={ShieldCheck} label="Encrypted" value={String(totalFiles)} tone="emerald" />
        <MetricCard icon={WifiOff} label="Offline Files" value={String(offlineFiles)} tone="indigo" />
        <MetricCard icon={Database} label="Stored Data" value={storageUsed} tone="amber" />
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,0.95fr)_minmax(0,1.05fr)]">
        <Card className="cyber-card overflow-hidden border-emerald-200/20 bg-[linear-gradient(160deg,rgba(6,78,59,0.30),rgba(4,19,38,0.86)_48%,rgba(2,6,23,0.82))] shadow-[0_18px_55px_rgba(6,78,59,0.16)]">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-white">
              <KeyRound className="h-5 w-5 text-teal-200" />
              Encryption Key
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-5">
            <div className="relative">
              <input
                type={showPassword ? "text" : "password"}
                value={vaultPassword}
                onChange={(event) => setVaultPassword(event.target.value)}
                placeholder="Enter a strong encryption password"
                className="h-12 w-full rounded-xl border border-emerald-100/15 bg-slate-950/80 px-4 pr-12 text-white outline-none transition placeholder:text-slate-500 focus:border-emerald-300 focus:ring-2 focus:ring-emerald-300/15"
              />
              <button
                type="button"
                onClick={() => setShowPassword((value) => !value)}
                className="absolute right-3 top-1/2 flex h-9 w-9 -translate-y-1/2 items-center justify-center rounded-lg text-slate-400 transition hover:bg-emerald-300/10 hover:text-emerald-100"
                aria-label={showPassword ? "Hide password" : "Show password"}
              >
                {showPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
              </button>
            </div>

            <div className="grid grid-cols-5 gap-2 text-xs">
              {[
                {
                  label: "8+",
                  active: vaultPassword.length >= 8,
                  activeClass: "border-cyan-300/45 bg-cyan-300/18 text-cyan-100 shadow-cyan-950/30",
                  idleClass: "border-cyan-300/24 bg-cyan-300/8 text-cyan-200/80",
                },
                {
                  label: "A-Z",
                  active: /[A-Z]/.test(vaultPassword),
                  activeClass: "border-violet-300/45 bg-violet-300/18 text-violet-100 shadow-violet-950/30",
                  idleClass: "border-violet-300/24 bg-violet-300/8 text-violet-200/80",
                },
                {
                  label: "a-z",
                  active: /[a-z]/.test(vaultPassword),
                  activeClass: "border-emerald-300/45 bg-emerald-300/18 text-emerald-100 shadow-emerald-950/30",
                  idleClass: "border-emerald-300/24 bg-emerald-300/8 text-emerald-200/80",
                },
                {
                  label: "0-9",
                  active: /[0-9]/.test(vaultPassword),
                  activeClass: "border-amber-300/45 bg-amber-300/18 text-amber-100 shadow-amber-950/30",
                  idleClass: "border-amber-300/24 bg-amber-300/8 text-amber-200/80",
                },
                {
                  label: "@#",
                  active: /[^A-Za-z0-9]/.test(vaultPassword),
                  activeClass: "border-rose-300/45 bg-rose-300/18 text-rose-100 shadow-rose-950/30",
                  idleClass: "border-rose-300/24 bg-rose-300/8 text-rose-200/80",
                },
              ].map((rule) => (
                <Badge
                  key={rule.label}
                  className={
                    rule.active
                      ? `justify-center shadow-sm ${rule.activeClass}`
                      : `justify-center ${rule.idleClass}`
                  }
                >
                  {rule.label}
                </Badge>
              ))}
            </div>

            <div className="flex items-start gap-2 rounded-xl border border-emerald-200/15 bg-emerald-950/20 p-3 text-sm">
              {passwordReady ? (
                <CheckCircle className="mt-0.5 h-4 w-4 text-emerald-300" />
              ) : (
                <AlertTriangle className="mt-0.5 h-4 w-4 text-amber-300" />
              )}
              <p className={passwordReady ? "text-emerald-300" : "text-slate-400"}>
                {passwordReady
                  ? "Password is strong and ready for encryption."
                  : passwordError || "Enter a strong password before uploading."}
              </p>
            </div>
          </CardContent>
        </Card>

        <Card className="cyber-card overflow-hidden border-cyan-200/20 bg-[linear-gradient(150deg,rgba(14,116,144,0.30),rgba(30,41,59,0.56)_44%,rgba(49,46,129,0.24),rgba(2,6,23,0.82))] shadow-[0_18px_55px_rgba(8,145,178,0.16)]">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-white">
              <Upload className="h-5 w-5 text-sky-200" />
              Upload Files
            </CardTitle>
          </CardHeader>
          <CardContent>
            <input
              ref={uploadInputRef}
              type="file"
              multiple
              className="hidden"
              onChange={(event) => {
                handleFilesUpload(event.target.files);
                event.currentTarget.value = "";
              }}
            />
            <div
              onDragOver={(event) => {
                event.preventDefault();
                setDragActive(true);
              }}
              onDragLeave={() => setDragActive(false)}
              onDrop={(event) => {
                event.preventDefault();
                handleFilesUpload(event.dataTransfer.files);
              }}
              onClick={() => uploadInputRef.current?.click()}
              className={[
                "cursor-pointer rounded-xl border border-dashed p-8 text-center transition shadow-inner",
                dragActive
                  ? "border-cyan-200 bg-cyan-300/15"
                  : "border-cyan-100/20 bg-[linear-gradient(135deg,rgba(8,47,73,0.38),rgba(24,35,72,0.56),rgba(2,6,23,0.62))] hover:border-cyan-200/70 hover:bg-slate-900/70",
              ].join(" ")}
            >
              <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-xl border border-cyan-200/24 bg-[linear-gradient(135deg,rgba(34,211,238,0.18),rgba(99,102,241,0.12))]">
                {uploading ? (
                  <Loader2 className="h-7 w-7 animate-spin text-cyan-100" />
                ) : (
                  <Upload className="h-7 w-7 text-cyan-100" />
                )}
              </div>
              <h3 className="text-lg font-semibold text-white">
                {uploading ? "Encrypting and uploading..." : "Drop files here"}
              </h3>
              <p className="mt-2 text-sm text-slate-400">
                PDF, DOCX, TXT, source code, and config files are supported.
              </p>
              <div className="mx-auto mt-4 flex max-w-md flex-wrap justify-center gap-2 text-[11px]">
                {["PDF", "DOCX", "TXT", "CODE", "CONFIG"].map((item) => (
                  <span
                    key={item}
                    className="rounded-md border border-cyan-200/20 bg-cyan-300/10 px-2 py-1 text-cyan-100/80"
                  >
                    {item}
                  </span>
                ))}
              </div>
              <Button className="mt-5" disabled={uploading || !passwordReady}>
                <FolderOpen className="mr-2 h-4 w-4" />
                Choose Files
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>

      {(error || successMsg) && (
        <div
          className={[
            "rounded-xl border p-4 text-sm",
            error
              ? "border-red-500/30 bg-red-500/10 text-red-300"
              : "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
          ].join(" ")}
        >
          <div className="flex items-center gap-2">
            {error ? <AlertTriangle className="h-5 w-5" /> : <CheckCircle className="h-5 w-5" />}
            <span>{error || successMsg}</span>
          </div>
        </div>
      )}

      <Card className="cyber-card overflow-hidden border-cyan-100/15 bg-[linear-gradient(180deg,rgba(12,25,49,0.96),rgba(5,15,32,0.94)_46%,rgba(2,6,23,0.90))] shadow-[0_22px_70px_rgba(2,6,23,0.34)]">
        <CardHeader className="gap-4 md:flex-row md:items-center md:justify-between">
          <div>
            <CardTitle className="flex items-center gap-2 text-white">
              <HardDrive className="h-5 w-5 text-cyan-100" />
              Vault Contents
            </CardTitle>
            <p className="mt-1 text-sm text-slate-400">
              {visibleFiles.length} of {totalFiles} files shown
            </p>
          </div>

          <div className="flex w-full flex-col gap-3 sm:flex-row md:w-auto">
            <div className="relative min-w-0 sm:w-72">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
              <input
                value={fileSearch}
                onChange={(event) => setFileSearch(event.target.value)}
                placeholder="Search files"
                className="h-10 w-full rounded-lg border border-cyan-100/15 bg-slate-950/80 pl-9 pr-3 text-sm text-white outline-none transition placeholder:text-slate-500 focus:border-cyan-200 focus:ring-2 focus:ring-cyan-200/15"
              />
            </div>
            <Button variant="outline" onClick={loadFiles} disabled={loading}>
              <RefreshCw className={["mr-2 h-4 w-4", loading ? "animate-spin" : ""].join(" ")} />
              Refresh
            </Button>
          </div>
        </CardHeader>

        <CardContent>
          {loading ? (
            <div className="flex items-center gap-3 py-8 text-slate-400">
              <Loader2 className="h-5 w-5 animate-spin" />
              Loading files...
            </div>
          ) : files.length === 0 ? (
            <EmptyState
              icon={FileText}
              title="No files uploaded yet"
              description="Upload your first encrypted file to start using the vault."
            />
          ) : visibleFiles.length === 0 ? (
            <EmptyState
              icon={Search}
              title="No matching files"
              description="Try another filename or extension."
            />
          ) : (
            <>
              <div className="hidden overflow-hidden rounded-xl border border-cyan-100/15 md:block">
                <Table>
                  <TableHeader>
                    <TableRow className="bg-[linear-gradient(90deg,rgba(8,47,73,0.62),rgba(15,23,42,0.78))]">
                      <TableHead>File</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Size</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Uploaded</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {visibleFiles.map((file) => (
                      <FileTableRow
                        key={file.id}
                        file={file}
                        onOffline={() => openPasswordModal("offline", file)}
                        onDownload={() => openPasswordModal("download", file)}
                        onDelete={() => openPasswordModal("delete", file)}
                      />
                    ))}
                  </TableBody>
                </Table>
              </div>

              <div className="grid gap-3 md:hidden">
                {visibleFiles.map((file) => (
                  <FileMobileCard
                    key={file.id}
                    file={file}
                    onOffline={() => openPasswordModal("offline", file)}
                    onDownload={() => openPasswordModal("download", file)}
                    onDelete={() => openPasswordModal("delete", file)}
                  />
                ))}
              </div>
            </>
          )}
        </CardContent>
      </Card>

      {passwordModalOpen && passwordModalFile && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
          <div className="w-full max-w-md rounded-2xl border border-teal-300/15 bg-[linear-gradient(180deg,rgba(15,23,42,0.98),rgba(2,6,23,0.98))] p-6 shadow-2xl shadow-black/50">
            <h2 className="mb-2 text-xl font-bold text-white">
              {passwordModalMode === "download"
                ? "Decrypt File"
                : passwordModalMode === "delete"
                ? "Confirm Delete"
                : passwordModalFile.offlineEnabled
                ? "Disable Offline Access"
                : "Enable Offline Access"}
            </h2>
            <p className="mb-4 break-words text-sm text-slate-400">
              {passwordModalMode === "download"
                ? `Enter password to decrypt: ${passwordModalFile.name}`
                : passwordModalMode === "delete"
                ? `Enter file password to delete: ${passwordModalFile.name}`
                : passwordModalFile.offlineEnabled
                ? `Enter file password to disable offline access: ${passwordModalFile.name}`
                : `Enter file password to encrypt and save offline copy: ${passwordModalFile.name}`}
            </p>

            {!navigator.onLine &&
              passwordModalMode === "download" &&
              passwordModalFile.offlineEnabled && (
                <div className="mb-4 rounded-xl border border-violet-500/30 bg-violet-500/10 p-3 text-sm text-violet-300">
                  You are offline. The encrypted local copy will be decrypted with this password.
                </div>
              )}

            <input
              type="password"
              value={modalPassword}
              onChange={(event) => setModalPassword(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") handlePasswordModalConfirm();
              }}
              placeholder="Password"
              className="h-12 w-full rounded-xl border border-slate-700 bg-slate-950/80 px-4 text-white outline-none focus:border-teal-300 focus:ring-2 focus:ring-teal-300/10"
            />

            <div className="mt-5 flex justify-end gap-3">
              <Button variant="outline" onClick={closePasswordModal} disabled={modalLoading}>
                Cancel
              </Button>
              <Button
                variant={passwordModalMode === "delete" ? "destructive" : "default"}
                onClick={handlePasswordModalConfirm}
                disabled={modalLoading}
              >
                {modalLoading ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : passwordModalMode === "download" ? (
                  "Download"
                ) : passwordModalMode === "delete" ? (
                  "Delete"
                ) : passwordModalFile.offlineEnabled ? (
                  "Disable Offline"
                ) : (
                  "Enable Offline"
                )}
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function MetricCard({
  icon: Icon,
  label,
  value,
  tone,
}: {
  icon: React.ElementType;
  label: string;
  value: string;
  tone: "sky" | "emerald" | "indigo" | "amber";
}) {
  const tones = {
    sky: "border-cyan-200/22 bg-[linear-gradient(135deg,rgba(14,165,233,0.22),rgba(12,25,49,0.82)_48%,rgba(2,6,23,0.78))] text-cyan-100 shadow-cyan-950/25",
    emerald: "border-emerald-200/22 bg-[linear-gradient(135deg,rgba(16,185,129,0.22),rgba(12,25,49,0.82)_48%,rgba(2,6,23,0.78))] text-emerald-100 shadow-emerald-950/25",
    indigo: "border-violet-200/22 bg-[linear-gradient(135deg,rgba(139,92,246,0.21),rgba(12,25,49,0.82)_48%,rgba(2,6,23,0.78))] text-violet-100 shadow-violet-950/25",
    amber: "border-amber-200/24 bg-[linear-gradient(135deg,rgba(245,158,11,0.20),rgba(12,25,49,0.82)_48%,rgba(2,6,23,0.78))] text-amber-100 shadow-amber-950/25",
  };

  return (
    <div className={`group relative overflow-hidden rounded-xl border p-5 shadow-lg transition hover:-translate-y-0.5 hover:shadow-xl ${tones[tone]}`}>
      <div className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-white/45 to-transparent opacity-70" />
      <div className="flex items-center justify-between">
        <span className="text-sm text-slate-300">{label}</span>
        <span className="flex h-9 w-9 items-center justify-center rounded-lg border border-white/10 bg-white/5">
          <Icon className="h-5 w-5" />
        </span>
      </div>
      <div className="mt-3 truncate text-2xl font-semibold text-white">{value}</div>
    </div>
  );
}

function EmptyState({
  icon: Icon,
  title,
  description,
}: {
  icon: React.ElementType;
  title: string;
  description: string;
}) {
  return (
    <div className="rounded-xl border border-cyan-100/15 bg-[linear-gradient(135deg,rgba(8,47,73,0.32),rgba(15,23,42,0.82),rgba(2,6,23,0.88))] py-14 text-center">
      <div className="mx-auto mb-3 flex h-14 w-14 items-center justify-center rounded-xl border border-cyan-100/15 bg-cyan-300/10">
        <Icon className="h-8 w-8 text-cyan-100/70" />
      </div>
      <p className="font-semibold text-white">{title}</p>
      <p className="mt-1 text-sm text-slate-400">{description}</p>
    </div>
  );
}

function FileStatus({ file }: { file: VaultFile }) {
  return (
    <div className="flex flex-wrap gap-2">
      <Badge className="border-emerald-300/30 bg-emerald-300/15 text-emerald-100">
        <Lock className="mr-1 h-3 w-3" />
        Encrypted
      </Badge>
      {file.offlineEnabled && (
        <Badge className="border-violet-300/30 bg-violet-300/15 text-violet-100">
          <WifiOff className="mr-1 h-3 w-3" />
          Offline
        </Badge>
      )}
    </div>
  );
}

function FileActions({
  file,
  onOffline,
  onDownload,
  onDelete,
}: {
  file: VaultFile;
  onOffline: () => void;
  onDownload: () => void;
  onDelete: () => void;
}) {
  return (
    <div className="flex justify-end gap-2">
      <Button size="sm" variant="outline" onClick={onOffline} aria-label="Toggle offline access">
        {file.offlineEnabled ? <Wifi className="h-4 w-4" /> : <WifiOff className="h-4 w-4" />}
      </Button>
      <Button size="sm" onClick={onDownload} className="bg-gradient-to-r from-emerald-500 to-cyan-500 text-slate-950 hover:from-emerald-400 hover:to-cyan-400" aria-label="Download file">
        <Download className="h-4 w-4" />
      </Button>
      <Button size="sm" variant="destructive" onClick={onDelete} aria-label="Delete file">
        <Trash2 className="h-4 w-4" />
      </Button>
    </div>
  );
}

function FileTableRow({
  file,
  onOffline,
  onDownload,
  onDelete,
}: {
  file: VaultFile;
  onOffline: () => void;
  onDownload: () => void;
  onDelete: () => void;
}) {
  return (
    <TableRow className="border-cyan-100/10 hover:bg-cyan-950/24">
      <TableCell>
        <div className="flex min-w-0 items-center gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-cyan-200/15 bg-[linear-gradient(135deg,rgba(34,211,238,0.14),rgba(16,185,129,0.10))]">
            <FileText className="h-5 w-5 text-cyan-100" />
          </div>
          <span className="max-w-[280px] truncate font-medium text-white" title={file.name}>
            {file.name}
          </span>
        </div>
      </TableCell>
      <TableCell>
        <Badge className="border-amber-200/20 bg-amber-300/10 text-amber-100 uppercase">
          {file.type}
        </Badge>
      </TableCell>
      <TableCell className="text-slate-300">{file.sizeDisplay}</TableCell>
      <TableCell>
        <FileStatus file={file} />
      </TableCell>
      <TableCell className="text-slate-400">{file.uploadedAt}</TableCell>
      <TableCell>
        <FileActions
          file={file}
          onOffline={onOffline}
          onDownload={onDownload}
          onDelete={onDelete}
        />
      </TableCell>
    </TableRow>
  );
}

function FileMobileCard({
  file,
  onOffline,
  onDownload,
  onDelete,
}: {
  file: VaultFile;
  onOffline: () => void;
  onDownload: () => void;
  onDelete: () => void;
}) {
  return (
    <div className="rounded-xl border border-cyan-100/15 bg-[linear-gradient(135deg,rgba(8,47,73,0.30),rgba(15,23,42,0.84),rgba(2,6,23,0.90))] p-4">
      <div className="flex gap-3">
        <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg border border-cyan-200/15 bg-cyan-300/10">
          <FileText className="h-5 w-5 text-cyan-100" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="truncate font-medium text-white">{file.name}</div>
          <div className="mt-1 text-xs text-slate-500">
            {file.type.toUpperCase()} - {file.sizeDisplay} - {file.uploadedAt}
          </div>
          <div className="mt-3">
            <FileStatus file={file} />
          </div>
        </div>
      </div>
      <div className="mt-4 grid grid-cols-3 gap-2">
        <Button size="sm" variant="outline" onClick={onOffline}>
          {file.offlineEnabled ? <Wifi className="h-4 w-4" /> : <WifiOff className="h-4 w-4" />}
        </Button>
        <Button size="sm" onClick={onDownload} className="bg-gradient-to-r from-emerald-500 to-cyan-500 text-slate-950 hover:from-emerald-400 hover:to-cyan-400">
          <Download className="h-4 w-4" />
        </Button>
        <Button size="sm" variant="destructive" onClick={onDelete}>
          <Trash2 className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
}
