import React, { useEffect, useRef, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Button } from "../ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../ui/table";
import { Badge } from "../ui/badge";
import { Progress } from "../ui/progress";
import { useLanguage } from "../../contexts/LanguageContext";
import {
  Upload,
  Download,
  Lock,
  Trash2,
  ShieldCheck,
  HardDrive,
  FileText,
  KeyRound,
  Eye,
  EyeOff,
  CheckCircle,
  AlertTriangle,
  Loader2,
  WifiOff,
  Wifi,
} from "lucide-react";

import {
  saveOfflineFile,
  getOfflineFile,
  deleteOfflineFile,
} from "../../utils/offlineVault";

const API_BASE_URL =
  (import.meta as any).env?.VITE_API_BASE_URL || "http://localhost:5000";

const ALLOWED_EXTENSIONS = new Set([
  "pdf", "docx", "txt",
  "py", "js", "ts", "jsx", "tsx",
  "java", "c", "cpp", "h", "hpp",
  "cs", "php", "go", "rs",
  "html", "css", "scss",
  "json", "xml", "yml", "yaml",
  "md", "sql", "sh", "bat", "ps1",
  "env", "ini", "cfg", "toml",
]);

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

export function FileVaultPage() {
  const { language, isRtl, formatDateTime } = useLanguage();

  const [files, setFiles] = useState<VaultFile[]>([]);
  const [loading, setLoading] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [dragActive, setDragActive] = useState(false);
  const [error, setError] = useState("");
  const [successMsg, setSuccessMsg] = useState("");
  const [vaultPassword, setVaultPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);

  const [passwordModalOpen, setPasswordModalOpen] = useState(false);
  const [passwordModalMode, setPasswordModalMode] =
    useState<PasswordModalMode>("download");
  const [passwordModalFile, setPasswordModalFile] =
    useState<VaultFile | null>(null);
  const [modalPassword, setModalPassword] = useState("");
  const [modalLoading, setModalLoading] = useState(false);

  const uploadInputRef = useRef<HTMLInputElement | null>(null);

  const validateVaultPassword = (password: string): string | null => {
    if (password.length < 8) {
      return language === "arabic"
        ? "كلمة السر لازم تكون 8 حروف على الأقل"
        : "Password must be at least 8 characters";
    }

    if (!/[A-Z]/.test(password)) {
      return language === "arabic"
        ? "كلمة السر لازم تحتوي على حرف كبير"
        : "Password must contain an uppercase letter";
    }

    if (!/[a-z]/.test(password)) {
      return language === "arabic"
        ? "كلمة السر لازم تحتوي على حرف صغير"
        : "Password must contain a lowercase letter";
    }

    if (!/[0-9]/.test(password)) {
      return language === "arabic"
        ? "كلمة السر لازم تحتوي على رقم"
        : "Password must contain a number";
    }

    if (!/[^A-Za-z0-9]/.test(password)) {
      return language === "arabic"
        ? "كلمة السر لازم تحتوي على رمز"
        : "Password must contain a special character";
    }

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
    if (parts.length < 2) return "file";
    return parts[parts.length - 1].toLowerCase();
  };

  const parseResponse = async (res: Response) => {
    const text = await res.text();

    try {
      return text ? JSON.parse(text) : {};
    } catch {
      return { raw: text };
    }
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

      const res = await fetch(`${API_BASE_URL}/api/documents`, {
        credentials: "include",
      });

      const data = await parseResponse(res);

      if (!res.ok) {
        throw new Error(
          data.error || data.raw || `Failed to load files (${res.status})`
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
      console.error("LOAD FILES ERROR:", err);
      setError(err.message || "Failed to load files");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadFiles();
  }, []);

  const uploadSingleFile = async (file: File) => {
    const ext = getFileType(file.name);

    if (ext !== "file" && !ALLOWED_EXTENSIONS.has(ext)) {
      throw new Error(`File type ".${ext}" is not allowed`);
    }

    const passwordError = validateVaultPassword(vaultPassword.trim());
    if (passwordError) {
      throw new Error(passwordError);
    }

    const formData = new FormData();
    formData.append("file", file);
    formData.append("password", vaultPassword.trim());

    const res = await fetch(`${API_BASE_URL}/api/documents`, {
      method: "POST",
      body: formData,
      credentials: "include",
    });

    const data = await parseResponse(res);

    if (!res.ok) {
      console.error("UPLOAD STATUS:", res.status);
      console.error("UPLOAD RESPONSE:", data);
      throw new Error(
        data.error || data.raw || `Upload failed with status ${res.status}`
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
        const f = fileList.item(i);
        if (f) await uploadSingleFile(f);
      }

      setSuccessMsg(
        language === "arabic"
          ? "تم رفع الملفات وتشفيرها بنجاح"
          : "Files uploaded and encrypted successfully"
      );

      setVaultPassword("");
      setShowPassword(false);
    } catch (err: any) {
      console.error("UPLOAD ERROR:", err);
      setError(
        err.message ||
          (language === "arabic" ? "فشل رفع الملف" : "Upload failed")
      );
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
      const downloadRes = await fetch(
        `${API_BASE_URL}/api/documents/${file.id}/download`,
        {
          method: "POST",
          credentials: "include",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ password }),
        }
      );

      if (!downloadRes.ok) {
        const data = await parseResponse(downloadRes);
        throw new Error(
          data.error ||
            data.raw ||
            `Offline cache failed (${downloadRes.status})`
        );
      }

      const blob = await downloadRes.blob();

      await saveOfflineFile({
        id: file.id,
        name: file.name,
        blob,
        savedAt: new Date().toISOString(),
      });
    } else {
      await deleteOfflineFile(file.id);
    }

    const res = await fetch(`${API_BASE_URL}/api/documents/${file.id}/offline`, {
      method: "PATCH",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ offline_enabled: nextValue }),
    });

    const data = await parseResponse(res);

    if (!res.ok) {
      throw new Error(
        data.error || data.raw || `Offline update failed (${res.status})`
      );
    }

    setFiles((prev) =>
      prev.map((x) =>
        x.id === file.id ? { ...x, offlineEnabled: nextValue } : x
      )
    );

    setSuccessMsg(
      nextValue
        ? language === "arabic"
          ? "تم حفظ نسخة Offline على الجهاز"
          : "Offline copy saved on this device"
        : language === "arabic"
        ? "تم حذف النسخة Offline من الجهاز"
        : "Offline copy removed from this device"
    );
  };

  const performDownload = async (file: VaultFile, password: string) => {
    if (!navigator.onLine && file.offlineEnabled) {
      const offlineFile = await getOfflineFile(file.id);

      if (!offlineFile) {
        throw new Error(
          language === "arabic"
            ? "لا توجد نسخة Offline محفوظة لهذا الملف"
            : "No offline copy found for this file"
        );
      }

      downloadBlob(offlineFile.blob, offlineFile.name);
      return;
    }

    const res = await fetch(`${API_BASE_URL}/api/documents/${file.id}/download`, {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ password }),
    });

    if (!res.ok) {
      const d = await parseResponse(res);
      throw new Error(d.error || d.raw || `Download failed (${res.status})`);
    }

    const blob = await res.blob();
    downloadBlob(blob, file.name);
  };

  const performDelete = async (file: VaultFile, password: string) => {
    const res = await fetch(`${API_BASE_URL}/api/documents/${file.id}`, {
      method: "DELETE",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ password }),
    });

    const d = await parseResponse(res);

    if (!res.ok) {
      throw new Error(d.error || d.raw || `Delete failed (${res.status})`);
    }

    await deleteOfflineFile(file.id).catch(() => null);

    setFiles((prev) => prev.filter((x) => x.id !== file.id));

    setSuccessMsg(
      language === "arabic"
        ? "تم حذف الملف بنجاح"
        : "File deleted successfully"
    );
  };

  const handlePasswordModalConfirm = async () => {
    try {
      if (!passwordModalFile) return;

      setModalLoading(true);
      setError("");
      setSuccessMsg("");

      const password = modalPassword.trim();
      const passwordError = validateVaultPassword(password);

      if (passwordError) {
        throw new Error(passwordError);
      }

      if (passwordModalMode === "download") {
        await performDownload(passwordModalFile, password);
      } else if (passwordModalMode === "delete") {
        await performDelete(passwordModalFile, password);
      } else {
        await performToggleOffline(passwordModalFile, password);
      }

      setPasswordModalOpen(false);
      setModalPassword("");
      setPasswordModalFile(null);
    } catch (err: any) {
      console.error("PASSWORD ACTION ERROR:", err);
      setError(err.message || "Action failed");
    } finally {
      setModalLoading(false);
    }
  };

  const totalFiles = files.length;
  const totalBytes = files.reduce((a, f) => a + f.sizeBytes, 0);
  const offlineFiles = files.filter((f) => f.offlineEnabled).length;

  const storageUsed = formatFileSize(totalBytes);
  const storagePercentage = Math.min(
    100,
    (totalBytes / (100 * 1024 * 1024 * 1024)) * 100 || 0
  );

  const passwordError = validateVaultPassword(vaultPassword.trim());
  const passwordReady = !passwordError && vaultPassword.trim().length > 0;

  return (
    <div className="space-y-8" dir={isRtl ? "rtl" : "ltr"}>
      <div className="flex items-center gap-3">
        <div className="p-3 rounded-2xl bg-blue-500/15 border border-blue-400/20">
          <ShieldCheck className="w-7 h-7 text-blue-400" />
        </div>

        <div>
          <h1 className="text-3xl font-bold text-white">
            {language === "arabic"
              ? "خزنة الملفات المشفرة"
              : "Encrypted File Vault"}
          </h1>
          <p className="text-gray-400 mt-1">
            {language === "arabic"
              ? "ارفع ملفاتك واحفظها مشفرة بكلمة سر قوية."
              : "Upload, encrypt, store, and download files securely."}
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-5">
        <Card className="cyber-card border-blue-500/20">
          <CardContent className="p-5 flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">
                {language === "arabic" ? "عدد الملفات" : "Total Files"}
              </p>
              <p className="text-3xl font-bold text-white mt-1">{totalFiles}</p>
            </div>
            <FileText className="w-9 h-9 text-blue-400" />
          </CardContent>
        </Card>

        <Card className="cyber-card border-green-500/20">
          <CardContent className="p-5 flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">
                {language === "arabic" ? "الحالة" : "Vault Status"}
              </p>
              <p className="text-xl font-bold text-green-400 mt-1">
                {language === "arabic" ? "محمي" : "Protected"}
              </p>
            </div>
            <Lock className="w-9 h-9 text-green-400" />
          </CardContent>
        </Card>

        <Card className="cyber-card border-purple-500/20">
          <CardContent className="p-5 flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">
                {language === "arabic" ? "ملفات Offline" : "Offline Files"}
              </p>
              <p className="text-3xl font-bold text-white mt-1">
                {offlineFiles}
              </p>
            </div>
            <WifiOff className="w-9 h-9 text-purple-400" />
          </CardContent>
        </Card>

        <Card className="cyber-card border-purple-500/20">
          <CardContent className="p-5 flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">
                {language === "arabic" ? "المساحة المستخدمة" : "Storage Used"}
              </p>
              <p className="text-2xl font-bold text-white mt-1">
                {storageUsed}
              </p>
            </div>
            <HardDrive className="w-9 h-9 text-purple-400" />
          </CardContent>
        </Card>
      </div>

      <Card className="cyber-card overflow-hidden">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <KeyRound className="w-5 h-5 text-blue-400" />
            {language === "arabic" ? "مفتاح التشفير" : "Encryption Key"}
          </CardTitle>
        </CardHeader>

        <CardContent className="space-y-5">
          <div className="relative">
            <input
              type={showPassword ? "text" : "password"}
              value={vaultPassword}
              onChange={(e) => setVaultPassword(e.target.value)}
              placeholder={
                language === "arabic"
                  ? "اكتب باسورد قوي للملف"
                  : "Enter a strong encryption password"
              }
              className="w-full p-4 pr-12 rounded-xl bg-slate-950/70 text-white border border-slate-700 focus:border-blue-400 outline-none"
            />

            <button
              type="button"
              onClick={() => setShowPassword((v) => !v)}
              className="absolute right-4 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white"
            >
              {showPassword ? (
                <EyeOff className="w-5 h-5" />
              ) : (
                <Eye className="w-5 h-5" />
              )}
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-5 gap-2 text-xs">
            <Badge
              className={
                vaultPassword.length >= 8
                  ? "bg-green-500/20 text-green-400 border-green-500/30"
                  : "bg-slate-800 text-gray-400 border-slate-700"
              }
            >
              8+ chars
            </Badge>

            <Badge
              className={
                /[A-Z]/.test(vaultPassword)
                  ? "bg-green-500/20 text-green-400 border-green-500/30"
                  : "bg-slate-800 text-gray-400 border-slate-700"
              }
            >
              A-Z
            </Badge>

            <Badge
              className={
                /[a-z]/.test(vaultPassword)
                  ? "bg-green-500/20 text-green-400 border-green-500/30"
                  : "bg-slate-800 text-gray-400 border-slate-700"
              }
            >
              a-z
            </Badge>

            <Badge
              className={
                /[0-9]/.test(vaultPassword)
                  ? "bg-green-500/20 text-green-400 border-green-500/30"
                  : "bg-slate-800 text-gray-400 border-slate-700"
              }
            >
              0-9
            </Badge>

            <Badge
              className={
                /[^A-Za-z0-9]/.test(vaultPassword)
                  ? "bg-green-500/20 text-green-400 border-green-500/30"
                  : "bg-slate-800 text-gray-400 border-slate-700"
              }
            >
              @#$%
            </Badge>
          </div>

          <div className="flex items-start gap-2 text-sm">
            {passwordReady ? (
              <CheckCircle className="w-4 h-4 text-green-400 mt-0.5" />
            ) : (
              <AlertTriangle className="w-4 h-4 text-yellow-400 mt-0.5" />
            )}

            <p className={passwordReady ? "text-green-400" : "text-gray-400"}>
              {passwordReady
                ? language === "arabic"
                  ? "كلمة السر قوية وجاهزة للتشفير."
                  : "Password is strong and ready for encryption."
                : language === "arabic"
                ? passwordError || "اكتب كلمة سر قوية."
                : passwordError || "Enter a strong password."}
            </p>
          </div>

          <p className="text-gray-500 text-sm">
            {language === "arabic"
              ? "بعد الرفع سيتم مسح الباسورد من الشاشة. لتفعيل Offline سيتم حفظ نسخة محلية على هذا الجهاز."
              : "After upload, the password will be cleared. Enabling Offline saves a local copy on this device."}
          </p>
        </CardContent>
      </Card>

      <Card className="cyber-card">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Upload className="w-5 h-5 text-blue-400" />
            {language === "arabic" ? "رفع الملفات" : "Upload Files"}
          </CardTitle>
        </CardHeader>

        <CardContent>
          <input
            ref={uploadInputRef}
            type="file"
            multiple
            className="hidden"
            onChange={(e) => {
              handleFilesUpload(e.target.files);
              e.currentTarget.value = "";
            }}
          />

          <div
            onDragOver={(e) => {
              e.preventDefault();
              setDragActive(true);
            }}
            onDragLeave={() => setDragActive(false)}
            onDrop={(e) => {
              e.preventDefault();
              handleFilesUpload(e.dataTransfer.files);
            }}
            onClick={() => uploadInputRef.current?.click()}
            className={[
              "cursor-pointer rounded-2xl border border-dashed p-10 text-center transition",
              dragActive
                ? "border-blue-400 bg-blue-500/10"
                : "border-slate-600 bg-slate-950/40 hover:bg-slate-900/60",
            ].join(" ")}
          >
            <div className="mx-auto w-16 h-16 rounded-2xl bg-blue-500/15 flex items-center justify-center mb-4">
              {uploading ? (
                <Loader2 className="w-8 h-8 text-blue-400 animate-spin" />
              ) : (
                <Upload className="w-8 h-8 text-blue-400" />
              )}
            </div>

            <h3 className="text-white text-lg font-semibold">
              {uploading
                ? language === "arabic"
                  ? "جارٍ التشفير والرفع..."
                  : "Encrypting and uploading..."
                : language === "arabic"
                ? "اسحب الملفات هنا أو اضغط للاختيار"
                : "Drag files here or click to choose"}
            </h3>

            <p className="text-gray-400 text-sm mt-2">
              {language === "arabic"
                ? "يدعم PDF و DOCX و TXT وملفات الكود"
                : "Supports PDF, DOCX, TXT, and code files"}
            </p>

            <Button className="mt-5" disabled={uploading}>
              {language === "arabic" ? "اختيار ملفات" : "Choose Files"}
            </Button>
          </div>

          {error && (
            <div className="mt-5 rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-red-400 flex items-center gap-2">
              <AlertTriangle className="w-5 h-5" />
              <span>{error}</span>
            </div>
          )}

          {successMsg && (
            <div className="mt-5 rounded-xl border border-green-500/30 bg-green-500/10 p-4 text-green-400 flex items-center gap-2">
              <CheckCircle className="w-5 h-5" />
              <span>{successMsg}</span>
            </div>
          )}
        </CardContent>
      </Card>

      <Card className="cyber-card">
        <CardHeader>
          <CardTitle className="text-white">
            {language === "arabic" ? "محتويات الخزنة" : "Vault Contents"}
          </CardTitle>
        </CardHeader>

        <CardContent>
          {loading ? (
            <div className="flex items-center gap-3 text-gray-400 py-8">
              <Loader2 className="w-5 h-5 animate-spin" />
              {language === "arabic" ? "جارٍ التحميل..." : "Loading files..."}
            </div>
          ) : files.length === 0 ? (
            <div className="py-14 text-center rounded-2xl bg-slate-950/40 border border-slate-800">
              <FileText className="w-12 h-12 text-gray-500 mx-auto mb-3" />
              <p className="text-white font-semibold">
                {language === "arabic"
                  ? "لا توجد ملفات بعد"
                  : "No files uploaded yet"}
              </p>
              <p className="text-gray-400 text-sm mt-1">
                {language === "arabic"
                  ? "ابدأ برفع أول ملف مشفر داخل الخزنة."
                  : "Upload your first encrypted file to the vault."}
              </p>
            </div>
          ) : (
            <div className="rounded-2xl border border-slate-800 overflow-hidden">
              <Table>
                <TableHeader>
                  <TableRow className="bg-slate-950/60">
                    <TableHead>
                      {language === "arabic" ? "الملف" : "File"}
                    </TableHead>
                    <TableHead>
                      {language === "arabic" ? "النوع" : "Type"}
                    </TableHead>
                    <TableHead>
                      {language === "arabic" ? "الحجم" : "Size"}
                    </TableHead>
                    <TableHead>
                      {language === "arabic" ? "الحالة" : "Status"}
                    </TableHead>
                    <TableHead>
                      {language === "arabic" ? "تاريخ الرفع" : "Uploaded"}
                    </TableHead>
                    <TableHead>
                      {language === "arabic" ? "الإجراءات" : "Actions"}
                    </TableHead>
                  </TableRow>
                </TableHeader>

                <TableBody>
                  {files.map((f) => (
                    <TableRow key={f.id} className="hover:bg-slate-900/40">
                      <TableCell>
                        <div className="flex items-center gap-3">
                          <div className="w-10 h-10 rounded-xl bg-blue-500/10 flex items-center justify-center">
                            <FileText className="w-5 h-5 text-blue-400" />
                          </div>
                          <span className="text-white font-medium">
                            {f.name}
                          </span>
                        </div>
                      </TableCell>

                      <TableCell>
                        <Badge className="bg-slate-800 text-gray-300 border-slate-700 uppercase">
                          {f.type}
                        </Badge>
                      </TableCell>

                      <TableCell className="text-gray-300">
                        {f.sizeDisplay}
                      </TableCell>

                      <TableCell>
                        <div className="flex flex-col gap-2">
                          <Badge className="bg-green-500/20 text-green-400 border-green-500/30 flex items-center gap-1 w-fit">
                            <Lock className="w-3 h-3" />
                            {language === "arabic" ? "مشفر" : "Encrypted"}
                          </Badge>

                          {f.offlineEnabled && (
                            <Badge className="bg-purple-500/20 text-purple-400 border-purple-500/30 flex items-center gap-1 w-fit">
                              <WifiOff className="w-3 h-3" />
                              Offline
                            </Badge>
                          )}
                        </div>
                      </TableCell>

                      <TableCell className="text-gray-400">
                        {f.uploadedAt}
                      </TableCell>

                      <TableCell>
                        <div className="flex items-center gap-2 flex-wrap">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => openPasswordModal("offline", f)}
                          >
                            {f.offlineEnabled ? (
                              <>
                                <Wifi className="w-4 h-4 mr-1" />
                                Online
                              </>
                            ) : (
                              <>
                                <WifiOff className="w-4 h-4 mr-1" />
                                Offline
                              </>
                            )}
                          </Button>

                          <Button
                            size="sm"
                            onClick={() => openPasswordModal("download", f)}
                            className="bg-blue-600 hover:bg-blue-700"
                          >
                            <Download className="w-4 h-4" />
                          </Button>

                          <Button
                            size="sm"
                            variant="destructive"
                            onClick={() => openPasswordModal("delete", f)}
                          >
                            <Trash2 className="w-4 h-4" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      <Card className="cyber-card">
        <CardContent className="p-5 space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-gray-400">
              {language === "arabic"
                ? `المساحة المستخدمة: ${storageUsed} / 100 GB`
                : `Storage Used: ${storageUsed} / 100 GB`}
            </p>
            <p className="text-gray-400 text-sm">
              {storagePercentage.toFixed(2)}%
            </p>
          </div>

          <Progress value={storagePercentage} />
        </CardContent>
      </Card>

      {passwordModalOpen && passwordModalFile && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
          <div className="w-full max-w-md rounded-2xl border border-slate-700 bg-slate-950 p-6 shadow-2xl">
            <h2 className="text-xl font-bold text-white mb-2">
              {passwordModalMode === "download"
                ? language === "arabic"
                  ? "فك تشفير الملف"
                  : "Decrypt File"
                : passwordModalMode === "delete"
                ? language === "arabic"
                  ? "تأكيد حذف الملف"
                  : "Confirm Delete"
                : passwordModalFile.offlineEnabled
                ? language === "arabic"
                  ? "إلغاء Offline Access"
                  : "Disable Offline Access"
                : language === "arabic"
                ? "تفعيل Offline Access"
                : "Enable Offline Access"}
            </h2>

            <p className="text-gray-400 text-sm mb-4 break-words">
              {passwordModalMode === "download"
                ? language === "arabic"
                  ? `ادخل باسورد فك تشفير: ${passwordModalFile.name}`
                  : `Enter password to decrypt: ${passwordModalFile.name}`
                : passwordModalMode === "delete"
                ? language === "arabic"
                  ? `ادخل باسورد الملف لحذفه: ${passwordModalFile.name}`
                  : `Enter file password to delete: ${passwordModalFile.name}`
                : passwordModalFile.offlineEnabled
                ? language === "arabic"
                  ? `ادخل باسورد الملف لتأكيد إلغاء Offline: ${passwordModalFile.name}`
                  : `Enter file password to disable offline access: ${passwordModalFile.name}`
                : language === "arabic"
                ? `ادخل باسورد الملف لحفظ نسخة Offline: ${passwordModalFile.name}`
                : `Enter file password to save offline copy: ${passwordModalFile.name}`}
            </p>

            {!navigator.onLine &&
              passwordModalMode === "download" &&
              passwordModalFile.offlineEnabled && (
                <div className="mb-4 rounded-xl border border-purple-500/30 bg-purple-500/10 p-3 text-purple-300 text-sm">
                  {language === "arabic"
                    ? "أنت غير متصل بالإنترنت. سيتم استخدام النسخة المحفوظة على الجهاز."
                    : "You are offline. The saved local copy will be used."}
                </div>
              )}

            <input
              type="password"
              value={modalPassword}
              onChange={(e) => setModalPassword(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  handlePasswordModalConfirm();
                }
              }}
              placeholder={language === "arabic" ? "كلمة السر" : "Password"}
              className="w-full p-4 rounded-xl bg-slate-900 text-white border border-slate-700 focus:border-blue-400 outline-none"
            />

            <div className="flex justify-end gap-3 mt-5">
              <Button
                variant="outline"
                onClick={closePasswordModal}
                disabled={modalLoading}
              >
                {language === "arabic" ? "إلغاء" : "Cancel"}
              </Button>

              <Button
                variant={
                  passwordModalMode === "delete" ? "destructive" : "default"
                }
                onClick={handlePasswordModalConfirm}
                disabled={modalLoading}
              >
                {modalLoading ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : passwordModalMode === "download" ? (
                  language === "arabic" ? (
                    "تنزيل"
                  ) : (
                    "Download"
                  )
                ) : passwordModalMode === "delete" ? (
                  language === "arabic" ? (
                    "حذف"
                  ) : (
                    "Delete"
                  )
                ) : passwordModalFile.offlineEnabled ? (
                  language === "arabic" ? (
                    "إلغاء Offline"
                  ) : (
                    "Disable Offline"
                  )
                ) : language === "arabic" ? (
                  "تفعيل Offline"
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