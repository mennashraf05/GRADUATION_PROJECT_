const DB_NAME = "sentinel_offline_vault";
const STORE_NAME = "offline_files";
const DB_VERSION = 2;
const KDF_ITERATIONS = 390000;

export type OfflineVaultFile = {
  id: number;
  documentId: string;
  originalName: string;
  mimeType: string;
  size: number;
  encryptedBlob: Blob;
  salt: string;
  iv: string;
  kdf: "PBKDF2-SHA256";
  iterations: number;
  encryption: "AES-GCM";
  createdAt: string;
  updatedAt: string;
};

const getCrypto = (): Crypto => {
  if (!globalThis.crypto?.subtle) {
    throw new Error("Secure offline storage requires Web Crypto support.");
  }
  return globalThis.crypto;
};

const bytesToBase64 = (bytes: Uint8Array): string => {
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
};

const base64ToBytes = (value: string): Uint8Array => {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
};

const deriveOfflineKey = async (
  password: string,
  salt: Uint8Array,
  iterations: number
): Promise<CryptoKey> => {
  const crypto = getCrypto();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
};

const openDB = (): Promise<IDBDatabase> => {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = () => {
      const db = request.result;

      if (request.oldVersion > 0 && request.oldVersion < 2) {
        if (db.objectStoreNames.contains(STORE_NAME)) {
          db.deleteObjectStore(STORE_NAME);
        }
      }

      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: "id" });
      }
    };

    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
};

export const encryptOfflineBlob = async ({
  id,
  name,
  blob,
  password,
}: {
  id: number;
  name: string;
  blob: Blob;
  password: string;
}): Promise<OfflineVaultFile> => {
  const crypto = getCrypto();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveOfflineKey(password, salt, KDF_ITERATIONS);
  const plaintext = await blob.arrayBuffer();
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    plaintext
  );
  const now = new Date().toISOString();

  return {
    id,
    documentId: String(id),
    originalName: name,
    mimeType: blob.type || "application/octet-stream",
    size: blob.size,
    encryptedBlob: new Blob([ciphertext], { type: "application/octet-stream" }),
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    kdf: "PBKDF2-SHA256",
    iterations: KDF_ITERATIONS,
    encryption: "AES-GCM",
    createdAt: now,
    updatedAt: now,
  };
};

export const decryptOfflineBlob = async (
  file: OfflineVaultFile,
  password: string
): Promise<Blob> => {
  if (file.encryption !== "AES-GCM" || file.kdf !== "PBKDF2-SHA256") {
    throw new Error("Unsupported offline vault encryption format.");
  }

  try {
    const crypto = getCrypto();
    const salt = base64ToBytes(file.salt);
    const iv = base64ToBytes(file.iv);
    const key = await deriveOfflineKey(password, salt, file.iterations);
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      await file.encryptedBlob.arrayBuffer()
    );
    return new Blob([plaintext], {
      type: file.mimeType || "application/octet-stream",
    });
  } catch {
    throw new Error("Wrong encryption password or corrupted offline copy.");
  }
};

export const saveOfflineFile = async (file: OfflineVaultFile) => {
  const db = await openDB();

  return new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    const store = tx.objectStore(STORE_NAME);

    store.put({ ...file, updatedAt: new Date().toISOString() });

    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
};

export const getOfflineFile = async (
  id: number
): Promise<OfflineVaultFile | null> => {
  const db = await openDB();

  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readonly");
    const store = tx.objectStore(STORE_NAME);
    const request = store.get(id);

    request.onsuccess = () => resolve(request.result || null);
    request.onerror = () => reject(request.error);
  });
};

export const deleteOfflineFile = async (id: number) => {
  const db = await openDB();

  return new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    const store = tx.objectStore(STORE_NAME);

    store.delete(id);

    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
};
