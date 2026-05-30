# Encrypted File Vault Security Test Checklist

Use this checklist after starting the backend and frontend locally.

## Offline Vault

- Upload a normal allowed file such as `notes.txt` with a strong vault password.
- Enable offline access and enter the correct vault password.
- Open browser DevTools, inspect IndexedDB `sentinel_offline_vault` / `offline_files`, and confirm the record contains `encryptedBlob`, `salt`, `iv`, `kdf`, `iterations`, and `encryption`, not a plaintext `blob`.
- Confirm the encrypted blob cannot be opened or read as the original file content from IndexedDB.
- Disconnect the backend or go offline, then download the offline file with a wrong password. It must fail with a password/corruption error.
- Download the offline file with the correct password. It must decrypt and download successfully.
- Disable offline access and confirm the IndexedDB record for that document is removed.

## Upload Rules

- Try uploading `.env`, `.sql`, `.sh`, `.bat`, `.ps1`, and `.php` files. The UI should block them with: `This file type is not allowed for security reasons.`
- Try uploading an allowed `.txt` file. It should upload normally.
- Try uploading a file larger than 50 MB. The UI should show that the file size exceeds the allowed limit.

## Backend Safety

- List vault documents after normal uploads and confirm the endpoint returns safe metadata.
- Corrupt or tamper with a vault document `stored_filename` in a local test database to include path traversal, then call `GET /api/documents`. The endpoint should not stat outside the vault directory or crash.
- Delete a vault file and verify activity logs/admin reports include the document ID and original filename.
- Attempt to download or delete another user's vault document. The response should be a 403 JSON message without exposing internals.

## Admin/Reporting

- Check Admin Threat Management after wrong password, denied access, offline enable, and delete actions.
- Check File Vault Activity Summary and confirm deleted/offline actions show target file details without decrypted content.
