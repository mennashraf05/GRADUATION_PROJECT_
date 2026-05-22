# Admin Console Access

## Accessing the Admin Console

The admin console is hidden from the public interface for security reasons. To access it:

### Method 1: Keyboard Shortcut (Recommended)
Press **Ctrl+Shift+A** (Windows/Linux) or **Cmd+Shift+A** (Mac) from anywhere in the application to access the admin login page.

### Method 2: Direct Navigation
If you have access to the navigation function, call:
```javascript
handleNavigate('admin-login')
```

### Method 3: Browser Console
Open your browser's developer console and enter:
```javascript
// This is a demo - in production, use proper routing
window.location.hash = '#admin-login'
```

## Credentials

- **Email and password** are stored only in the private dashboard environment configuration (restart the dev server after changes).
- **2FA** is real TOTP (Google Authenticator, etc.): the first successful login on a browser shows a **QR code**; after you scan and confirm with a code, the TOTP secret is stored only in that browser’s `localStorage`. Later logins use the rotating code from the app. Use **Reset authenticator on this device** to scan a new QR.

## Security Notes

- In production, admin routes should be on a separate subdomain (e.g., `admin.sentinel-ai.com`)
- All admin access is logged and monitored
- The admin console is completely separate from the main user interface
- Users without admin authentication will see a 403 Forbidden page when attempting to access `/admin`

## Features

The admin console includes:
- User & Role Management (RBAC)
- Alert & Incident Management
- Module Configuration
- Threat Intelligence Monitoring
- Job Scheduling
- System Health Monitoring
- Audit Logs
- Integration Management
- Report Generation
- System Settings

## Navigation

Once logged in, you can:
- Navigate between 11 different admin sections
- Logout using the red "Logout" button in the top-right corner
- Access is protected - logging out will require re-authentication
