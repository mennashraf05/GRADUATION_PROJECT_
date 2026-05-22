# Testing Admin Console Flow

## Quick Test Guide

Follow these steps to test the complete admin authentication flow:

### 1. Access Admin Login
**Option A:** Press `Ctrl+Shift+A` (Windows/Linux) or `Cmd+Shift+A` (Mac)
**Option B:** Manually navigate to the admin login in your code

### 2. Login Screen
You should see:
- Dark themed login page (#0B0F19 background)
- Orange/red gradient shield icon
- "Admin Console" title
- "Sentinel AI Administrative Access" subtitle
- Email and password input fields

### 3. Enter credentials
Use the private admin credentials configured in the dashboard environment file (restart the dev server if you changed them).

### 4. First-time 2FA (new browser)
If this browser has no TOTP yet: scan the **QR** with an authenticator app, then enter the current **6-digit code** to finish setup.

### 5. Two-Factor Authentication (returning)
After email/password, enter the **current** rotating code from the app → "Verify & Login".

### 6. Admin Console
You should now see:
- Full admin console with dark theme
- Top header with "Sentinel AI Admin" branding
- Left sidebar with 11 sections:
  - Overview
  - Users & Roles
  - Alerts & Incidents
  - Modules
  - Threat Intel
  - Jobs & Scheduling
  - System Health
  - Audit Logs
  - Integrations
  - Reports
  - Settings
- Red "Logout" button in top-right corner
- Search bar and quick actions

### 7. Navigate Sections
Click through different sections to verify:
- Overview: KPI cards, charts, activity feed
- Users & Roles: User table, filters, role management
- Alerts & Incidents: Alert table with severity chips
- Modules: Grid of security modules with config
- And more...

### 8. Test Protection
- Click the "Logout" button
- You should be redirected to the home page
- Try to access admin directly without logging in
- You should see the 403 Forbidden page

### 9. 403 Forbidden Page
The forbidden page should show:
- Large "403" error code
- "Access Forbidden" message
- Security notice
- Options to:
  - Go to Homepage
  - Admin Login

## Expected Behavior

### ✅ Correct Behavior
- No admin links visible in public UI
- Admin login requires email + password + 2FA
- Invalid credentials show error messages
- Successful login redirects to admin console
- Admin console is fully functional
- Logout works and requires re-authentication
- Accessing /admin without auth shows 403

### ❌ Incorrect Behavior
- Admin links visible in sidebar
- Bypassing authentication to access admin
- No 403 page when unauthorized
- Logout doesn't clear authentication
- Admin sections visible in main layout

## Security Features Implemented

1. **Separate Authentication Flow**
   - Dedicated admin login page
   - Two-factor authentication support
   - Session management

2. **Route Protection**
   - Admin routes require authentication token
   - Unauthorized access shows 403 Forbidden
   - Clean separation from main user interface

3. **Hidden Access**
   - No visible links in public UI
   - Keyboard shortcut for easy development access
   - Can be accessed only by those who know

4. **Consistent Design**
   - Matches Sentinel AI dark theme
   - Professional enterprise aesthetic
   - Smooth animations and transitions

## Notes

- In production, admin console should be on a separate subdomain
- All admin actions should be logged (implemented in Audit Logs)
- Consider additional security measures (IP whitelisting, rate limiting)
- Current implementation uses client-side state (use proper JWT/session tokens in production)
