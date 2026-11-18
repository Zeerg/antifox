---
name: api-security-testing
description: Professional skills and methodology for API security testing
version: 1.0.0
---

# API Security Testing

## Overview

API security testing is essential for securing API endpoints. This skill provides methods, tooling, and best practices.

## Test scope

### 1. Authentication and authorization

**Tests:**
- Token validity
- Token-expiry handling
- Access control
- Role/permission checks

### 2. Input validation

**Tests:**
- Parameter-type validation
- Data-length limits
- Special-character handling
- SQL-injection defenses
- XSS defenses

### 3. Business logic

**Tests:**
- Workflow validation
- State transitions
- Concurrency control
- Business rules

### 4. Error handling

**Tests:**
- Error-message leakage
- Stack traces
- Sensitive-data exposure

## Testing methodology

### 1. API discovery

**Find API endpoints:**
```bash
# Directory scanning
gobuster dir -u https://target.com -w api-wordlist.txt

# Passive Burp Suite scanning
# Browse the app and observe API calls

# Analyze JavaScript files
# Look for API endpoint definitions
```

### 2. Authentication testing

**Token tests:**
```http
# Invalid token
GET /api/user
Authorization: Bearer invalid_token

# Expired token
GET /api/user
Authorization: Bearer expired_token

# No token
GET /api/user
```

**JWT tests:**
```bash
# jwt_tool
python jwt_tool.py <JWT_TOKEN>

# Algorithm confusion
python jwt_tool.py <JWT_TOKEN> -X a

# Secret brute-force
python jwt_tool.py <JWT_TOKEN> -C -d wordlist.txt
```

### 3. Authorization testing

**Horizontal privilege:**
```http
# User A accessing user B's resource
GET /api/user/123
Authorization: Bearer user_a_token

# Should return 403
```

**Vertical privilege:**
```http
# Regular user hitting an admin endpoint
GET /api/admin/users
Authorization: Bearer user_token

# Should return 403
```

### 4. Input-validation testing

**SQL injection:**
```http
POST /api/search
{
  "query": "test' OR '1'='1"
}
```

**Command injection:**
```http
POST /api/execute
{
  "command": "ping; id"
}
```

**XXE:**
```http
POST /api/parse
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

### 5. Rate-limit testing

**Test rate limits:**
```python
import requests

for i in range(1000):
    response = requests.get('https://target.com/api/endpoint')
    print(f"Request {i}: {response.status_code}")
```

## Tool usage

### Postman

**Build a test collection:**
1. Import the API spec
2. Configure authentication
3. Create test cases
4. Run automated tests

### Burp Suite

**API scanning:**
1. Configure API endpoints
2. Set authentication
3. Run active scanning
4. Analyze results

### OWASP ZAP

```bash
# API scan
zap-cli quick-scan --self-contained \
  --start-options '-config api.disablekey=true' \
  http://target.com/api
```

### REST-Attacker

```bash
# Scan an OpenAPI spec
rest-attacker scan openapi.yaml
```

## Common vulnerabilities

### 1. Authentication bypass

**Token-validation flaws:**
- Weak token generation
- Predictable tokens
- Unsigned-token acceptance

### 2. Privilege escalation

**IDOR:**
- Direct object references
- Missing ownership verification

### 3. Information disclosure

**Error messages:**
- Verbose errors
- Stack traces
- Sensitive data

### 4. Injection

**Common injections:**
- SQL injection
- NoSQL injection
- Command injection
- XXE

### 5. Business logic

**Logic flaws:**
- Price manipulation
- Quantity-limit bypass
- State modification

## Testing checklist

### Authentication
- [ ] Token validity
- [ ] Token-expiry handling
- [ ] Weak-token detection
- [ ] Token-replay attacks

### Authorization
- [ ] Horizontal-privilege tests
- [ ] Vertical-privilege tests
- [ ] Role/permission checks
- [ ] Resource access control

### Input validation
- [ ] SQL-injection tests
- [ ] XSS tests
- [ ] Command-injection tests
- [ ] XXE tests
- [ ] Parameter pollution

### Business logic
- [ ] Workflow validation
- [ ] State transitions
- [ ] Concurrency control
- [ ] Business rules

### Error handling
- [ ] Error-message leakage
- [ ] Stack traces
- [ ] Sensitive-data exposure

## Defenses

### Recommended

1. **Authentication**
   - Strong tokens
   - Token refresh
   - Signature verification

2. **Authorization**
   - Role-based access control
   - Ownership verification
   - Least privilege

3. **Input validation**
   - Type checks
   - Length limits
   - Allowlists

4. **Error handling**
   - Uniform error responses
   - No detailed info leaked
   - Error logging

5. **Rate limiting**
   - API throttling
   - Brute-force protection
   - Anomalous-request monitoring

## Notes

- Test only in authorized environments
- Avoid impacting the API
- Mind differences across API versions
- Watch request rates while testing
