---
name: secure-code-review
description: Professional skills and methodology for secure code review
version: 1.0.0
---

# Secure Code Review

## Overview

Secure code review is a key method for identifying security vulnerabilities in code. This skill provides methods, tooling, and best practices for secure code review.

## Review scope

### 1. Input validation

**Checks:**
- User-input validation
- Parameter validation
- Data filtering
- Bounds checking

### 2. Output encoding

**Checks:**
- XSS protection
- Output encoding
- Content Security Policy
- Response-header settings

### 3. Authentication and authorization

**Checks:**
- Authentication mechanism
- Session management
- Access control
- Password handling

### 4. Cryptography and keys

**Checks:**
- Data encryption
- Key management
- Hash algorithms
- Random-number generation

## Review methods

### 1. Static analysis

**SAST tools:**
```bash
# SonarQube
sonar-scanner

# Checkmarx
# Use the web interface

# Fortify
sourceanalyzer -b project build.sh
sourceanalyzer -b project -scan

# Semgrep
semgrep --config=auto .
```

### 2. Manual review

**Review checklist:**
- [ ] Input validation
- [ ] Output encoding
- [ ] SQL injection
- [ ] XSS vulnerabilities
- [ ] Authentication/authorization
- [ ] Cryptography usage
- [ ] Error handling
- [ ] Logging

### 3. Dangerous-pattern identification

**Dangerous functions:**
```python
# Python
eval()
exec()
pickle.loads()
os.system()
subprocess.call()
```

```java
// Java
Runtime.exec()
ProcessBuilder()
Class.forName()
```

```php
// PHP
eval()
exec()
system()
passthru()
```

## Common vulnerability patterns

### SQL injection

**Dangerous code:**
```java
String query = "SELECT * FROM users WHERE id = " + userId;
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);
```

**Safe code:**
```java
String query = "SELECT * FROM users WHERE id = ?";
PreparedStatement stmt = connection.prepareStatement(query);
stmt.setInt(1, userId);
ResultSet rs = stmt.executeQuery();
```

### XSS

**Dangerous code:**
```javascript
document.innerHTML = userInput;
element.innerHTML = "<div>" + userInput + "</div>";
```

**Safe code:**
```javascript
element.textContent = userInput;
element.setAttribute("data-value", userInput);
// or use an encoding library
element.innerHTML = escapeHtml(userInput);
```

### Command injection

**Dangerous code:**
```python
import os
os.system("ping " + user_input)
```

**Safe code:**
```python
import subprocess
subprocess.run(["ping", "-c", "1", validated_input])
```

### Path traversal

**Dangerous code:**
```java
String filePath = "/uploads/" + fileName;
File file = new File(filePath);
```

**Safe code:**
```java
String basePath = "/uploads/";
String fileName = Paths.get(fileName).getFileName().toString();
String filePath = basePath + fileName;
File file = new File(filePath);
if (!file.getCanonicalPath().startsWith(basePath)) {
    throw new SecurityException("Invalid path");
}
```

### Hardcoded secrets

**Dangerous code:**
```java
String apiKey = "1234567890abcdef";
String password = "admin123";
```

**Safe code:**
```java
String apiKey = System.getenv("API_KEY");
String password = keyStore.getPassword("db_password");
```

## Tool usage

### SonarQube

```bash
# Start SonarQube
docker run -d -p 9000:9000 sonarqube

# Run a scan
sonar-scanner \
  -Dsonar.projectKey=myproject \
  -Dsonar.sources=. \
  -Dsonar.host.url=http://localhost:9000
```

### Semgrep

```bash
# Install
pip install semgrep

# Run a scan
semgrep --config=auto .

# Use a ruleset
semgrep --config=p/security-audit .
```

### CodeQL

```bash
# Create a database
codeql database create database --language=java --source-root=.

# Run queries
codeql database analyze database security-and-quality.qls --format=sarif-latest
```

## Review checklist

### Input validation
- [ ] All user input is validated
- [ ] Allowlist validation used
- [ ] Data types and ranges checked
- [ ] Special characters handled

### Output encoding
- [ ] HTML output encoding
- [ ] URL encoding
- [ ] JavaScript encoding
- [ ] SQL parameterization

### Authentication and authorization
- [ ] Strong password policy
- [ ] Secure session management
- [ ] Permission checks
- [ ] Multi-factor authentication

### Cryptography
- [ ] Strong encryption algorithms
- [ ] Secure key storage
- [ ] Transport encryption
- [ ] At-rest encryption

### Error handling
- [ ] No sensitive info leaked
- [ ] Uniform error responses
- [ ] Errors logged
- [ ] Exceptions handled

## Best practices

### 1. Secure coding standards

- Follow the OWASP Top 10
- Use secure-coding guidelines
- Establish a code-review process
- Security training

### 2. Automation

- Integrate SAST tools
- CI/CD security checks
- Automated scanning
- Result analysis

### 3. Review process

- Peer review
- Security-expert review
- Periodic reviews
- Track findings

## Notes

- Combine tooling with manual review
- Focus on business-logic flaws
- Keep tool rules updated
- Build a secure-coding culture
