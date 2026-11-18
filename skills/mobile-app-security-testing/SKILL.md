---
name: mobile-app-security-testing
description: Professional skills and methodology for mobile application security testing
version: 1.0.0
---

# Mobile Application Security Testing

## Overview

Mobile app security testing is essential for ensuring mobile application security. This skill provides methods, tooling, and best practices for both Android and iOS platforms.

## Test scope

### 1. Application security

**Checks:**
- Code obfuscation
- Decompilation protection
- Anti-debugging
- Certificate pinning

### 2. Data security

**Checks:**
- Data encryption
- Key management
- Sensitive-data storage
- Data in transit

### 3. Authentication & authorization

**Checks:**
- Authentication mechanisms
- Token management
- Biometrics
- Session management

### 4. Communication security

**Checks:**
- TLS/SSL configuration
- Certificate validation
- API security
- MITM protection

## Android security testing

### Static analysis

**APKTool:**
```bash
# Decompile the APK
apktool d app.apk

# Inspect AndroidManifest.xml
cat app/AndroidManifest.xml

# Inspect Smali code
find app/smali -name "*.smali"
```

**Jadx:**
```bash
# Decompile the APK
jadx -d output app.apk

# Inspect Java sources
find output -name "*.java"
```

**MobSF:**
```bash
# Start MobSF
docker run -it -p 8000:8000 opensecurity/mobsf

# Upload the APK for analysis
# Open http://localhost:8000
```

### Dynamic analysis

**Frida:**
```javascript
// Hook a function
Java.perform(function() {
    var MainActivity = Java.use("com.example.MainActivity");
    MainActivity.onCreate.implementation = function(savedInstanceState) {
        console.log("[*] onCreate called");
        this.onCreate(savedInstanceState);
    };
});
```

**Objection:**
```bash
# Start Objection
objection -g com.example.app explore

# Hook a function
android hooking watch class_method com.example.MainActivity.onCreate
```

**Burp Suite:**
```bash
# Configure the proxy
# Point the Android proxy at Burp Suite
# Install the Burp certificate
```

### Common vulnerabilities

**Hardcoded keys:**
```java
// Insecure code
String apiKey = "1234567890abcdef";
String password = "admin123";
```

**Insecure storage:**
```java
// Sensitive data in SharedPreferences
SharedPreferences prefs = getSharedPreferences("data", MODE_WORLD_READABLE);
prefs.edit().putString("password", password).apply();
```

**Certificate-validation bypass:**
```java
// Never validates certificates
TrustManager[] trustAllCerts = new TrustManager[] {
    new X509TrustManager() {
        public X509Certificate[] getAcceptedIssuers() { return null; }
        public void checkClientTrusted(X509Certificate[] certs, String authType) { }
        public void checkServerTrusted(X509Certificate[] certs, String authType) { }
    }
};
```

## iOS security testing

### Static analysis

**class-dump:**
```bash
# Export headers
class-dump app.ipa

# Inspect headers
find app -name "*.h"
```

**Hopper:**
```bash
# Disassemble with Hopper
# Open the app binary
# Analyze the assembly
```

**otool:**
```bash
# Inspect Mach-O info
otool -L app

# Search strings
strings app | grep -i "password\|key\|secret"
```

### Dynamic analysis

**Frida:**
```javascript
// Hook an Objective-C method
var className = ObjC.classes.ViewController;
var method = className['- login:password:'];
Interceptor.attach(method.implementation, {
    onEnter: function(args) {
        console.log("[*] Login called");
        console.log("Username: " + ObjC.Object(args[2]).toString());
        console.log("Password: " + ObjC.Object(args[3]).toString());
    }
});
```

**Cycript:**
```bash
# Attach to a process
cycript -p app

# Run commands
[UIApplication sharedApplication]
```

### Common vulnerabilities

**Hardcoded keys:**
```objective-c
// Insecure code
NSString *apiKey = @"1234567890abcdef";
NSString *password = @"admin123";
```

**Insecure storage:**
```objective-c
// Poor Keychain usage — password in NSUserDefaults
NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
[defaults setObject:password forKey:@"password"];
```

**Certificate-validation bypass:**
```objective-c
// Never validates certificates
- (void)connection:(NSURLConnection *)connection 
didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
    [challenge.sender useCredential:[NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust] 
          forAuthenticationChallenge:challenge];
}
```

## Tool usage

### MobSF

```bash
# Start MobSF
docker run -it -p 8000:8000 opensecurity/mobsf

# Upload the app for analysis
# Supports Android and iOS
```

### Frida

```bash
# Install Frida
pip install frida-tools

# Run a script
frida -U -f com.example.app -l script.js
```

### Objection

```bash
# Install Objection
pip install objection

# Start Objection
objection -g com.example.app explore
```

### Burp Suite

**Configure the proxy:**
1. Configure a Burp Suite listener
2. Point the mobile device proxy at it
3. Install the Burp certificate
4. Intercept and analyze traffic

## Testing checklist

### Application security
- [ ] Code-obfuscation check
- [ ] Decompilation protection
- [ ] Anti-debugging
- [ ] Certificate pinning

### Data security
- [ ] Data-encryption check
- [ ] Key management
- [ ] Sensitive-data storage
- [ ] Data-in-transit security

### Authentication & authorization
- [ ] Authentication-mechanism testing
- [ ] Token management
- [ ] Session management
- [ ] Biometrics

### Communication security
- [ ] TLS/SSL configuration
- [ ] Certificate validation
- [ ] API security testing
- [ ] MITM protection

## Common security issues

### 1. Hardcoded keys

**Problem:**
- Hardcoded API keys
- Hardcoded passwords
- Hardcoded encryption keys

**Fix:**
- Use a key-management service
- Use environment variables
- Use secure storage

### 2. Insecure storage

**Problem:**
- Sensitive data stored in plaintext
- Insecure storage mechanisms
- Unencrypted data

**Fix:**
- Use encrypted storage
- Use Keychain/Keystore
- Implement data encryption

### 3. Certificate-validation bypass

**Problem:**
- SSL certificates not validated
- Self-signed certificates accepted
- No certificate pinning

**Fix:**
- Implement certificate pinning
- Validate the certificate chain
- Use the system trust store

### 4. Debug-information leakage

**Problem:**
- Logs contain sensitive info
- Error messages leak details
- Debug mode not disabled

**Fix:**
- Remove debug code
- Restrict log output
- Disable debugging in production

## Best practices

### 1. Code security

- Implement code obfuscation
- Disable debug features
- Implement anti-debugging
- Use certificate pinning

### 2. Data security

- Encrypt sensitive data
- Use secure storage
- Implement key management
- Restrict data access

### 3. Communication security

- Use TLS/SSL
- Implement certificate pinning
- Validate server certificates
- Use secure APIs

### 4. Authentication security

- Implement strong authentication
- Secure token management
- Implement session management
- Use biometrics

## Notes

- Test only in authorized environments
- Comply with laws and regulations
- Mind platform differences
- Protect user privacy
