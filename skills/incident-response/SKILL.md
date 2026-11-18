---
name: incident-response
description: Professional skills and methodology for security incident response
version: 1.0.0
---

# Security Incident Response

## Overview

Incident response is the key process for handling security events. This skill provides methods, tooling, and best practices for incident response.

## Response process

### 1. Preparation

**Prepare:**
- Establish a response team
- Develop a response plan
- Ready tools and resources
- Establish communication channels

### 2. Identification

**Identify events:**
- Monitoring alerts
- Anomaly detection
- Log analysis
- User reports

### 3. Containment

**Containment measures:**
- Isolate affected systems
- Disable accounts
- Block network connections
- Preserve evidence

### 4. Eradication

**Remove the threat:**
- Remove malware
- Patch vulnerabilities
- Reset credentials
- Clean out backdoors

### 5. Recovery

**Restore systems:**
- Restore from backups
- Verify system integrity
- Monitor systems
- Restore services gradually

### 6. Lessons learned

**Debrief:**
- Incident report
- Lessons learned
- Improvement actions
- Update processes

## Tool usage

### Log analysis

**Splunk:**
```bash
# Search logs
index=security event_type="failed_login"

# Statistical analysis
index=security | stats count by src_ip

# Time-series analysis
index=security | timechart count by event_type
```

**ELK:**
```bash
# Elasticsearch query
GET /logs/_search
{
  "query": {
    "match": {
      "event_type": "malware"
    }
  }
}
```

### Forensic tools

**Volatility:**
```bash
# Analyze a memory image
volatility -f memory.dump imageinfo

# List processes
volatility -f memory.dump --profile=Win7SP1x64 pslist

# Dump process memory
volatility -f memory.dump --profile=Win7SP1x64 memdump -p 1234 -D output/
```

**Autopsy:**
```bash
# Start Autopsy
# Create a case
# Add evidence
# Analyze the data
```

### Network analysis

**Wireshark:**
```bash
# Capture traffic
wireshark -i eth0

# Analyze a PCAP file
wireshark -r capture.pcap

# Filter traffic
# Display filter: ip.addr == 192.168.1.100
# Capture filter: host 192.168.1.100
```

**tcpdump:**
```bash
# Capture traffic
tcpdump -i eth0 -w capture.pcap

# Analyze traffic
tcpdump -r capture.pcap -A
```

## Incident types

### Malware

**Response steps:**
1. Isolate affected systems
2. Collect samples
3. Analyze the malware
4. Eradicate the threat
5. Patch the vulnerabilities

**Tools:**
- VirusTotal
- Cuckoo Sandbox
- YARA rules

### Data breach

**Response steps:**
1. Confirm the breach scope
2. Contain the leak
3. Assess impact
4. Notify stakeholders
5. Fix the vulnerabilities

**Check:**
- Volume of leaked data
- Affected users
- Leak channel
- Data sensitivity

### Denial of service

**Response steps:**
1. Confirm the attack type
2. Enable protective measures
3. Filter malicious traffic
4. Monitor system status
5. Restore normal service

**Protective measures:**
- DDoS protection services
- Traffic scrubbing
- Rate limiting
- CDN protection

### Unauthorized access

**Response steps:**
1. Disable affected accounts
2. Reset credentials
3. Review access logs
4. Assess data access
5. Fix the vulnerabilities

**Check:**
- Access times
- Accessed content
- Access sources
- Data modifications

## Response checklist

### Preparation
- [ ] Establish a response team
- [ ] Develop a response plan
- [ ] Prepare tools
- [ ] Establish communication channels

### Identification
- [ ] Confirm the event
- [ ] Collect information
- [ ] Assess impact
- [ ] Record the timeline

### Containment
- [ ] Isolate systems
- [ ] Disable accounts
- [ ] Block connections
- [ ] Preserve evidence

### Eradication
- [ ] Remove the threat
- [ ] Patch vulnerabilities
- [ ] Reset credentials
- [ ] Verify eradication

### Recovery
- [ ] Restore systems
- [ ] Verify integrity
- [ ] Monitor systems
- [ ] Restore services

### Lessons learned
- [ ] Write the report
- [ ] Summarize lessons
- [ ] Improvement actions
- [ ] Update processes

## Best practices

### 1. Preparation

- Establish a response team
- Develop a response plan
- Drill regularly
- Prepare tools

### 2. Response

- Respond fast
- Work systematically
- Log every action
- Preserve evidence

### 3. Communication

- Internal communication
- External notification
- Status updates
- Post-incident reports

### 4. Improvement

- Incident analysis
- Process improvement
- Tool updates
- Training

## Notes

- Respond fast
- Preserve evidence
- Log actions
- Comply with laws and regulations
