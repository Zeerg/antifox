---
name: cloud-security-audit
description: Professional skills and methodology for cloud security auditing
version: 1.0.0
---

# Cloud Security Audit

## Overview

Cloud security auditing is essential for evaluating the security of cloud environments. This skill provides methods, tooling, and best practices covering AWS, Azure, GCP, and other major cloud platforms.

## Audit scope

### 1. Identity and access management

**Checks:**
- IAM policy configuration
- User permissions
- Role permissions
- Access-key management

### 2. Network security

**Checks:**
- Security-group configuration
- Network ACLs
- VPC configuration
- Traffic encryption

### 3. Data security

**Checks:**
- Data encryption
- Key management
- Backup policies
- Data classification

### 4. Compliance

**Checks:**
- Compliance frameworks
- Audit logs
- Monitoring and alerting
- Incident response

## AWS security audit

### IAM audit

**Check IAM policies:**
```bash
# List all IAM users
aws iam list-users

# List all IAM policies
aws iam list-policies

# Check user permissions
aws iam list-user-policies --user-name username
aws iam list-attached-user-policies --user-name username

# Check role permissions
aws iam list-role-policies --role-name rolename
```

**Common issues:**
- Excessive permissions
- Unused access keys
- Weak password policy
- MFA not enabled

### S3 security audit

**Check S3 buckets:**
```bash
# List all buckets
aws s3 ls

# Check the bucket policy
aws s3api get-bucket-policy --bucket bucketname

# Check the bucket ACL
aws s3api get-bucket-acl --bucket bucketname

# Check bucket encryption
aws s3api get-bucket-encryption --bucket bucketname
```

**Common issues:**
- Public access
- No encryption
- Versioning not enabled
- Logging not enabled

### Security-group audit

**Check security groups:**
```bash
# List all security groups
aws ec2 describe-security-groups

# Check open ports
aws ec2 describe-security-groups --group-ids sg-xxx
```

**Common issues:**
- 0.0.0.0/0 open
- Unnecessary ports open
- Overly permissive rules

### CloudTrail audit

**Check audit logs:**
```bash
# List all trails
aws cloudtrail describe-trails

# Check log-file integrity
aws cloudtrail get-trail-status --name trailname
```

## Azure security audit

### Subscriptions and resource groups

**Check subscriptions:**
```bash
# List all subscriptions
az account list

# Check resource groups
az group list
```

### Network security groups

**Check NSGs:**
```bash
# List all NSGs
az network nsg list

# Check NSG rules
az network nsg rule list --nsg-name nsgname --resource-group rgname
```

### Storage accounts

**Check storage accounts:**
```bash
# List all storage accounts
az storage account list

# Check access policies
az storage account show --name accountname --resource-group rgname
```

## GCP security audit

### Projects and organizations

**Check projects:**
```bash
# List all projects
gcloud projects list

# Check IAM policy
gcloud projects get-iam-policy project-id
```

### Compute Engine

**Check instances:**
```bash
# List all instances
gcloud compute instances list

# Check firewall rules
gcloud compute firewall-rules list
```

### Storage

**Check buckets:**
```bash
# List all buckets
gsutil ls

# Check bucket permissions
gsutil iam get gs://bucketname
```

## Automated tooling

### Scout Suite

```bash
# AWS audit
scout aws

# Azure audit
scout azure

# GCP audit
scout gcp
```

### Prowler

```bash
# AWS security audit
prowler -c check11,check12,check13

# Full audit
prowler
```

### CloudSploit

```bash
# Scan an AWS account
cloudsploit scan aws

# Scan an Azure subscription
cloudsploit scan azure
```

### Pacu

```bash
# AWS penetration-testing framework
pacu
```

## Audit checklist

### IAM security
- [ ] Check user permissions
- [ ] Check role permissions
- [ ] Check access keys
- [ ] Check password policy
- [ ] Check MFA enablement

### Network security
- [ ] Check security-group/NSG rules
- [ ] Check VPC configuration
- [ ] Check network ACLs
- [ ] Check traffic encryption

### Data security
- [ ] Check data encryption
- [ ] Check key management
- [ ] Check backup policy
- [ ] Check data classification

### Compliance
- [ ] Check audit logs
- [ ] Check monitoring/alerting
- [ ] Check incident response
- [ ] Check compliance frameworks

## Common security issues

### 1. Excessive permissions

**Problem:**
- Overly permissive IAM policies
- Users holding admin rights
- Overly broad role permissions

**Fix:**
- Least-privilege principle
- Regular permission reviews
- Simulate IAM policies

### 2. Public resources

**Problem:**
- Public S3 buckets
- Security groups open to 0.0.0.0/0
- Publicly accessible databases

**Fix:**
- Restrict access scope
- Use private networking
- Enable access controls

### 3. Unencrypted data

**Problem:**
- Unencrypted storage
- Unencrypted transit
- Poor key management

**Fix:**
- Enable encryption
- Use TLS/SSL
- Use a key-management service

### 4. Missing logs

**Problem:**
- Audit logs not enabled
- Logs not retained
- Logs not monitored

**Fix:**
- Enable CloudTrail/Azure Monitor
- Set log-retention policies
- Configure monitoring alerts

## Best practices

### 1. Least privilege

- Grant only what's needed
- Review permissions regularly
- Simulate IAM policies

### 2. Defense in depth

- Network-layer protection
- Application-layer protection
- Data-layer protection

### 3. Monitoring and alerting

- Enable audit logs
- Configure monitoring alerts
- Establish an incident-response process

### 4. Compliance

- Follow compliance frameworks
- Audit security regularly
- Document security policies

## Notes

- Audit only in authorized environments
- Avoid impacting production
- Mind differences across cloud platforms
- Audit security regularly
