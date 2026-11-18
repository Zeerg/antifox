---
name: container-security-testing
description: Professional skills and methodology for container security testing
version: 1.0.0
---

# Container Security Testing

## Overview

Container security testing is essential for securing containerized applications. This skill provides methods, tooling, and best practices covering Docker, Kubernetes, and other container technologies.

## Test scope

### 1. Image security

**Checks:**
- Base-image vulnerabilities
- Dependency vulnerabilities
- Image configuration
- Sensitive information

### 2. Runtime security

**Checks:**
- Container privileges
- Resource limits
- Network isolation
- Filesystem

### 3. Orchestration security

**Checks:**
- Kubernetes configuration
- Service accounts
- RBAC
- Network policies

## Docker security testing

### Image scanning

**Trivy:**
```bash
# Scan an image
trivy image nginx:latest

# Scan a local image archive
trivy image --input nginx.tar

# Show only high-severity findings
trivy image --severity HIGH,CRITICAL nginx:latest
```

**Clair:**
```bash
# Start Clair
docker run -d --name clair clair:latest

# Scan an image
clair-scanner --ip 192.168.1.100 nginx:latest
```

**Docker Bench:**
```bash
# Run the Docker security benchmark
docker run --rm --net host --pid host --userns host --cap-add audit_control \
  -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
  -v /etc:/etc:ro \
  -v /usr/bin/containerd:/usr/bin/containerd:ro \
  -v /usr/bin/runc:/usr/bin/runc:ro \
  -v /usr/lib/systemd:/usr/lib/systemd:ro \
  -v /var/lib:/var/lib:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  --label docker_bench_security \
  docker/docker-bench-security
```

### Container-configuration checks

**Check the Dockerfile:**
```dockerfile
# Insecurity examples
FROM ubuntu:latest  # uses the latest tag
RUN apt-get update && apt-get install -y curl  # unpinned version
COPY . /app  # may include sensitive files
ENV PASSWORD=secret  # hardcoded password
USER root  # runs as root
```

**Security best practices:**
```dockerfile
# Pin a specific version
FROM ubuntu:20.04

# Pin package versions
RUN apt-get update && apt-get install -y curl=7.68.0-1ubuntu2.7

# Use a non-root user
RUN useradd -m appuser
USER appuser

# Minimize the image
FROM alpine:3.15

# Multi-stage build
FROM golang:1.18 AS builder
WORKDIR /app
COPY . .
RUN go build -o app

FROM alpine:3.15
COPY --from=builder /app/app /app
```

### Runtime checks

**Check container privileges:**
```bash
# Check for privileged containers
docker ps --filter "label=privileged=true"

# Check mounted host directories
docker inspect container_name | grep -A 10 Mounts

# Check container networks
docker network inspect network_name
```

**Check resource limits:**
```bash
# Check memory limits
docker stats container_name

# Check CPU limits
docker inspect container_name | grep -i cpu
```

## Kubernetes security testing

### Configuration checks

**kube-bench:**
```bash
# Run kube-bench
kube-bench run

# Check specific targets
kube-bench run --targets master,node,etcd
```

**kube-hunter:**
```bash
# Run kube-hunter
kube-hunter --remote target-ip

# Active mode
kube-hunter --active
```

### Pod security

**Check pod security policies:**
```yaml
# Insecure pod configuration
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: nginx
    securityContext:
      privileged: true  # privileged mode
      runAsUser: 0  # root user
```

**Secure configuration:**
```yaml
apiVersion: v1
kind: Pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
  containers:
  - name: app
    image: nginx
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL
        add:
        - NET_BIND_SERVICE
```

### RBAC checks

**Check role permissions:**
```bash
# List all roles
kubectl get roles --all-namespaces

# Check role bindings
kubectl get rolebindings --all-namespaces

# Check cluster roles
kubectl get clusterroles

# Check user permissions
kubectl auth can-i --list --as=system:serviceaccount:default:sa-name
```

**Common issues:**
- Excessive permissions
- Unused roles
- Unused service accounts

### Network policies

**Check network policies:**
```bash
# List all network policies
kubectl get networkpolicies --all-namespaces

# Inspect a network policy
kubectl describe networkpolicy policy-name -n namespace
```

**Network policy example:**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

## Tool usage

### Falco

**Runtime security monitoring:**
```bash
# Install Falco
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco

# Check rules
falco -r /etc/falco/rules.d/
```

### Aqua Security

```bash
# Scan an image
aqua image scan nginx:latest

# Scan a Kubernetes cluster
aqua k8s scan
```

### Snyk

```bash
# Scan a Dockerfile
snyk test --docker nginx:latest

# Scan Kubernetes configs
snyk iac test k8s/
```

## Testing checklist

### Image security
- [ ] Scan base-image vulnerabilities
- [ ] Scan dependency vulnerabilities
- [ ] Check Dockerfile configuration
- [ ] Check for sensitive-info leaks

### Runtime security
- [ ] Check container privileges
- [ ] Check resource limits
- [ ] Check network isolation
- [ ] Check filesystem mounts

### Orchestration security
- [ ] Check Kubernetes configuration
- [ ] Check RBAC configuration
- [ ] Check network policies
- [ ] Check pod security policies

## Common security issues

### 1. Image vulnerabilities

**Problem:**
- Base image contains vulnerabilities
- Dependencies contain vulnerabilities
- Not updated in time

**Fix:**
- Scan images regularly
- Update base images promptly
- Use minimal images

### 2. Excessive privileges

**Problem:**
- Containers run as root
- Privileged mode
- Sensitive directories mounted

**Fix:**
- Use non-root users
- Disable privileged mode
- Restrict filesystem access

### 3. Misconfiguration

**Problem:**
- Insecure default configs
- Missing network policies
- Wrong RBAC config

**Fix:**
- Follow security best practices
- Implement network policies
- Configure RBAC correctly

### 4. Sensitive-information leakage

**Problem:**
- Secrets baked into images
- Exposed environment variables
- Leaked config files

**Fix:**
- Use secret management
- Avoid hardcoding
- Use Secret objects

## Best practices

### 1. Image security

- Use official base images
- Update images regularly
- Scan for vulnerabilities
- Minimize image size

### 2. Runtime security

- Use non-root users
- Restrict container privileges
- Enforce resource limits
- Enable security contexts

### 3. Orchestration security

- Configure network policies
- Implement RBAC
- Use pod security policies
- Enable audit logs

## Notes

- Test only in authorized environments
- Avoid impacting production
- Mind differences across container platforms
- Scan regularly
