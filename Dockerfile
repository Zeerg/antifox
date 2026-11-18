# syntax=docker/dockerfile:1
#
# Runtime image (no in-image compilation): installs the usual tools and drops in
# a PRE-BUILT Linux single binary. The binary is cross-compiled by CI's binaries
# job (pure Go, no QEMU) and placed in the build context at
# dist/<TARGETARCH>/antifox. For multi-arch builds, arm64 only has to emulate the
# apt layers, not the Next/Go builds — much faster.
#
# To build this image locally, produce the binary first:
#   cd web && npm run build:static && cd ..
#   cp -r web/out server/webui/dist
#   CGO_ENABLED=0 GOARCH=amd64 go build -tags embedui -o dist/amd64/antifox ./cmd/antifox
#   docker build -t antifox:local .
FROM python:3.12-slim-bookworm
ARG TARGETARCH
# Usual tools: ripgrep / curl / vim, plus a set of standard recon utilities
# (add/remove as needed). Node 20.x comes from NodeSource: bookworm's apt nodejs
# is 18, and Playwright requires >= 20.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates ripgrep curl wget vim git jq unzip \
      dnsutils iputils-ping netcat-openbsd whois nmap \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*
# Preinstall Playwright MCP/CLI + Chromium so the browser MCP works out of the
# box in the container. Note: the previous layer removed the apt lists, and
# `--with-deps` needs apt to install Chromium's system dependencies, so this
# layer rebuilds them with apt-get update first — otherwise `playwright install`
# fails with exit 100.
RUN apt-get update \
    && npm install -g @playwright/mcp@latest @playwright/cli@latest playwright@latest \
    && playwright-cli --help \
    && playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*
# Report generation depends on python-docx (invoked by the Go side as a
# subprocess via report_builder.py when rendering .docx)
RUN pip install --no-cache-dir python-docx
WORKDIR /app
# Prebuilt binary for the target arch (dist/amd64/antifox or dist/arm64/antifox)
COPY dist/${TARGETARCH}/antifox /app/antifox
RUN chmod +x /app/antifox
COPY skills/ /app/skills/
# data/ (SQLite + jwt.key) is the persistence point
VOLUME ["/app/data"]
EXPOSE 8787
ENTRYPOINT ["/app/antifox"]
CMD ["-addr", ":8787", "-proxy", "127.0.0.1:8788"]
