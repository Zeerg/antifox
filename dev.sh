#!/usr/bin/env bash
# Dev mode: run the backend (:8787) + traffic proxy (:8788) and the frontend
# next dev server (:5173) together. The frontend proxies /api to the backend;
# Ctrl-C stops everything.
#
# For the single embedded-binary mode see the README "single binary" section —
# this script is not used for that.
set -euo pipefail
cd "$(dirname "$0")"

# On exit, kill every child in this process group (backend + frontend).
cleanup() { kill 0 2>/dev/null || true; }
trap cleanup EXIT INT TERM

# Backend (plain go run, frontend not embedded); the number of concurrent work
# agents is configured on the system settings page.
go run ./cmd/antifox -addr :8787 -proxy 127.0.0.1:8788 &

# Frontend hot reload (Next dev server, /api proxies to :8787).
( cd web && npm run dev ) &

echo "[dev] backend :8787 / proxy :8788 / frontend http://localhost:5173  (Ctrl-C to exit)"
wait
