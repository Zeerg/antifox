package server

import (
	"net/http"
	"strings"

	"antifox/db"
)

// RBAC permission enforcement: route → required permission mapping.
// Safety valve: unmapped routes are allowed through (not forced to 403 — a missed
// mapping must not break the platform); admin holds all permissions and is never
// blocked. Switch: settings key rbac.enforce (default true).

// isAdmin reports whether the current request comes from the built-in admin
// role. Used to further tighten high-risk "executes commands on the host"
// operations (stdio MCP, command/script/shell custom tools) — equivalent to host
// command execution, admin-only, never delegated to operator via tool:write /
// mcp:write. No auth profile → treated as non-admin (fail-closed).
func isAdmin(r *http.Request) bool {
	acc := CurrentAccess(r)
	if acc == nil {
		return false
	}
	for _, role := range acc.Roles {
		if role.ID == db.RBACRoleAdmin {
			return true
		}
	}
	return false
}

// hostExecToolKind reports whether a custom-tool kind executes commands/scripts on the host.
func hostExecToolKind(kind string) bool {
	switch kind {
	case "command", "script", "shell":
		return true
	}
	return false
}

// crudPerm maps HTTP method to read/write/delete permission.
func crudPerm(method, module string) string {
	switch method {
	case http.MethodGet, http.MethodHead:
		return module + ":read"
	case http.MethodDelete:
		// Some modules have no ":delete" permission in the catalog (llm/agent/mcp/
		// tool/intercept) — for those, delete is gated by ":write". Without this
		// fallback even admin (whose perm set == the catalog) hits a nonexistent
		// "<module>:delete" and gets 403 on every delete.
		if p := module + ":delete"; db.RBACPermissions[p] != "" {
			return p
		}
		return module + ":write"
	default:
		return module + ":write"
	}
}

// permissionForRequest returns the permission a request needs; "" means unmapped (allowed through).
func permissionForRequest(method, fullPath string) string {
	p := strings.TrimPrefix(fullPath, "/api")
	switch {
	case p == "/rbac/me":
		return "auth:self"
	case strings.HasPrefix(p, "/rbac"):
		if method == http.MethodGet {
			return "rbac:read"
		}
		return "rbac:write"
	case strings.HasPrefix(p, "/audit"):
		return "log:read"
	case strings.HasPrefix(p, "/logs"):
		return "log:read"
	case p == "/stats" || strings.HasPrefix(p, "/tokens"):
		return "dashboard:read"
	case strings.HasPrefix(p, "/tasks"), p == "/active", strings.HasPrefix(p, "/exploration"),
		strings.HasPrefix(p, "/chat"), strings.HasPrefix(p, "/conversations"):
		return crudPerm(method, "task")
	case strings.HasPrefix(p, "/findings"):
		return crudPerm(method, "finding")
	case strings.HasPrefix(p, "/traffic"):
		return "traffic:read"
	case strings.HasPrefix(p, "/assets"), strings.HasPrefix(p, "/companies"), strings.HasPrefix(p, "/sync"):
		return crudPerm(method, "asset")
	case strings.HasPrefix(p, "/llm"):
		return crudPerm(method, "llm")
	case strings.HasPrefix(p, "/agents"), strings.HasPrefix(p, "/triggers"), strings.HasPrefix(p, "/visibility"):
		return crudPerm(method, "agent")
	case strings.HasPrefix(p, "/mcp"):
		return crudPerm(method, "mcp")
	case strings.HasPrefix(p, "/skills"):
		return crudPerm(method, "skill")
	case strings.HasPrefix(p, "/tools"):
		return crudPerm(method, "tool")
	case strings.HasPrefix(p, "/intercept"):
		return crudPerm(method, "intercept")
	case strings.HasPrefix(p, "/knowledge"):
		// search/categories/logs are read actions even though search is POST.
		if p == "/knowledge/search" || p == "/knowledge/categories" || p == "/knowledge/logs" {
			return "knowledge:read"
		}
		return crudPerm(method, "knowledge")
	case strings.HasPrefix(p, "/settings"):
		return crudPerm(method, "config")
	case strings.HasPrefix(p, "/update"):
		// One-click update lives under system config: check/progress = config:read;
		// apply/rollback (POST) = config:write (admin-only — the dangerous download-
		// swap/rollback can only be triggered by admin).
		return crudPerm(method, "config")
	case strings.HasPrefix(p, "/report"):
		// Covers /report, /reports, /report/generate, /report-settings,
		// /report-templates, /report-assets (all start with /report).
		// GET=read (view/download/status), POST/PUT=write (generate reports/manage
		// template settings), DELETE=delete (reports/templates). The report module
		// has the full read/write/delete set.
		return crudPerm(method, "report")
	default:
		return "" // unmapped → allowed through
	}
}
