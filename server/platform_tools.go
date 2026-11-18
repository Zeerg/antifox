package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"antifox/db"
	actool "antifox/engine/tool"
)

// Platform-operation tools (for the built-in Auto agent): create/edit skills,
// custom tools, and MCPs. All host tools — seeded into the tools table, bound to
// auto by default, injected via hostTools. Reuses existing db/filesystem logic.

func (s *Server) platformTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolCreateSkill(),
		s.toolUpdateSkillFile(),
		s.toolCreateCustomTool(),
		s.toolUpdateCustomTool(),
		s.toolCreateMCP(),
		s.toolUpdateMCP(),
	}
}

// platformToolKeys are the tool keys the Auto agent gets bound by default.
var platformToolKeys = []string{
	"create_skill", "update_skill_file",
	"create_custom_tool", "update_custom_tool",
	"create_mcp", "update_mcp",
}

// ---- skills ----

func (s *Server) toolCreateSkill() actool.CoreTool {
	return wrTool("create_skill",
		"Create a new skill (writes SKILL.md, agentskills.io format). name is lowercase letters/digits/hyphens.",
		objSchema(map[string]any{
			"name":         strParam("skill name (lowercase start, letters/digits/hyphens)"),
			"description":  strParam("skill description (required — what it does / when to use it)"),
			"instructions": strParam("Markdown body content (optional)"),
		}, "name", "description"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct{ Name, Description, Instructions string }
			_ = json.Unmarshal(in, &a)
			if !validSkillName(a.Name) {
				return actool.Errorf("invalid skill name (lowercase start, letters/digits/hyphens only, ≤64)"), nil
			}
			if strings.TrimSpace(a.Description) == "" {
				return actool.Errorf("description is required"), nil
			}
			path := filepath.Join(s.skillDir, a.Name)
			if _, err := os.Stat(path); err == nil {
				return actool.Errorf("skill already exists: " + a.Name), nil
			}
			if err := os.MkdirAll(path, 0o755); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			var b strings.Builder
			b.WriteString("---\n")
			fmt.Fprintf(&b, "name: %s\n", a.Name)
			fmt.Fprintf(&b, "description: %s\n", a.Description)
			b.WriteString("---\n")
			if strings.TrimSpace(a.Instructions) != "" {
				b.WriteString(a.Instructions)
			} else {
				fmt.Fprintf(&b, "## %s\n\n1. \n2. \n3. \n", a.Name)
			}
			if err := os.WriteFile(filepath.Join(path, "SKILL.md"), []byte(b.String()), 0o644); err != nil {
				_ = os.RemoveAll(path)
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text("skill created: " + a.Name), nil
		})
}

func (s *Server) toolUpdateSkillFile() actool.CoreTool {
	return wrTool("update_skill_file",
		"Write/overwrite one file inside a skill (default SKILL.md). Use it to modify skill content or add scripts/references.",
		objSchema(map[string]any{
			"name":    strParam("skill name"),
			"file":    strParam("relative path (optional, default SKILL.md, e.g. scripts/run.py)"),
			"content": strParam("complete file content"),
		}, "name", "content"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct{ Name, File, Content string }
			_ = json.Unmarshal(in, &a)
			if !validSkillName(a.Name) {
				return actool.Errorf("invalid skill name"), nil
			}
			skillPath := filepath.Join(s.skillDir, a.Name)
			if _, err := os.Stat(skillPath); os.IsNotExist(err) {
				return actool.Errorf("skill does not exist: " + a.Name), nil
			}
			rel := strings.TrimSpace(a.File)
			if rel == "" {
				rel = "SKILL.md"
			}
			clean, msg := skillRelPath(rel)
			if msg != "" {
				return actool.Errorf("invalid path: " + msg), nil
			}
			full := filepath.Join(skillPath, clean)
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if err := os.WriteFile(full, []byte(a.Content), 0o644); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text("skill file written: " + a.Name + "/" + clean), nil
		})
}

// ---- custom tools ----

type customToolToolInput struct {
	Key         string          `json:"key"`
	Description string          `json:"description"`
	Kind        string          `json:"kind"`
	Exec        json.RawMessage `json:"exec"`
	Schema      json.RawMessage `json:"schema"`
	Agents      []string        `json:"agents"`
	Deferred    bool            `json:"deferred"`
	Enabled     *bool           `json:"enabled"`
}

func customToolSchema(keyDesc string) map[string]any {
	return objSchema(map[string]any{
		"key":         strParam(keyDesc),
		"description": strParam("description shown to the model"),
		"kind":        strParam("shell | command | script (Python only) | http. shell = bash environment declaration (only tells the model the tool is callable directly in bash — no exec/schema needed); the other three require exec"),
		"exec":        map[string]any{"type": "object", "description": "exec spec (not needed for shell): command→{command}; script→{code}; http→{method,url,headers,body,proxy,use_recording_proxy}"},
		"schema":      map[string]any{"type": "object", "description": "args JSON-Schema (shell/command/script may leave empty; http requires one with properties)"},
		"agents":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "bound agent keys (optional)"},
		"deferred":    map[string]any{"type": "boolean", "description": "defer loading (no effect on shell; only for rarely used command/script/http tools)"},
		"enabled":     map[string]any{"type": "boolean", "description": "enabled (default true)"},
	}, "key", "kind")
}

func toDBTool(a customToolToolInput) *db.Tool {
	enabled := true
	if a.Enabled != nil {
		enabled = *a.Enabled
	}
	return &db.Tool{
		Key: a.Key, Description: a.Description, Schema: a.Schema, Agents: a.Agents,
		Enabled: enabled, Kind: a.Kind, Exec: a.Exec, Deferred: a.Deferred,
	}
}

func (s *Server) toolCreateCustomTool() actool.CoreTool {
	return wrTool("create_custom_tool", "Create a custom tool (shell/command/script/http). shell = bash environment declaration — needs only key+description+agents, no exec/schema.",
		customToolSchema("tool key (lowercase start, letters/digits/underscores)"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a customToolToolInput
			_ = json.Unmarshal(in, &a)
			a.Key = strings.TrimSpace(a.Key)
			if !reToolKey.MatchString(a.Key) {
				return actool.Errorf("key must start lowercase and contain only lowercase letters/digits/underscores"), nil
			}
			if a.Kind != "shell" && a.Kind != "command" && a.Kind != "script" && a.Kind != "http" {
				return actool.Errorf("kind must be shell / command / script / http"), nil
			}
			// Host command-execution kinds (command/script/shell) are admin-only,
			// consistent with the HTTP layer: agents in non-admin sessions must not
			// create tools that execute commands on the host.
			if hostExecToolKind(a.Kind) && !ctxIsAdmin(ctx) {
				return actool.Errorf("only admins can create command/script/shell custom tools (host command execution)"), nil
			}
			if a.Kind == "http" && !hasSchemaProps(a.Schema) {
				return actool.Errorf("http tools must provide an args JSON Schema (must not be empty)"), nil
			}
			if exist, _ := s.m.pg.GetTool(a.Key); exist != nil {
				return actool.Errorf("key already exists: " + a.Key), nil
			}
			if err := s.m.pg.CreateCustomTool(toDBTool(a)); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text("custom tool created: " + a.Key), nil
		})
}

func (s *Server) toolUpdateCustomTool() actool.CoreTool {
	return wrTool("update_custom_tool", "Modify an existing custom tool (by key).",
		customToolSchema("custom tool key to modify"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a customToolToolInput
			_ = json.Unmarshal(in, &a)
			existing, _ := s.m.pg.GetTool(a.Key)
			if existing == nil || existing.System {
				return actool.Errorf("can only modify custom tools: " + a.Key), nil
			}
			if a.Kind != "shell" && a.Kind != "command" && a.Kind != "script" && a.Kind != "http" {
				return actool.Errorf("kind must be shell / command / script / http"), nil
			}
			// Admin-only if either old or new kind is a host command-execution kind (prevents bypass by changing an http tool into a command tool).
			if (hostExecToolKind(a.Kind) || hostExecToolKind(existing.Kind)) && !ctxIsAdmin(ctx) {
				return actool.Errorf("only admins can change tools to/from the command/script/shell kinds (host command execution)"), nil
			}
			if a.Kind == "http" && !hasSchemaProps(a.Schema) {
				return actool.Errorf("http tools must provide an args JSON Schema (must not be empty)"), nil
			}
			if err := s.m.pg.UpdateCustomTool(toDBTool(a)); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text("custom tool updated: " + a.Key), nil
		})
}

// ---- MCP ----

type mcpToolInput struct {
	ID        int64           `json:"id"`
	Name      string          `json:"name"`
	Transport string          `json:"transport"`
	Command   string          `json:"command"`
	Args      json.RawMessage `json:"args"`
	Env       json.RawMessage `json:"env"`
	URL       string          `json:"url"`
	Enabled   *bool           `json:"enabled"`
}

func mcpSchema(withID bool) map[string]any {
	props := map[string]any{
		"name":      strParam("MCP server name"),
		"transport": strParam("stdio | http / sse"),
		"command":   strParam("stdio launch command (e.g. npx)"),
		"args":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "command args array"},
		"env":       map[string]any{"type": "object", "description": "env vars {KEY:VALUE}"},
		"url":       strParam("http/sse URL"),
		"enabled":   map[string]any{"type": "boolean", "description": "enabled (default true)"},
	}
	required := []string{"name", "transport"}
	if withID {
		props["id"] = map[string]any{"type": "integer", "description": "id of the MCP server to modify"}
		required = []string{"id", "name", "transport"}
	}
	return objSchema(props, required...)
}

func (a mcpToolInput) toDB() *db.MCPServer {
	enabled := true
	if a.Enabled != nil {
		enabled = *a.Enabled
	}
	return &db.MCPServer{
		ID: a.ID, Name: a.Name, Transport: a.Transport, Command: a.Command,
		Args: a.Args, Env: a.Env, URL: a.URL, Enabled: enabled,
	}
}

func (s *Server) toolCreateMCP() actool.CoreTool {
	return wrTool("create_mcp", "Create an MCP server (stdio/http). After creation its tools must be granted per-agent visibility.",
		mcpSchema(false),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a mcpToolInput
			_ = json.Unmarshal(in, &a)
			a.ID = 0
			if strings.TrimSpace(a.Name) == "" || strings.TrimSpace(a.Transport) == "" {
				return actool.Errorf("name / transport are required"), nil
			}
			// stdio MCP: the server launches command/args as a subprocess = host command execution — admin-only, consistent with the HTTP layer.
			if strings.EqualFold(strings.TrimSpace(a.Transport), "stdio") && !ctxIsAdmin(ctx) {
				return actool.Errorf("only admins can create stdio-type MCP servers (launches a subprocess on the host)"), nil
			}
			id, err := s.m.pg.SaveMCP(a.toDB())
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(fmt.Sprintf("mcp created: id=%d name=%s", id, a.Name)), nil
		})
}

func (s *Server) toolUpdateMCP() actool.CoreTool {
	return wrTool("update_mcp", "Modify an existing MCP server (by id).",
		mcpSchema(true),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			// Consistent with the HTTP layer: modifying an existing MCP is admin-only
			// (existing config may contain credentials; a non-admin-session agent must
			// not redirect them by changing the address/command). Agent runs triggered
			// by the scheduler or normal sessions are admin=false.
			if !ctxIsAdmin(ctx) {
				return actool.Errorf("only admins can modify existing MCP configs"), nil
			}
			var a mcpToolInput
			_ = json.Unmarshal(in, &a)
			if a.ID == 0 {
				return actool.Errorf("id is required"), nil
			}
			// Read the existing MCP to fill connection fields missing from the input
			// (name/transport/command/args/url) — otherwise partial edits blank them
			// and SaveMCP misreads it as an "endpoint change", wiping stored
			// credentials (env/headers).
			var cur *db.MCPServer
			if list, err := s.m.pg.ListMCP(); err == nil {
				for _, m := range list {
					if m.ID == a.ID {
						cur = m
						break
					}
				}
			}
			if cur == nil {
				return actool.Errorf(fmt.Sprintf("MCP does not exist: id=%d", a.ID)), nil
			}
			d := a.toDB()
			if strings.TrimSpace(d.Name) == "" {
				d.Name = cur.Name
			}
			if strings.TrimSpace(d.Transport) == "" {
				d.Transport = cur.Transport
			}
			if strings.TrimSpace(d.Command) == "" {
				d.Command = cur.Command
			}
			if len(d.Args) == 0 {
				d.Args = cur.Args
			}
			if strings.TrimSpace(d.URL) == "" {
				d.URL = cur.URL
			}
			// mcpToolInput has no description/timeout fields → existing values are always preserved (never blanked/zeroed).
			d.Description = cur.Description
			d.TimeoutSeconds = cur.TimeoutSeconds
			if _, err := s.m.pg.SaveMCP(d); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(fmt.Sprintf("mcp updated: id=%d", a.ID)), nil
		})
}
