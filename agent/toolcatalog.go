package agent

import (
	"context"
	"encoding/json"

	actool "antifox/engine/tool"
)

// This file turns "built-in tools" from pure code into an enumerable, DB-overridable
// catalog:
//   - BuiltinToolSeeds(): expands the three execution agents' built-in toolsets into
//     seed records (key + description + param schema + default-bound agents) for the
//     server to idempotently seed into the tools table at startup.
//   - ToolResolve hook: at runtime, applies each tools row to the assembled tools
//     ("filter by agent + override description/schema + inject param defaults").
//     key/handler stay at the code layer; the DB only changes "prose and defaults".
// The handler (Call behavior) always comes from code — the DB can't change it,
// only the description and default inputs the model sees.

// ToolSeed is a seedable snapshot of a built-in tool: Key is CoreTool.Name()
// (hard-bound to the handler, read-only in the UI); Desc/Schema come from the code
// tool definition; Agents is which agents code binds it to by default.
type ToolSeed struct {
	Key    string         // = CoreTool.Name(), primary key, immutable
	Desc   string         // top-level description (UI-overridable)
	Schema map[string]any // parameter JSON-Schema (structure read-only; description/default editable in UI)
	Agents []string       // default-bound agent keys (worker/planner/mainagent)
}

// builtinToolsByAgent builds each execution agent's domain toolset with a
// "read-only shell" ToolSet (nil stores). Tool constructors only put closures into
// Spec and never dereference the stores at construction, so nil is safe — these
// tools are used here only to read Name()/Description()/InputSchema(), never Call.
//
// Deliberately EXCLUDES the SDK generic tools actool.DefaultTools() (Read/Write/
// Edit/MultiEdit/LS/Glob/Grep/Bash): every agent always has them — there's no
// "which agent binds it" choice — and their docs mostly live in Prompt() (this
// table only covers Description(), which would be a misleading half-override).
// Not seeded → no DB row → ToolResolve passes them through untouched, same
// behavior as before. Only antifox's own domain tools enter the managed table.
func builtinToolsByAgent() map[string][]actool.CoreTool {
	ts := NewToolSet(nil, "")
	return map[string][]actool.CoreTool{
		"mainagent": ts.MainAgentTools(),
		"planner":   ts.PlannerTools(),
		"worker":    ts.WorkerTools(),
		// auto binds finding-reporting + asset-management tools + knowledge search by
		// default; other domain tools can be enabled in the UI as needed.
		// New DBs are seeded here; old DBs are migrated by seedAutoDefaultBindings.
		"auto": {ts.addFinding(), ts.insertAssets(), ts.addCompanyScope(), ts.listAssets(), ts.listCompanies(), ts.searchKnowledge(), ts.listKnowledgeCategories()},
		// pentest (standalone pentest agent) binds by default: list assets / insert
		// assets / report finding / list findings / list companies / knowledge search.
		// New DBs are seeded here; old DBs are migrated by seedPentestDefaultBindings.
		"pentest": {ts.listAssets(), ts.insertAssets(), ts.addFinding(), ts.listFindings(), ts.listCompanies(), ts.searchKnowledge(), ts.listKnowledgeCategories()},
	}
}

// BuiltinToolSeeds dedup-merges the three agents' built-in toolsets into a seed
// list: same-named tools (e.g. list_assets on all three) collapse to one row, Agents
// is the union. Order is stable (mainagent→planner→worker).
func BuiltinToolSeeds() []ToolSeed {
	byAgent := builtinToolsByAgent()
	order := []string{"mainagent", "planner", "worker", "auto", "pentest"}

	type acc struct {
		tool   actool.CoreTool
		agents []string
	}
	m := map[string]*acc{}
	var keys []string
	for _, ak := range order {
		for _, t := range byAgent[ak] {
			a, ok := m[t.Name()]
			if !ok {
				a = &acc{tool: t}
				m[t.Name()] = a
				keys = append(keys, t.Name())
			}
			a.agents = append(a.agents, ak)
		}
	}

	out := make([]ToolSeed, 0, len(keys))
	for _, k := range keys {
		a := m[k]
		out = append(out, ToolSeed{
			Key:    k,
			Desc:   a.tool.Description(),
			Schema: a.tool.InputSchema(),
			Agents: a.agents,
		})
	}
	return out
}

// ToolResolve, if set, post-processes an agent's fully-assembled tool list against
// the DB tools table: it drops tools not bound to this agent (or globally disabled)
// and wraps the rest so the model sees the DB-overridden description/schema and
// default inputs get injected. Tools with no matching DB row (MCP/skill/host tools like
// traffic) pass through untouched. nil = tools unchanged. Wired in server/assembly.go.
var ToolResolve func(ctx context.Context, agentKey string, tools []actool.CoreTool) []actool.CoreTool

// DecorateTool wraps t so Description()/InputSchema() report the DB overrides and
// Call() injects scalar parameter defaults (from schema's "default" props) whenever
// the model omitted them. Name/Prompt/permission/scheduler flags delegate to t, so
// the tool's identity and handler are unchanged. Empty desc/schema fall back to t's.
func DecorateTool(t actool.CoreTool, desc string, schema map[string]any) actool.CoreTool {
	if desc == "" {
		desc = t.Description()
	}
	if len(schema) == 0 {
		schema = t.InputSchema()
	}
	return &overriddenTool{CoreTool: t, desc: desc, schema: schema}
}

// overriddenTool is a CoreTool decorator: it embeds the original (so all behavioral
// methods — Prompt/IsReadOnly/IsConcurrencySafe/CheckPermissions/Name — delegate)
// and overrides only the model-facing description/schema plus default injection.
type overriddenTool struct {
	actool.CoreTool
	desc   string
	schema map[string]any
}

func (o *overriddenTool) Description() string         { return o.desc }
func (o *overriddenTool) InputSchema() map[string]any { return o.schema }

func (o *overriddenTool) Call(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	return o.CoreTool.Call(ctx, injectDefaults(in, o.schema), tc)
}

// injectDefaults fills scalar parameter defaults declared in the (possibly edited)
// schema into the input JSON whenever the model omitted the field or left it empty/
// null. Structure (names/types/required) is untouched — only default values are merged in.
func injectDefaults(in json.RawMessage, schema map[string]any) json.RawMessage {
	defs := scalarDefaults(schema)
	if len(defs) == 0 {
		return in
	}
	m := map[string]json.RawMessage{}
	if len(in) > 0 {
		if err := json.Unmarshal(in, &m); err != nil {
			return in // non-object input: don't touch it
		}
	}
	changed := false
	for k, dv := range defs {
		if cur, ok := m[k]; !ok || isEmptyJSON(cur) {
			m[k] = dv
			changed = true
		}
	}
	if !changed {
		return in
	}
	b, err := json.Marshal(m)
	if err != nil {
		return in
	}
	return b
}

// scalarDefaults extracts properties[k]["default"] for scalar params (string/
// integer/number/boolean). Array/object defaults are skipped: merging them is
// ambiguous and not worth the surprise.
func scalarDefaults(schema map[string]any) map[string]json.RawMessage {
	props, _ := schema["properties"].(map[string]any)
	if len(props) == 0 {
		return nil
	}
	out := map[string]json.RawMessage{}
	for name, raw := range props {
		p, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		dv, ok := p["default"]
		if !ok || dv == nil {
			continue
		}
		switch p["type"] {
		case "string", "integer", "number", "boolean":
			if b, err := json.Marshal(dv); err == nil {
				out[name] = b
			}
		}
	}
	return out
}

func isEmptyJSON(raw json.RawMessage) bool {
	s := string(raw)
	return s == "null" || s == `""`
}
