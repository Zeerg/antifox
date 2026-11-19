// Package db is the PostgreSQL data source for AntiFox (replacing the old single-file SQLite graph).
// It opens the connection, applies the schema, and seeds built-in agents and the variable catalog.
package db

import (
	"database/sql"
	_ "embed"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"antifox/config"
	_ "github.com/jackc/pgx/v5/stdlib" // pgx database/sql driver ("pgx")
)

//go:embed schema.sql
var schemaSQL string

// Connection-pool cap (see Open). Conservative: enough for a single-instance deployment while leaving headroom for other PG clients.
const (
	maxOpenConns    = 25
	maxIdleConns    = 10
	connMaxLifetime = 55 * time.Minute
	connMaxIdleTime = 5 * time.Minute
)

// DSN resolves the PostgreSQL connection string and reports where it came from.
// Precedence: env ANTIFOX_PG_DSN > config file (config.json). There is no
// built-in default — it errors if neither source is configured.
func DSN() (dsn, source string, err error) {
	return config.PostgresDSN()
}

// DB wraps the shared *sql.DB. PG handles its own connection pool + concurrency
// (MVCC), so unlike the old SQLite store there is no process-wide write mutex.
type DB struct{ *sql.DB }

// ensureDatabase connects to the postgres system database and creates the target
// database if it does not exist. dsn must be a postgres:// URL.
func ensureDatabase(dsn string) error {
	u, err := url.Parse(dsn)
	if err != nil {
		return nil // unparseable DSN — let the normal Open fail with a clear error
	}
	dbName := strings.TrimPrefix(u.Path, "/")
	if dbName == "" || dbName == "postgres" {
		return nil
	}
	// connect to the postgres maintenance database instead
	adminDSN := *u
	adminDSN.Path = "/postgres"
	admin, err := sql.Open("pgx", adminDSN.String())
	if err != nil {
		return nil // best-effort; let Open surface the real error
	}
	defer admin.Close()
	if err := admin.Ping(); err != nil {
		return nil
	}
	var exists bool
	_ = admin.QueryRow(`SELECT true FROM pg_database WHERE datname=$1`, dbName).Scan(&exists)
	if !exists {
		if _, err := admin.Exec(`CREATE DATABASE "` + dbName + `"`); err != nil {
			return fmt.Errorf("create database %q: %w", dbName, err)
		}
	}
	return nil
}

// Open connects, applies the schema (idempotent), and seeds builtin rows.
func Open(dsn string) (*DB, error) {
	if err := ensureDatabase(dsn); err != nil {
		return nil, err
	}
	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	if err := sqlDB.Ping(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("ping postgres (%s): %w", config.Redact(dsn), err)
	}
	// Connection-pool cap: limits concurrent database connections so a request storm
	// can't exhaust them and fail queries. PG defaults to max_connections=100; leave
	// ample room for other clients (psql/pg_dump/backups); idle connections are
	// recycled instead of lingering, and a max connection lifetime prevents
	// half-dead network connections from piling up.
	sqlDB.SetMaxOpenConns(maxOpenConns)
	sqlDB.SetMaxIdleConns(maxIdleConns)
	sqlDB.SetConnMaxLifetime(connMaxLifetime)
	sqlDB.SetConnMaxIdleTime(connMaxIdleTime)
	// Serialize schema migration + seeding across concurrent openers (e.g. parallel
	// test packages) using a session-level advisory lock. The lock is released
	// automatically when the connection is returned to the pool or closed.
	if _, err := sqlDB.Exec(`SELECT pg_advisory_lock(7337741001)`); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("advisory lock: %w", err)
	}
	// pgx runs multi-statement Exec via the simple protocol when there are no args.
	if _, err := sqlDB.Exec(schemaSQL); err != nil {
		sqlDB.Exec(`SELECT pg_advisory_unlock(7337741001)`) //nolint:errcheck
		sqlDB.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	d := &DB{sqlDB}
	if err := d.seedBuiltins(); err != nil {
		sqlDB.Exec(`SELECT pg_advisory_unlock(7337741001)`) //nolint:errcheck
		sqlDB.Close()
		return nil, fmt.Errorf("seed builtins: %w", err)
	}
	if _, err := sqlDB.Exec(`SELECT pg_advisory_unlock(7337741001)`); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("advisory unlock: %w", err)
	}
	return d, nil
}

// builtinAgent describes one of the fixed agents and its prompt-variable catalog.
type builtinAgent struct {
	key, name, role, desc string
	vars                  []promptVar
	interactiveShell      bool // default interactive-shell flag at row creation; ON CONFLICT must not override the user's later manual toggle
	runSeconds            *int // per-run wall-clock cap (seconds) at row creation; nil = table default (600), 0 = unlimited
}

type promptVar struct{ name, desc, example, source string }

// intp returns a pointer to v, used to set builtinAgent optional fields (like runSeconds) explicitly.
func intp(v int) *int { return &v }

// builtinAgents mirrors docs §5(a). Built-in tools are not stored; only agents + the variable catalog are seeded here.
// Note: planner/worker/mainagent/auto get their interactive-shell default set to
// true uniformly by the interactive_shell_default_v1 block below (respecting later
// toggles); the interactiveShell field here is only for new agents that must
// default on at row creation.
var builtinAgents = []builtinAgent{
	{"goals", "Goal Decomposition", "goals", "Breaks a pentest task goal into several independent, verifiable sub-goals.", []promptVar{
		{"EngagementDescription", "task description (target/background)", "test the example.com site", "exploration"},
		{"Now", "current server time (RFC3339)", "2026-06-25T00:00:00Z", "runtime"},
	}, false, nil},
	{"planner", "Planner", "planner", "Reads the situation, judges goals, and adds exploration intents only when a genuinely uncovered new direction exists (one planning loop per task).", []promptVar{
		{"Goal", "overall task goal", "gain admin privileges on example.com", "exploration"},
		{"AssetSummary", "asset count/type distribution summary (optional)", "domain:3 ip:5 site:2", "distilled"},
	}, false, nil},
	{"mainagent", "Main", "main", "Human-machine interface: watches progress, turns human intent into hints or high-priority intents.", []promptVar{
		{"Goal", "current task goal", "gain admin privileges on example.com", "exploration"},
		{"AssetSummary", "opening situation summary (optional)", "domain:3 ip:5", "distilled"},
		{"FindingsSummary", "confirmed-findings summary (optional)", "high:1 medium:2", "distilled"},
	}, false, nil},
	{"worker", "Worker", "worker", "Claims one intent, executes it, writes discovered facts/vulns back to the knowledge graph, then stops.", []promptVar{
		{"ProxyAddr", "recording proxy address (drives the if/two-variant copy)", "127.0.0.1:8080", "runtime"},
		{"WorkerName", "worker self-identifier (optional)", "worker-1", "runtime"},
	}, false, intp(1200)}, // worker per-round wall-clock default 1200s (hard targets/slow networks often exceed 600s; ref AntiFox 0.3.3)
	// Auto: built-in "platform operations" agent. Not part of the pentest orchestration loop; driven from the chat page, operates the platform via tools.
	{"auto", "Auto", "assistant", "Platform-operations assistant: manages tasks (create/view/pause/hint) and assets via tools, and can create/modify skills, custom tools, and MCP servers.", nil, false, nil},
	// pentest: built-in "standalone pentest" agent. Driven from the chat page; walks the full chain from recon to wrap-up alone — plans, executes, and verifies by itself. Interactive shell on by default.
	{"pentest", "Pentest", "assistant", "Standalone pentest agent: single-handedly walks the whole chain recon → attack surface → deep exploitation → verification → wrap-up; plans, executes, and adversarially verifies on its own.", nil, true, intp(0)},
}

// seedBuiltins inserts the fixed built-in agents and their variable catalog (idempotent).
func (d *DB) seedBuiltins() error {
	for _, a := range builtinAgents {
		var agentID int64
		err := d.QueryRow(`
INSERT INTO agents(key, name, description, role, builtin, enabled, interactive_shell, run_seconds)
VALUES ($1, $2, NULLIF($3,''), $4, true, true, $5, COALESCE($6, 600))
ON CONFLICT (key) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description
RETURNING id`, a.key, a.name, a.desc, a.role, a.interactiveShell, a.runSeconds).Scan(&agentID)
		if err != nil {
			return fmt.Errorf("agent %s: %w", a.key, err)
		}
		for _, v := range a.vars {
			if _, err := d.Exec(`
INSERT INTO agent_prompt_vars(agent_id, var_name, description, example, source)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (agent_id, var_name) DO UPDATE
  SET description = EXCLUDED.description, example = EXCLUDED.example, source = EXCLUDED.source`,
				agentID, v.name, v.desc, v.example, v.source); err != nil {
				return fmt.Errorf("agent %s var %s: %w", a.key, v.name, err)
			}
		}
	}
	// Drop catalog entries for variables that were renamed, so the white-list no
	// longer advertises a name templates can't resolve (EngagementTitle→Description).
	if _, err := d.Exec(`DELETE FROM agent_prompt_vars WHERE var_name IN ('EngagementTitle', 'CoverageGaps')`); err != nil {
		return fmt.Errorf("cleanup renamed vars: %w", err)
	}
	// Default-on interactive_shell for the runtime agents (planner/worker/mainagent/auto)
	// ONCE — respects a later user toggle-off (guarded by a settings flag). goals(one-shot
	// decomposer) stays off. Runs after the column exists (schema applied before seed).
	if v, _, _ := d.GetSetting("interactive_shell_default_v1"); v != "true" {
		if _, err := d.Exec(`UPDATE agents SET interactive_shell=true WHERE key IN ('planner','worker','mainagent','auto')`); err != nil {
			return fmt.Errorf("seed interactive_shell defaults: %w", err)
		}
		_ = d.SetSetting("interactive_shell_default_v1", "true")
	}
	// Seed built-in MCP servers — insert-if-absent so user edits survive restart.
	// browser (Playwright): headless browser automation, MITM recording proxy auto-
	// injected when traffic capture is on (server.Manager.syncBrowserMCPProxy).
	if _, err := d.Exec(`
INSERT INTO mcp_servers(name, transport, command, args, env, enabled)
VALUES ('browser', 'stdio', 'npx', $1, '{}', true)
ON CONFLICT (name) DO NOTHING`,
		`["@playwright/mcp","--headless"]`); err != nil {
		return fmt.Errorf("seed browser mcp: %w", err)
	}
	// filesystem: read/write files during pentest (payloads, output, configs).
	if _, err := d.Exec(`
INSERT INTO mcp_servers(name, transport, command, args, env, enabled, description)
VALUES ('filesystem', 'stdio', 'npx', $1, '{}', true, 'Read and write the local filesystem — store payloads, script output, discovered config files, etc. during pentesting')
ON CONFLICT (name) DO NOTHING`,
		`["@modelcontextprotocol/server-filesystem","/tmp/antifox-fs"]`); err != nil {
		return fmt.Errorf("seed filesystem mcp: %w", err)
	}
	// github: recon via GitHub API — search repos, find exposed secrets, analyze code.
	// Seeded DISABLED: it needs a real GITHUB_PERSONAL_ACCESS_TOKEN, so leaving it
	// enabled with the placeholder guarantees "connection closed" error spam on every
	// deploy. Operator enables it after setting a token on the MCP page.
	if _, err := d.Exec(`
INSERT INTO mcp_servers(name, transport, command, args, env, enabled, description)
VALUES ('github', 'stdio', 'npx', $1, $2, false, 'GitHub repository recon — search public repos for leaked credentials, keys, or sensitive config, or analyze the target organization''s open-source code (requires a GITHUB_PERSONAL_ACCESS_TOKEN on the MCP page to enable)')
ON CONFLICT (name) DO NOTHING`,
		`["@modelcontextprotocol/server-github"]`, `{"GITHUB_PERSONAL_ACCESS_TOKEN":"<your-token>"}`); err != nil {
		return fmt.Errorf("seed github mcp: %w", err)
	}
	if err := d.seedBuiltinMCPVisibility(); err != nil {
		return fmt.Errorf("seed mcp visibility: %w", err)
	}
	// NOTE: the placeholder ScopeSentry data-source MCP (empty URL + empty X-API-Key,
	// disabled) is seeded directly in schema.sql §F so a raw `psql < schema.sql` init
	// also gets it. schema.sql is Exec'd on every startup, so it stays idempotent.
	if err := d.seedBuiltinSkillVisibility(); err != nil {
		return fmt.Errorf("seed skill visibility: %w", err)
	}
	if err := d.seedDefaultInterceptRules(); err != nil {
		return fmt.Errorf("seed intercept rules: %w", err)
	}
	d.backfillSeedTextEnglish()
	d.migrateKnowledgeConfigToBuiltin()
	d.ensureKnowledgeVectorSchema() // best-effort; degrades to keyword search if pgvector absent
	return nil
}

// ensureKnowledgeVectorSchema creates the pgvector extension + knowledge_chunks
// table (the semantic layer). It is best-effort and NEVER fails boot: CREATE
// EXTENSION vector needs a superuser to have pre-installed it, so on a deployment
// where that hasn't happened the knowledge base degrades to keyword search.
// Records the outcome in the settings flag "knowledge.vector_available".
func (d *DB) ensureKnowledgeVectorSchema() {
	if _, err := d.Exec(`CREATE EXTENSION IF NOT EXISTS vector`); err != nil {
		log.Printf("[knowledge] pgvector unavailable (%v) — semantic search disabled, falling back to keyword search."+
			"a superuser must run CREATE EXTENSION vector once to enable it", err)
		_ = d.SetBool("knowledge.vector_available", false)
		return
	}
	// Embeddings use a variable-dimension vector column + per-chunk embed_model/dim;
	// retrieval filters by the current model so switching embedders doesn't mix
	// vectors (old-model rows are ignored until the index is rebuilt). Exact scan is
	// fine at this data volume.
	if _, err := d.Exec(`
CREATE TABLE IF NOT EXISTS knowledge_chunks (
    id          BIGSERIAL PRIMARY KEY,
    doc_id      BIGINT NOT NULL REFERENCES knowledge_docs(id) ON DELETE CASCADE,
    chunk_index INT NOT NULL DEFAULT 0,
    content     TEXT NOT NULL DEFAULT '',
    embedding   vector,
    embed_model TEXT NOT NULL DEFAULT '',
    embed_dim   INT NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_knowledge_chunks_doc ON knowledge_chunks(doc_id);
CREATE INDEX IF NOT EXISTS idx_knowledge_chunks_model ON knowledge_chunks(embed_model);`); err != nil {
		log.Printf("[knowledge] failed to create knowledge_chunks (%v) — semantic search disabled", err)
		_ = d.SetBool("knowledge.vector_available", false)
		return
	}
	_ = d.SetBool("knowledge.vector_available", true)
}

// builtinSkillVisibility maps a shipped skill's directory name → the built-in
// agent keys that should see it by default. The skill FILES themselves live on the
// filesystem (SkillDir, loaded by the engine at runtime); DB only carries this visibility
// binding. Skills omitted here (e.g. playwright-cli, scopesentry) ship invisible by
// default — the user turns them on per-agent when needed. scopesentry additionally
// declares `mcps: ScopeSentry`, which only takes effect once it's made visible and
// that MCP is enabled/configured.
var builtinSkillVisibility = map[string][]string{
	"api-recon": {"auto", "pentest", "worker"},
	// Pentest methodology library migrated from old AntiFox (tool-agnostic; uses
	// public CLI tools via Bash). Visible to execution agents by default
	// (worker/auto/pentest); planner/mainagent stay clean. incident-response
	// (blue-team) and security-awareness-training are intentionally not default —
	// installed, but the user enables them per agent on the Skills page.
	"api-security-testing":        {"worker", "auto", "pentest"},
	"business-logic-testing":      {"worker", "auto", "pentest"},
	"cloud-security-audit":        {"worker", "auto", "pentest"},
	"command-injection-testing":   {"worker", "auto", "pentest"},
	"container-security-testing":  {"worker", "auto", "pentest"},
	"csrf-testing":                {"worker", "auto", "pentest"},
	"deserialization-testing":     {"worker", "auto", "pentest"},
	"file-upload-testing":         {"worker", "auto", "pentest"},
	"idor-testing":                {"worker", "auto", "pentest"},
	"ldap-injection-testing":      {"worker", "auto", "pentest"},
	"mobile-app-security-testing": {"worker", "auto", "pentest"},
	"network-penetration-testing": {"worker", "auto", "pentest"},
	"secure-code-review":          {"worker", "auto", "pentest"},
	"security-automation":         {"worker", "auto", "pentest"},
	"sql-injection-testing":       {"worker", "auto", "pentest"},
	"ssrf-testing":                {"worker", "auto", "pentest"},
	"vulnerability-assessment":    {"worker", "auto", "pentest"},
	"xpath-injection-testing":     {"worker", "auto", "pentest"},
	"xss-testing":                 {"worker", "auto", "pentest"},
	"xxe-testing":                 {"worker", "auto", "pentest"},
}

// seedBuiltinSkillVisibility binds the shipped built-in skills to their default
// agents. Insert-if-absent (ON CONFLICT DO NOTHING) so a user's later toggle-off is
// never resurrected on restart — matches the browser-MCP / intercept-rule seed policy.
func (d *DB) seedBuiltinSkillVisibility() error {
	for skillName, agentKeys := range builtinSkillVisibility {
		for _, key := range agentKeys {
			if _, err := d.Exec(`
INSERT INTO agent_skill_visibility(agent_id, skill_name, enabled)
SELECT id, $2, true FROM agents WHERE key=$1
ON CONFLICT (agent_id, skill_name) DO NOTHING`, key, skillName); err != nil {
				return fmt.Errorf("skill %s → agent %s: %w", skillName, key, err)
			}
		}
	}
	return nil
}

// builtinMCPVisibility maps a shipped MCP server name → the built-in agent keys
// that should see it by default. browser/filesystem/github are useful for pentest
// agents (worker/auto/pentest); planner/mainagent stay clean.
var builtinMCPVisibility = map[string][]string{
	"browser":    {"worker", "auto", "pentest"},
	"filesystem": {"worker", "auto", "pentest"},
	"github":     {"worker", "auto", "pentest"},
}

// seedBuiltinMCPVisibility binds the shipped built-in MCP servers to their default
// agents via agent_visibility. Insert-if-absent (ON CONFLICT DO NOTHING) so a user's
// later toggle-off is never resurrected on restart.
func (d *DB) seedBuiltinMCPVisibility() error {
	for serverName, agentKeys := range builtinMCPVisibility {
		for _, key := range agentKeys {
			if _, err := d.Exec(`
INSERT INTO agent_visibility(agent_id, resource_kind, resource_id, enabled)
SELECT a.id, 'mcp', m.id, true
FROM agents a, mcp_servers m
WHERE a.key=$1 AND m.name=$2
ON CONFLICT (agent_id, resource_kind, resource_id, mcp_tool_name) DO NOTHING`, key, serverName); err != nil {
				return fmt.Errorf("mcp %s → agent %s: %w", serverName, key, err)
			}
		}
	}
	return nil
}

// interceptRuleSeed is one built-in safety intercept rule; seeds insert once and
// backfillSeedTextEnglish rewrites old-language text on already-seeded rows.
type interceptRuleSeed struct {
	name     string
	target   string // tool_name | tool_input
	typ      string // string | regex
	pattern  string
	action   string
	message  string
	priority int
}

var defaultInterceptRuleSeeds = []interceptRuleSeed{
	// ── system-destructive commands (priority 100) ──────────────────────────────
	{
		name:     "[builtin] recursive force-delete rm -rf",
		target:   "tool_input",
		typ:      "regex",
		pattern:  `(?i)\brm\b.{0,80}(?:-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*|--recursive|--no-preserve-root)`,
		action:   "deny",
		message:  "recursive force-delete is forbidden (rm -rf / rm --recursive) — it can permanently damage the system or target environment",
		priority: 100,
	},
	{
		name:     "[builtin] delete critical system directories",
		target:   "tool_input",
		typ:      "regex",
		pattern:  `\brm\b[^"'\n]{0,60}["'\s](/|/etc|/bin|/usr|/boot|/var|/lib|/sys|/proc|/dev|/sbin|/root)`,
		action:   "deny",
		message:  "deleting critical system paths is forbidden",
		priority: 100,
	},
	{
		name:     "[builtin] disk formatting mkfs",
		target:   "tool_input",
		typ:      "regex",
		pattern:  `\bmkfs\b`,
		action:   "deny",
		message:  "formatting disks (mkfs) is forbidden",
		priority: 100,
	},
	{
		name:     "[builtin] overwrite disk device with dd",
		target:   "tool_input",
		typ:      "regex",
		pattern:  `\bdd\b[^|\n]{0,100}\bof=\s*/dev/[a-zA-Z]`,
		action:   "deny",
		message:  "overwriting disk devices with dd is forbidden",
		priority: 100,
	},
	{
		name:     "[builtin] fork bomb",
		target:   "tool_input",
		typ:      "regex",
		pattern:  `:\(\)\s*\{[^}]*:\|:`,
		action:   "deny",
		message:  "fork bombs are forbidden",
		priority: 100,
	},
	{
		name:     "[builtin] shutdown / reboot",
		target:   "tool_input",
		typ:      "regex",
		pattern:  `\b(?:shutdown|reboot|halt|poweroff|init\s+[06])\b`,
		action:   "deny",
		message:  "shutdown or reboot commands are forbidden",
		priority: 100,
	},
	{
		name:     "[builtin] kill all processes",
		target:   "tool_input",
		typ:      "regex",
		pattern:  `\bkill\s+-9\s+-1\b|\bkillall\s+-9\b`,
		action:   "deny",
		message:  "kill -9 -1 or killall -9 is forbidden (kills all processes)",
		priority: 100,
	},
	{
		name:     "[builtin] disk wiping shred / wipe",
		target:   "tool_input",
		typ:      "regex",
		pattern:  `\b(?:shred|wipe)\b[^|\n]{0,80}/dev/[a-zA-Z]`,
		action:   "deny",
		message:  "running shred/wipe on disk devices is forbidden",
		priority: 100,
	},
	{
		name:     "[builtin] flush firewall rules",
		target:   "tool_input",
		typ:      "regex",
		pattern:  `\biptables\s+(?:-F|--flush)\b|\bnft\s+flush\s+ruleset\b`,
		action:   "deny",
		message:  "flushing firewall rules is forbidden (iptables -F / nft flush)",
		priority: 100,
	},
	// ── destructive database operations (priority 90) ─────────────────────────
	{
		name:     "[builtin] SQL DROP DATABASE / TABLE / SCHEMA",
		target:   "tool_input",
		typ:      "regex",
		pattern:  `(?i)\bDROP\s+(?:DATABASE|TABLE|SCHEMA|INDEX|VIEW|TABLESPACE|USER|ROLE)\b`,
		action:   "deny",
		message:  "DROP operations are forbidden — they can irreversibly destroy database objects",
		priority: 90,
	},
	{
		name:     "[builtin] SQL TRUNCATE",
		target:   "tool_input",
		typ:      "regex",
		pattern:  `(?i)\bTRUNCATE\s+(?:TABLE\s+)?\w`,
		action:   "deny",
		message:  "TRUNCATE is forbidden — it may empty all data in a table",
		priority: 90,
	},
	{
		name:     "[builtin] MongoDB drop / dropDatabase",
		target:   "tool_input",
		typ:      "regex",
		pattern:  `(?i)\.(?:dropDatabase|dropCollection|drop)\s*\(`,
		action:   "deny",
		message:  "MongoDB drop operations are forbidden",
		priority: 90,
	},
	{
		name:     "[builtin] Redis FLUSHALL / FLUSHDB",
		target:   "tool_input",
		typ:      "regex",
		pattern:  `(?i)\b(?:FLUSHALL|FLUSHDB)\b`,
		action:   "deny",
		message:  "Redis FLUSHALL / FLUSHDB is forbidden — it may wipe all cached data",
		priority: 90,
	},
	// ── destructive HTTP requests (priority 80) ──────────────────────────────
	// Three common ways an agent sends DELETE requests:
	//   1. curl -X DELETE / --request DELETE (via Bash directly or inside a script)
	//   2. Python HTTP client .delete() method
	//   3. method: 'DELETE' / method="DELETE" in JS/generic scripts
	{
		name:     "[builtin] curl / wget sending DELETE requests",
		target:   "tool_input",
		typ:      "regex",
		pattern:  `(?i)\bcurl\b[^|\n&;"]{0,300}(?:-X\s*DELETE|--request\s+DELETE|-XDELETE)|\bwget\b[^|\n&;"]{0,300}--method[=\s]+DELETE`,
		action:   "deny",
		message:  "sending HTTP DELETE requests via curl/wget is forbidden — it may delete target-system data",
		priority: 80,
	},
	{
		name:     "[builtin] Python HTTP client DELETE (requests/httpx/aiohttp)",
		target:   "tool_input",
		typ:      "regex",
		pattern:  `(?i)\b(?:requests|httpx|aiohttp|urllib\.request)\.delete\s*\(|session\.delete\s*\(|client\.delete\s*\(`,
		action:   "deny",
		message:  "sending DELETE requests via Python HTTP clients is forbidden",
		priority: 80,
	},
	{
		name:     "[builtin] declaring HTTP DELETE method in scripts (JS/generic)",
		target:   "tool_input",
		typ:      "regex",
		pattern:  `(?i)axios\.delete\s*\(|method\s*[:=]\s*['"]DELETE['"]`,
		action:   "deny",
		message:  "declaring and sending HTTP DELETE requests in scripts is forbidden",
		priority: 80,
	},
	{
		name:     "[builtin] bulk clear / wipe endpoint paths",
		target:   "tool_input",
		typ:      "regex",
		pattern:  `(?i)/(?:clear|wipe|flush|purge|truncate|drop|destroy|factory[-_]reset|reset[-_]all)(?:[/?#"'\s]|$)`,
		action:   "deny",
		message:  "calling bulk-clear or destroy-type endpoints is forbidden (/clear /wipe /flush /purge etc.)",
		priority: 80,
	},
}

// seedDefaultInterceptRules inserts built-in safety intercept rules once on
// first startup. The seed is gated by a settings flag so user edits (disable,
// delete, re-order) are never overwritten on subsequent restarts.
func (d *DB) seedDefaultInterceptRules() error {
	if v, _, _ := d.GetSetting("intercept_default_rules_v1"); v == "done" {
		return nil
	}
	for _, r := range defaultInterceptRuleSeeds {
		if _, err := d.Exec(`
INSERT INTO intercept_rules(name, enabled, priority, match_target, match_type, pattern, action, message, timeout_enabled, timeout_seconds, timeout_action)
VALUES ($1, true, $2, $3, $4, $5, $6, $7, false, 60, 'deny')
ON CONFLICT DO NOTHING`,
			r.name, r.priority, r.target, r.typ, r.pattern, r.action, r.message,
		); err != nil {
			return fmt.Errorf("rule %q: %w", r.name, err)
		}
	}
	return d.SetSetting("intercept_default_rules_v1", "done")
}

// backfillSeedTextEnglish rewrites user-visible text on rows seeded before the
// codebase was translated to English — builtin intercept-rule names/messages,
// builtin MCP descriptions, the built-in admin display name — ONCE (settings
// flag), matching only rows that still carry the old Chinese text so operator
// edits are never clobbered.
func (d *DB) backfillSeedTextEnglish() {
	if v, _, _ := d.GetSetting("seed_text_en_v1"); v == "done" {
		return
	}
	for _, r := range defaultInterceptRuleSeeds {
		// match the old-language builtin row by its (unchanged) pattern + [内置] prefix
		d.Exec(`UPDATE intercept_rules SET name=$1, message=$2 WHERE pattern=$3 AND name LIKE '[内置]%'`, //nolint:errcheck
			r.name, r.message, r.pattern)
	}
	d.Exec(`UPDATE mcp_servers SET description=$1 WHERE name='filesystem' AND description ~ '[一-鿿]'`, //nolint:errcheck
		`Read and write the local filesystem — store payloads, script output, discovered config files, etc. during pentesting`)
	d.Exec(`UPDATE mcp_servers SET description=$1 WHERE name='github' AND description ~ '[一-鿿]'`, //nolint:errcheck
		`GitHub repository recon — search public repos for leaked credentials, keys, or sensitive config, or analyze the target organization's open-source code (requires a GITHUB_PERSONAL_ACCESS_TOKEN on the MCP page to enable)`)
	d.Exec(`UPDATE rbac_users SET display_name='Administrator' WHERE username='admin' AND display_name='管理员'`) //nolint:errcheck
	_ = d.SetSetting("seed_text_en_v1", "done")
}

// migrateKnowledgeConfigToBuiltin moves a still-on-the-old-default embedder
// config onto the vendored in-process model. Only fires while base_url is the
// factory default — any operator-set endpoint is left alone.
func (d *DB) migrateKnowledgeConfigToBuiltin() {
	if v, _, _ := d.GetSetting("builtin_embedder_v1"); v == "done" {
		return
	}
	d.Exec(`UPDATE knowledge_config SET base_url='builtin', model='potion-base-8M', api_key='', dim=256, updated_at=now()
		WHERE base_url='https://open.bigmodel.cn/api/paas/v4'`) //nolint:errcheck
	_ = d.SetSetting("builtin_embedder_v1", "done")
}
