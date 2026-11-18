package agent

import (
	"context"
	"fmt"

	"antifox/db"
	"antifox/engine/agentcore"
	"antifox/engine/llm"
	"antifox/engine/permission"
	actool "antifox/engine/tool"
	"antifox/engine/transcript"
)

// MainAgent is the thin human-interface orchestrator (docs §4.2 / §7). The human
// chats with it; it observes (read tools), and steers by injecting hints
// (→planner) or direct high-priority intents (→frontier). It does NOT run the
// autonomous intent-generation loop (that is the planner's job).
type MainAgent struct {
	prov        llm.Provider
	model       string
	tx          *transcript.Store // raw LLM conversation persistence (nil = off)
	window      int               // context window in tokens (for compaction)
	maxTurns    int               // max agent turns per run (0 = unlimited)
	proxyAddr   string            // recording proxy for WebFetch (empty = direct)
	proxyCACert string            // recording proxy's CA cert path (HTTPS verify)
	webSearch   WebSearchOpts     // web_search tool backend selection (off by default)
	workDir     string            // shared work dir (surfaced in prompt as artifact-output target)
}

func NewMainAgent(prov llm.Provider, model, workDir string, tx *transcript.Store, window, maxTurns int) *MainAgent {
	return &MainAgent{prov: prov, model: model, workDir: workDir, tx: tx, window: window, maxTurns: maxTurns}
}

// SetProxy points the main agent's WebFetch at the recording proxy plus the CA
// cert it trusts to verify HTTPS through it (empty addr = direct).
func (m *MainAgent) SetProxy(addr, caCert string) { m.proxyAddr, m.proxyCACert = addr, caCert }

// SetWebSearch selects the web_search backend for the main agent (off by default).
func (m *MainAgent) SetWebSearch(o WebSearchOpts) { m.webSearch = o }

// mainAgentDefaultTmpl is the built-in EDITABLE body (section [A]) of the main
// agent prompt, seeded into agent_prompts. Goal is a {{.Goal}} template var; the
// artifact-output-spec tail is code-owned (artifactSpec), appended after rendering.
const mainAgentDefaultTmpl = `You are the "main agent" of an authorized penetration testing system — the human operator's interface. You do not explore yourself and you do not autonomously generate a stream of intents (that is the planner's job). Your duties:

1. Observe: use graph_overview / list_findings / list_facts / list_assets / get_worker_output to answer the human's questions about current progress.
2. Record findings (important — don't miss any): every vulnerability already verified by a worker, or confirmed by your own review, **immediately record with report_finding, one call per finding** — fill vulnclass (vulnerability name/type), severity (critical|high|medium|low; critical = can directly cause full system/data compromise, e.g. RCE, unauthenticated arbitrary file read yielding keys/credentials, privilege bypass enabling account takeover), summary (include the affected target), evidence (verbatim reproducible request/command/response PoC text), asset_ids when the affected assets have ids; **and fill the structured reproduction whenever possible** (entry_point / prerequisites including how to register test accounts / steps with each real request + expected + proves / provenance) — take requests verbatim from worker transcripts / real executions, don't paraphrase, so the report can be reproduced by a human from scratch. **Record on confirmation — don't ask permission and don't just list findings in your reply** — only findings recorded via report_finding reach the findings page / exploration graph / report; findings written only in a reply are wasted work. Use list_findings first to avoid duplicates. Never report as confirmed something inferred only from version/CVE matching or "looks exploitable" conjecture. **Exposure / info-disclosure counts as a finding too**: worker-proven unauthenticated-reachable sensitive surfaces (admin/debug interfaces, Swagger/API docs, exposed config or backup/source files, sensitive-data leak endpoints — with real response evidence) also each get a report_finding (severity by sensitivity: generic leak = low, unauthenticated sensitive/admin interface = medium, direct takeover or credentials = high) — don't file them as mere assets/facts. **When the user asks you to "review current findings", or when a task wraps up / pauses**: record every worker-written finding and proven exposure in the graph into the store one by one (list_findings/list_facts first to dedup) — even if hard exploitation didn't break through, deliver these proven exposures/risks; don't just list them in a reply.
3. Steering (turn the human's intent into system actions):
   - Human wants to "change direction / emphasize a vuln class / focus an area" → write a hint with add_hint (the planner reads it next round).
   - Human wants to "test a specific target right now" → inject a high-priority intent directly with add_intent (priority 8-10).
4. Reply concisely in plain language: what you did and which findings you recorded.

Current task goal: {{.Goal}}

Do not fabricate findings; record and answer only from real tool-returned data and verified evidence.`

func mainAgentSystem(goal, workDir string) string {
	body := renderSystem("mainagent", mainAgentDefaultTmpl, MainVars{Goal: goal})
	return body + artifactSpec(workDir)
}

// Chat handles one human message and returns the assistant reply. emit, if
// non-nil, receives each execution step (thinking / tool_use / tool_result /
// text / result) so the main-agent session shows its work — exactly like the
// worker/planner sessions — not just the final answer.
func (m *MainAgent) Chat(ctx context.Context, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, goal, message string, emit func(db.Activity), notify func()) (string, error) {
	tsx := NewToolSet(ts, "human")
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetTaskID(taskID)
	tsx.SetNotify(notify) // add_hint wakes this task's planner (debounced)
	// domain tools + base default toolset (Read/Write/Edit/MultiEdit/LS/Glob/Grep/Bash)
	base := append(tsx.MainAgentTools(), actool.DefaultTools()...)
	tools, def, cleanup := AugmentTools(ctx, "mainagent", base)
	defer cleanup()
	system, boundary := deferredSystem(mainAgentSystem(goal, m.workDir), def)
	opts := agentcore.Options{
		Provider:        m.prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,
		EnableWebFetch:  true, // route through the recording proxy for evidence; load its CA to verify MITM-resigned HTTPS certs
		WebFetchProxy:   m.proxyAddr,
		WebFetchCACert:  m.proxyCACert,
		// Web search (optional). ddgs needs no key; brave-free needs BraveKey; tavily needs TavilyKey.
		// WebSearchProxy is an independent egress proxy (http/https/socks5), unrelated to the traffic-recording MITM proxy; empty = direct.
		EnableWebSearch:    m.webSearch.Enabled,
		WebSearchBackend:   m.webSearch.Backend,
		BraveSearchAPIKey:  m.webSearch.BraveKey,
		TavilySearchAPIKey: m.webSearch.TavilyKey,
		WebSearchProxy:     m.webSearch.Proxy,
		BashEnv:            proxyEnv(m.proxyAddr, m.proxyCACert), // Bash subcommands default to the proxy + trust its CA
		MaxTurns:           m.maxTurns,                           // 0 = unlimited (configurable in agent management)
		Compaction:         compactionConfig(m.window),           // long chats stay within the window
		Todos:              actool.NewTodoStore(),                // session-scoped scratch todos (TodoWrite), planning only, dropped on exit
		// Hitting the step budget → the SDK runs wrap-up: output a one-line progress summary to the user. Prompt and wrap-up rounds are editable in the admin UI (default 5 rounds).
		Settlement: wrapupSettlement("mainagent", nil),
	}
	if m.tx != nil { // persist raw human↔AI conversation; one accumulating file per task
		opts.Transcript = m.tx
		opts.SessionID = fmt.Sprintf("exp%d-main", ts.ID())
	}
	s := agentcore.NewSession(opts)
	defer s.Close()
	// reload the prior conversation from the transcript so the agent has context
	// across turns (each Chat is a fresh session; without this it can't see earlier
	// messages). First turn: no file yet → Resume loads nothing and proceeds.
	if m.tx != nil {
		_ = s.Resume(opts.SessionID)
	}
	// C2: this session is fresh each turn; re-unlock skill-gated MCPs from prior
	// Skill() calls in the reloaded history so revealed tools stay callable.
	seedUnlockFromHistory(s.Messages(), def.UnlockSkill)
	text, _, err := captureRunSession(ctx, s, message, func(r db.Activity) {
		if emit != nil {
			r.Worker = "mainagent"
			emit(r)
		}
	})
	return text, err
}
