package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"antifox/db"
	"antifox/engine/agentcore"
	"antifox/engine/harness"
	"antifox/engine/llm"
	"antifox/engine/memory"
	"antifox/engine/permission"
	actool "antifox/engine/tool"
	"antifox/engine/transcript"
)

// Worker is an LLM work agent (docs §4.4): it claims ONE intent, completes it
// with real tools (Bash: kali tooling through the recording proxy), writes the
// FACTS it found back into the graph, and stops. It does NOT generate new
// directions (that is the planner's job) and does NOT keep exploring toward the
// goal on its own. Multiple workers run concurrently as goroutines.
// WebSearchOpts is the web-search backend selection the server pushes into each
// agent (planner/worker/main). Enabled=false leaves the web_search tool off.
// Backend is "ddgs" (no key), "brave-free" (BraveKey required), or "tavily"
// (TavilyKey required). It maps directly onto agentcore.Options.
// Proxy is a dedicated egress proxy for the search request (http/https/socks5),
// independent of the traffic-recording MITM proxy — set it when the search endpoint
// is only reachable via a VPN/SOCKS proxy. Empty = direct.
type WebSearchOpts struct {
	Enabled   bool
	Backend   string
	BraveKey  string
	TavilyKey string
	Proxy     string
}

type Worker struct {
	prov        llm.Provider
	model       string
	workDir     string
	proxyAddr   string
	proxyCACert string            // recording proxy's CA cert path (for WebFetch HTTPS verify)
	webSearch   WebSearchOpts     // web_search tool backend selection (off by default)
	mem         *memory.Store     // cross-engagement tradecraft memory (G4)
	tx          *transcript.Store // raw LLM conversation persistence (nil = off)
	window      int               // context window in tokens (for compaction)
	maxTurns    int               // max agent turns per run (0 = unlimited)
	// runTimeout is the wall-clock budget for the main exploration of one intent
	// (0 = unlimited). When it fires, the run is cut and a settlement round is
	// forced so already-identified facts get written back instead of being lost.
	runTimeout time.Duration
	// extraTools are host-provided tools (e.g. traffic query, oast) appended to
	// the worker's graph write-back tools.
	extraTools []actool.CoreTool
	// trafficResolver, if set, resolves a finding's reproduction steps to real
	// recorded traffic exchange ids at record time (host callback). nil = no linkage.
	trafficResolver func(taskID int64, repro json.RawMessage) json.RawMessage
}

// SetRunTimeout configures the per-intent wall-clock budget for the main
// exploration (0 = unlimited). When it fires, the SDK settlement phase still runs
// so facts are never lost to a timeout. Safe to call before Execute.
func (w *Worker) SetRunTimeout(run time.Duration) {
	w.runTimeout = run
}

// settleHardGrace is how far past the soft wall-clock budget (runTimeout) the hard
// ctx deadline sits — a backstop for a hung turn; the soft budget handles the
// normal case at the turn boundary.
const settleHardGrace = 90 * time.Second

// settleWrapUpPrompt is injected by the SDK settlement phase when a worker hits its
// turn/time budget: stop probing, write back what was found, then end with a
// plain-text one-liner (which becomes this run's displayed result).
const settleWrapUpPrompt = "You are about to be terminated for budget exhaustion. Do not run any more commands/probes. In order: (1) write back everything you identified above but haven't stored yet — new assets via insert_assets, exploration conclusions/facts via record_fact, confirmed vulnerabilities via report_finding; (2) **then output ONE plain-text sentence** summarizing what you did and the key conclusions (this sentence is shown as the run's result — you must output it)."

// SetMemory enables cross-engagement tradecraft memory (RecallMemory/RecordMemory
// tools + auto-injection of relevant memories, docs §8 G4).
func (w *Worker) SetMemory(m *memory.Store) { w.mem = m }

func NewWorker(prov llm.Provider, model, workDir string, tx *transcript.Store, window, maxTurns int, extra ...actool.CoreTool) *Worker {
	return &Worker{prov: prov, model: model, workDir: workDir, tx: tx, window: window, maxTurns: maxTurns, extraTools: extra}
}

// SetProxy configures the recording proxy address that workers route target
// traffic through, plus the CA cert path WebFetch trusts to verify HTTPS through
// that MITM proxy. Empty addr disables the hint.
func (w *Worker) SetProxy(addr, caCert string) { w.proxyAddr, w.proxyCACert = addr, caCert }

// SetWebSearch selects the web_search backend for this worker (off by default).
func (w *Worker) SetWebSearch(o WebSearchOpts) { w.webSearch = o }

// SetTrafficResolver wires the record-time traffic linkage callback (host-provided).
func (w *Worker) SetTrafficResolver(fn func(taskID int64, repro json.RawMessage) json.RawMessage) {
	w.trafficResolver = fn
}

// proxyEnv builds the Bash-subprocess env that routes child-command HTTP through
// the recording proxy and makes the common toolchain trust its MITM CA — so tools
// need no manual -x/--proxy/-k. Each ecosystem reads a different CA var (verified
// empirically): SSL_CERT_FILE→curl/urllib/Go/openssl, REQUESTS_CA_BUNDLE→python
// requests (it ignores SSL_CERT_FILE), CURL_CA_BUNDLE→curl, GIT_SSL_CAINFO→git,
// NODE_EXTRA_CA_CERTS→node; NODE_USE_ENV_PROXY makes Node 24+ honor the proxy vars.
// Empty proxyAddr → nil (direct, unchanged env).
func proxyEnv(proxyAddr, caCert string) []string {
	if proxyAddr == "" {
		return nil
	}
	env := []string{
		"HTTP_PROXY=" + proxyAddr, "HTTPS_PROXY=" + proxyAddr,
		"http_proxy=" + proxyAddr, "https_proxy=" + proxyAddr,
		"NODE_USE_ENV_PROXY=1", // Node 24+: honor HTTP(S)_PROXY in built-in fetch/http
	}
	if caCert != "" {
		env = append(env,
			"SSL_CERT_FILE="+caCert,
			"CURL_CA_BUNDLE="+caCert,
			"REQUESTS_CA_BUNDLE="+caCert,
			"GIT_SSL_CAINFO="+caCert,
			"NODE_EXTRA_CA_CERTS="+caCert,
		)
	}
	return env
}

// workerDefaultTmpl is the built-in EDITABLE body (section [A]) of the worker
// system prompt, seeded into agent_prompts. The trafficTool block and the
// artifact-output-spec are NOT here — they are code-owned and appended by
// workerSystem after rendering (sections [B]/[C]), so editing the DB body can
// never drop them.
const workerDefaultTmpl = `You are the "executor" (work agent) of an authorized penetration testing system. You are handed [ONE intent] (a one-sentence exploration direction). Your sole duty: **complete that one intent, write the discovered facts back to the knowledge graph, then stop and return.**

Ironclad rules (must follow):
1. **Do only this one intent**. The intent's boundary is your red line. A fingerprinting intent means fingerprinting only — don't slip into enumerating endpoints, brute-forcing directories, scraping JS for APIs, or testing vulnerabilities — those belong to [other intents], which the planner dispatches to other workers.
2. **You are not responsible for "exploration direction."** If you find a new lead worth chasing, don't pursue it yourself; just write it back to the graph — the planner reads it and generates new intents itself. Generating directions is the planner's job, not yours.
3. **Exhaust before returning — don't give up at the first obstacle.** The bar for "intent achieved" is [you have genuinely exhausted this direction]: a blocked first attempt (one payload filtered, one endpoint 404, one injection point with no echo) does not mean the path is dead — first walk the intent's reasonable means: change encoding / method / parameter / path, then conclude. **But the boundary holds**: what you exhaust is only the means [inside this one intent] — never slide into doing other intents (enumerating other endpoints, testing other vulnerabilities); those remain the planner's other workers' business. Once truly exhausted or confirmed dead, write back and return immediately — don't keep going because "the overall task goal isn't met yet," and don't spin on an exhausted direction just to spend steps.
4. **Write back as you discover, and write to the right place**. Store every result the moment you get it (don't save it all for the end — if your steps run out, it's all lost). A result only counts once it's in the graph; what lives only in your head/text doesn't count. **Keep the two graphs straight**:
   - **New asset/resource discovered** → insert_assets into the [asset graph] (registers the asset itself: endpoint / parameter / tech fingerprint / service / credential / subdomain etc.). An asset's structured attributes go on itself: site/endpoint status code/title/body length/content_type go in props.http; a tech stack is registered as a type=tech node. Register multiple assets in one insert_assets call via the assets array.
   - **Exploration conclusion/fact reached** (positive conclusions like fingerprints/enumeration, and negative conclusions like "port closed", "this parameter is not injectable", "no login entry found") → record_fact into the [exploration graph] (pass intent_id). **Combine multiple observations from one exploration into [ONE] fact**: summary = one summarizing sentence, detail = the related specifics (tech stack, status codes, response traits all go into this one detail) — **do not write one fact per attribute**; one intent usually produces one fact, and over-splitting bloats the graph endlessly. Use the facts array for a batch only when there are genuinely [distinct] conclusions. [New] **Write only the delta**: before writing, scan recent_facts in the [global exploration situation] above — record only what you [newly learned] this run; don't re-record an existing fact in different words (duplicate facts bloat the graph and mislead the planner into thinking there's new progress). If your observation merely confirms an existing fact with nothing new, don't record another one.
   - **Confirmed vulnerability** → report_finding into the [exploration graph] (with PoC, pass intent_id).
   - **Exposure / info-disclosure is also a finding, not just an asset**: an unauthenticated-reachable sensitive surface — admin/debug interfaces, Swagger/API docs, config or backup/source files, sensitive-data leak endpoints — **as long as you actually accessed it and got a response proving the exposure**, that is itself a [confirmed] finding (reachable + real response = triggered, not conjecture) → record with report_finding (severity by sensitivity: generic info leak = low, unauthenticated sensitive/admin interface = medium, direct takeover or credentials/keys obtained = high). **The difference**: "this interface exists" alone is an asset (insert_assets); "it is accessible unauthenticated AND exposes what it shouldn't" is a finding (report_finding) — don't file the latter as mere asset/fact. When hard exploitation doesn't break through, these proven exposures are the findings you must deliver — don't record zero.

Available tools:
- insert_assets: register new assets (asset graph). **You pass only raw info — the key and parent/child links are computed by code**: a new endpoint → pass full url+method (code auto-creates domain→site→endpoint and auto-extracts URL query params; body/header params go in params); a fingerprint → type=tech, name=tech name, on_url=site address, props={version,category}. Multiple assets go in the assets array in one batch call. Attributes live on the asset's own props — don't put exploration conclusions here.
- record_fact: write an exploration [fact/conclusion] into the exploration graph and link it to the intent (pass intent_id). Use it for positive/negative conclusions, observations, judgments; **combine one exploration's multiple observations into one fact** (summary = one sentence + detail = specifics), not one fact per attribute. Only use the facts array for genuinely distinct conclusions. **Write only what you truly saw**: provide evidence (one line of key evidence: command + key output — concise, don't paste huge blobs; details go in detail) and mark confidence (observed = directly seen / inferred = deduced); **evidence bar for negative conclusions** (ones like not-injectable/port-closed/no-login-entry that [may make the planner abandon a whole direction]): before concluding, confirm you have [exhausted the reasonable means inside this intent] (changed encoding/parameter/path/method); if the means aren't exhausted, or the evidence is only "looks like / probably so", mark confidence=inferred. **Better to mark inferred and let the planner re-check than to weld a whole route shut with a hasty observed negative** — especially early in a task, one wrong observed negative can derail the whole task and is hard to recover from.
- report_finding: confirmed vulnerability → record (with PoC, pass intent_id = the intent id you were handed). **Use it only if YOU actually triggered the vulnerability in this run and obtained reproducible evidence (request/response or command output).** NEVER report these as confirmed findings: matching a CVE only by version/fingerprint, "the parameter looks injectable", inference from external vuln DBs/changelogs/code diffs alone. **Do not substitute CVE-DB lookups or "comparing patch versions" for actually triggering it.** If you can't trigger it but there's genuine suspicion, record a confidence=inferred fact with record_fact (describe the suspected point + why you couldn't trigger it) and let the planner dispatch a follow-up intent — don't force it into a finding.
  **[Always fill the structured reproduction]** (you just ran it — you know each step best; nobody can reconstruct it accurately later): entry_point (the key endpoint that triggers the vuln: method+URL) · prerequisites (what's needed to reproduce: required account/role/prior steps; if a test account is needed, explain [how to register it] — the endpoint + key request essentials, so a human can reproduce from zero) · steps (ordered steps; each step's request = the verbatim request you actually sent [word-for-word, don't rewrite/fabricate], response = that step's real response verbatim [status code + key headers + key body excerpt — taken verbatim from the real return; if too long keep the parts that prove the issue], expected = one-sentence expectation/conclusion for that step, proves = what it proves) · provenance (the vuln's attack-chain origin/dependencies). Give verbatim requests and responses whenever possible — this reproduction directly determines whether the report can be reproduced by a human, so fill it in carefully.
- list_assets (queries assets, not exploration nodes) / asset_neighbors / list_facts (exploration facts) / list_findings (vulnerabilities) / node_detail (exploration node id, not asset id): query context on demand.
- [Use only when necessary — most context is already in this session] search_all_worker_traces / list_worker_traces / get_worker_trace: **reusing information across works** (things that appeared in other works' execution but were never written into facts). You can't see the exploration graph, but you can: search_all_worker_traces(q) to keyword-search all works' processes (results carry intent_id); list_worker_traces to see which works ran; get_worker_trace(intent_id) for a work's step summary; get_worker_trace(intent_id, step_ids=[…]) to fetch full content of specific steps (≤5 at a time). **Only for reusing others' observations and avoiding duplicate work — it does NOT change your task boundary (you still do only your one intent).**

Operate only within authorized scope. When the intent is done, summarize in one sentence what you did and which facts you wrote back. Be pragmatic, restrained, focused on this one intent.`

// workerTrafficBlock is section [B]: the traffic-tool note, code-injected only when
// traffic capture is on (proxyAddr set). Not stored, not editable.
func workerTrafficBlock(proxyAddr string) string {
	if proxyAddr == "" {
		return ""
	}
	return "\n\n**Traffic tools**:\n- traffic_search / traffic_get: target traffic is fully stored by the recording proxy (local file tree data/traffic/<host>/<request path>/). To review responses or find already-visited resources, **search traffic first — don't re-curl the same URL**. traffic_search **requires a host** and returns only 3 ultra-light index entries by default (id/method/url/status/resp_len, no response content) — raise limit explicitly for more; to read a record's full text use traffic_get(id)."
}

// artifactSpec is section [C]: the code-owned, non-editable tail appended to every
// pentest agent's prompt — intermediate artifacts must land in the shared work
// dir, never /tmp. Guaranteed present regardless of how the DB body is edited.
func artifactSpec(workDir string) string {
	return "\n\n**Artifact output spec**: all intermediate artifacts — scripts, payloads, captured response bodies, temp data — **must be written to the shared working directory " + workDir + "** (this is the CWD shared by all agents; relative paths land here, or use this absolute path) — **do not write to /tmp or any other absolute path**."
}

// workerArtifactSubdir is the worker-only addendum to artifactSpec: put a run's
// artifacts under an i<intentID>/ subdir to avoid concurrent name collisions.
const workerArtifactSubdir = "To avoid name collisions with other works, put this run's artifacts under subdirectory i<intent id>/ (e.g. i123/exploit.py)."

func workerSystem(proxyAddr, workDir string) string {
	body := renderSystem("worker", workerDefaultTmpl, WorkerVars{ProxyAddr: proxyAddr})
	return body + workerTrafficBlock(proxyAddr) + artifactSpec(workDir) + workerArtifactSubdir
}

// renderIntentTask formats the claimed intent for the worker's SYSTEM prompt: the
// intent is the worker's whole job, so — like the planner's situational block — it
// belongs in system, where compaction can never drop it during a long run.
func renderIntentTask(intent *db.Node) string {
	return fmt.Sprintf("\n\n[The intent you were handed (your only task this run: do only this, produce only facts, stop when done)]:\n%s\nintent id: %d (pass it when calling record_fact / report_finding)", string(intent.Payload), intent.ID)
}

// renderWorkerGraphOverview folds the global situational snapshot into the worker's
// SYSTEM prompt for AWARENESS ONLY. The framing is deliberately strong: the overview
// must NOT widen the worker's job — it still does only its assigned intent. Its sole
// purpose is letting the worker read context (existing facts/assets/hints)
// so it avoids redundant work and doesn't re-derive what others already found.
func renderWorkerGraphOverview(data map[string]any) string {
	b, err := json.Marshal(data)
	if err != nil {
		return "" // fall back silently: the worker just won't have the global context
	}
	return "\n\n[Global exploration situation (for your situational awareness only — NOT your task list)]:\n" +
		"Below is the task's current exploration overview. Its **only purpose** is to keep you aware of the big picture, reuse existing conclusions, and avoid redoing what others already did.\n" +
		"**It does NOT widen your responsibility boundary**: you still do only the one intent you were handed above. If you see other open intents / uncovered points / other attackable directions here, **never act on them yourself** — those belong to other workers, scheduled by the planner. If you spot a relevant new lead, at most write it into a fact so the planner knows — don't chase it yourself.\n" +
		string(b)
}

// Execute runs one intent. hooks (the per-task Guard) gates every tool call; may
// be nil. emit, if non-nil, receives one ActivityRecord per execution step.
// Returns the terminal reason (so the engine can distinguish completed vs
// max_turns) and a per-kind breakdown of what was written back (so an intent that
// explored but persisted nothing isn't mistaken for done, and the engine can log
// facts/assets/findings separately instead of lumping them under "facts").
func (w *Worker) Execute(ctx context.Context, name string, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, intent *db.Node, hooks harness.HookRunner, emit func(db.Activity), enr EnrichTrigger) (harness.TerminalReason, WriteCounts, error) {
	tsx := NewToolSet(ts, name)
	tsx.SetTaskID(taskID)
	tsx.SetTrafficResolver(w.trafficResolver)
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetOwnerNode(intent.ID) // assets this worker discovers anchor to its intent → visible to the task
	tsx.SetEnrich(enr)          // async DNS/HTTP auto-completion for assets this worker writes
	// base = built-in worker tools ∪ host tools (traffic) ∪ default tools (incl. Bash);
	// then augment with the agent's visible skills/MCP. During the SDK settlement
	// phase, Bash is hidden via Settlement.DisabledTools (no local gating needed).
	base := append(tsx.WorkerTools(), w.extraTools...)
	base = append(base, actool.DefaultTools()...)
	tools, def, cleanup := AugmentTools(ctx, "worker", base)
	defer cleanup()

	// The intent is the worker's entire task, so it goes into the system prompt
	// (compaction-proof, present all round), not the user input — consistent with the
	// planner putting its situation in system. It lands after the instructions,
	// before the deferred block. The global situation (graphOverviewData) is included
	// too, but only for awareness; the intent sits last, in the most prominent spot.
	overview := renderWorkerGraphOverview(tsx.graphOverviewData())
	system, boundary := deferredSystem(workerSystem(w.proxyAddr, w.workDir)+overview+renderIntentTask(intent), def)
	// The task-level deadline (injected via ctx) clamps this run's wall-clock budget and selects the wrap-up text (see taskclock.go).
	tc := taskClockFrom(ctx)
	maxDur, clamped := clampMaxDuration(tc.DeadlineUnix, w.runTimeout)
	settle := wrapupSettlement("worker", []string{"Bash"})
	if tc.DeadlineUnix > 0 {
		settle = wrapupSettlementForTask("worker", []string{"Bash"}, clamped)
	}
	opts := agentcore.Options{
		Provider:        w.prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,
		// WebFetch goes through the recording proxy — its HTTP is recorded just like
		// curl; loading the proxy CA lets MITM-resigned HTTPS certs verify normally
		// (rather than disabling verification). Empty proxy = direct.
		EnableWebFetch: true,
		WebFetchProxy:  w.proxyAddr,
		WebFetchCACert: w.proxyCACert,
		// Web search (optional). ddgs needs no key; brave-free needs BraveKey; tavily needs TavilyKey.
		// WebSearchProxy is an independent egress proxy (http/https/socks5), unrelated to the traffic-recording MITM proxy; empty = direct.
		EnableWebSearch:    w.webSearch.Enabled,
		WebSearchBackend:   w.webSearch.Backend,
		BraveSearchAPIKey:  w.webSearch.BraveKey,
		TavilySearchAPIKey: w.webSearch.TavilyKey,
		WebSearchProxy:     w.webSearch.Proxy,
		// Bash subcommands' HTTP defaults to the recording proxy + trusts its CA (no -x/-k needed).
		BashEnv:    proxyEnv(w.proxyAddr, w.proxyCACert),
		WorkingDir: w.workDir,
		MaxTurns:   w.maxTurns, // 0 = unlimited (configurable in agent management)
		// Wall-clock budget, judged at turn boundaries (never interrupts mid-action);
		// 0 = unlimited. With a task-level deadline, clamped to min(own budget, time to
		// deadline) so this run naturally enters wrap-up at task timeout (see taskclock.go).
		MaxDuration: maxDur,
		// Hitting the budget (turns OR duration) → the SDK runs a wrap-up round
		// (Bash hidden) to write back what was identified — no unfinished tail.
		// When clamped (squeezed by the task deadline), use PromptByReason: timeout =
		// task deadline reached → task-timeout text; turns = steps exhausted inside the
		// clamped window → fall back to per-run text. Non-clamped stays pure per-run.
		Settlement: settle,
		// large tool output spills to cmd-output/ with a head + pointer (SDK tool.Capture);
		// full output preserved on disk. Truncation limit uses the SDK default (30000 chars).
		ToolOutputDir: filepath.Join(w.workDir, "cmd-output"),
		Compaction:    compactionConfig(w.window), // long tool-heavy runs stay within the window
		Todos:         actool.NewTodoStore(),      // session-scoped scratch todos (TodoWrite), planning only, dropped on exit
	}
	if hooks != nil { // typed-nil guard: only set when concrete (avoids harness panic)
		opts.Hooks = hooks
	}
	if w.mem != nil {
		opts.Memory = &agentcore.MemoryOptions{Store: w.mem, AutoInject: true, MaxInject: 3}
	}
	if w.tx != nil { // persist raw LLM conversation; one file per worked intent
		opts.Transcript = w.tx
		opts.SessionID = fmt.Sprintf("exp%d-worker-i%d", ts.ID(), intent.ID)
	}
	intentID := intent.ID
	emitWrap := func(r db.Activity) {
		if emit != nil {
			r.NodeID, r.Worker = &intentID, name
			emit(r)
		}
	}
	// The intent is in system. The user input carries only the kickoff instruction.
	input := "Start executing the intent in the system prompt: do only it, produce only facts, stop when done."

	s := agentcore.NewSession(opts)
	defer s.Close() // release the session's background-task manager (temp dir + processes)

	// Budgets + settlement are owned by the SDK (MaxTurns/MaxDuration + Settlement):
	// on hit it runs a wrap-up turn and finishes with ReasonMaxTurns/ReasonTimeout.
	// We only add a HARD ctx backstop past the soft wall-clock budget, for the rare
	// case a single turn hangs so the turn-boundary check never runs — the soft
	// budget handles the normal case gracefully (no mid-stream abort). pause /
	// planner kill cancel ctx; the engine distinguishes those and re-queues/stops.
	// backstop uses the EFFECTIVE (deadline-clamped) budget, not the raw runTimeout,
	// so a task-timeout run's hard deadline sits just past its clamped soft budget.
	runCtx := ctx
	if maxDur > 0 {
		var runCancel context.CancelFunc
		runCtx, runCancel = context.WithTimeout(ctx, maxDur+settleHardGrace)
		defer runCancel()
	}
	_, reason, err := captureRunSession(runCtx, s, input, emitWrap)
	return reason, tsx.Writes(), err
}
