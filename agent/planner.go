package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"antifox/db"
	"antifox/engine/agentcore"
	"antifox/engine/llm"
	"antifox/engine/permission"
	actool "antifox/engine/tool"
	"antifox/engine/transcript"
)

// Planner is the event-driven LLM planner (docs §4.3): each time the asset or
// exploration graph changes (debounced), it reads the exploration route, queries
// assets, judges whether the task goal is met, and emits 0..N exploration intents
// into the frontier. It is the sole intent generator.
type Planner struct {
	prov        llm.Provider
	model       string
	tx          *transcript.Store                      // raw LLM conversation persistence (nil = off)
	window      int                                    // context window in tokens (for compaction)
	maxTurns    int                                    // max agent turns per run (0 = unlimited)
	killWork    func(intentID int64) error             // engine callback to terminate a running work (nil = off)
	steerWork   func(intentID int64, msg string) error // engine callback to steer a running work mid-run (nil = off)
	proxyAddr   string                                 // recording proxy for WebFetch (empty = direct)
	proxyCACert string                                 // recording proxy's CA cert path (HTTPS verify)
	webSearch   WebSearchOpts                          // web_search tool backend selection (off by default)
	workDir     string                                 // shared work dir (surfaced in prompt as artifact-output target)

	// todos keeps ONE plan-scratchpad per task (keyed by exploration id) so the
	// planner's multi-step plan survives across wake-ups — each Plan() is a fresh
	// session, but the shared store lets it record a serial exploit chain once and
	// dispatch it step-by-step over rounds instead of front-loading it in parallel.
	todoMu sync.Mutex
	todos  map[int64]*actool.TodoStore
}

func NewPlanner(prov llm.Provider, model, workDir string, tx *transcript.Store, window, maxTurns int) *Planner {
	return &Planner{prov: prov, model: model, workDir: workDir, tx: tx, window: window, maxTurns: maxTurns, todos: map[int64]*actool.TodoStore{}}
}

// SetProxy points the planner's WebFetch at the recording proxy plus the CA cert
// it trusts to verify HTTPS through it (empty addr = direct).
func (p *Planner) SetProxy(addr, caCert string) { p.proxyAddr, p.proxyCACert = addr, caCert }

// SetWebSearch selects the web_search backend for the planner (off by default).
func (p *Planner) SetWebSearch(o WebSearchOpts) { p.webSearch = o }

// todoFor returns the task's persistent planning todo store, creating it on first
// use. Shared across all of this task's planner wake-ups.
func (p *Planner) todoFor(expID int64) *actool.TodoStore {
	p.todoMu.Lock()
	defer p.todoMu.Unlock()
	s := p.todos[expID]
	if s == nil {
		s = actool.NewTodoStore()
		p.todos[expID] = s
	}
	return s
}

// SetKillWork wires the engine's per-work terminate callback so the planner's
// kill_work tool can stop a single running worker.
func (p *Planner) SetKillWork(fn func(intentID int64) error) { p.killWork = fn }

// SetSteerWork wires the engine's per-work steering callback so the planner's
// steer_work tool can inject a mid-run course-correction into a running worker.
func (p *Planner) SetSteerWork(fn func(intentID int64, msg string) error) { p.steerWork = fn }

// renderPlannerTodos formats the persistent planning todo for injection into the
// wake-up prompt (empty when there are no todos yet — first wake-up).
func renderPlannerTodos(items []actool.Todo) string {
	if len(items) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n[Your planning todo list (persists across wake-ups — you wrote it last round)]:\n")
	for _, it := range items {
		mark := map[actool.TodoStatus]string{actool.TodoPending: "☐", actool.TodoInProgress: "▶", actool.TodoCompleted: "✔"}[it.Status]
		if mark == "" {
			mark = "☐"
		}
		b.WriteString(fmt.Sprintf("  %s %s\n", mark, it.Content))
	}
	b.WriteString("Proceed accordingly: only dispatch intents for next steps whose prerequisites are complete / whose depended-on facts exist; update the list with TodoWrite (mark steps already satisfied by facts as completed). Do not re-dispatch steps already pending/in_progress in the list.")
	return b.String()
}

// renderDoneIntents surfaces the intent(s) whose completion triggered this round
// so the planner looks first at their fresh yields (in the situation below) before
// deciding whether a new direction opened up. Empty for non-completion wakes.
func renderDoneIntents(ids []int64) string {
	if len(ids) == 0 {
		return ""
	}
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = fmt.Sprintf("#%d", id)
	}
	return "\n\n[The intent(s) that just completed and triggered this round]: " + strings.Join(parts, ", ")
}

// renderGraphOverview folds the pre-computed graph_overview snapshot into the
// wake-up prompt so the planner starts each round with the full situation in
// hand — saving the round-trip it would otherwise spend calling the tool. It is
// the exact same JSON graph_overview would return; deeper detail is still one
// tool call away (node_detail / list_facts / …).
func renderGraphOverview(data map[string]any) string {
	b, err := json.Marshal(data)
	if err != nil {
		return "" // fall back to the model calling graph_overview itself
	}
	return "\n\n[This round's situation (graph_overview prefetched — identical to what calling that tool returns; call node_detail/list_facts etc. on demand for deeper detail)]:\n" + string(b)
}

// plannerDefaultTmpl is the built-in EDITABLE body (section [A]) of the planner prompt,
// seeded into agent_prompts. Goal is a {{.Goal}} template var; the artifact-output-spec
// tail is code-owned (artifactSpec) and appended by plannerSystem after rendering.
const plannerDefaultTmpl = `You are the "planner" of an authorized penetration testing system. You are woken frequently (every time the graph changes). Your job: read the situation, judge the goals, and add exploration intents **only when a genuinely uncovered new direction exists**.

Task goal: {{.Goal}}

⚠️ **Producing 0 intents is a legitimate, normal outcome — but only with a [specific justified reason]; it is NOT a "dispatch fewer to be safe" default posture.** You should produce 0 intents only when:
- **Already covered**: every direction you can think of is already covered by open / running / recent_done intents — re-generating an existing intent (or rewording it) is a serious error; or
- **Waiting on dependencies**: the next step depends on output from a [currently running work] that hasn't produced it yet — then you should [wait for those works to finish and plan at the next wake-up after the graph updates]; dispatching now leaves downstream workers missing prerequisites that don't exist yet, spinning uselessly.
Conversely: if there IS a [new direction covered by no intent and not dependent on a running work], or [the goal is unmet and untested surface remains in scope], do NOT hold back just because "0 intents is common" — dispatch what should be dispatched. Don't use 0 intents as a lazy default.

Decision process (each wake-up):
1. **The complete situation is attached below this prompt (it IS the graph_overview result — no need to call it again)**: task (**original task title+goal**, the root node), asset counts, goals and their status, open/running/recent_done intents, sites_without_endpoints, findings (**confirmed vulnerabilities** count), facts (**exploration facts/conclusions** count — a different kind from findings), recent_facts (most recent facts as {id, summary, confidence?}, including **negative conclusions** like "port closed / not injectable" — don't generate intents for already-proven dead ends; but a negative conclusion with confidence=inferred is only an [inference] — weak evidence, not settled fact, so if that direction is critical to the goal it may deserve one re-check intent). **The exploration nodes here (goals/intents/facts/findings) belong only to THIS task** (never another task's goals); **the asset graph is shared globally** (one graph across tasks — asset counts are global in-scope data, not task-private). Only when deeper detail is needed, call on demand: list_facts for all facts, list_findings for all findings, **node_detail(id)** for one node's full evidence/detail (lists/recent_facts give only summaries).
   - open_intents / running_intents / recent_done_intents — "which directions already have intents covering them / already tried." Each intent also carries **parents (upstream: which facts/intents it derived from) and yields (downstream: which facts/findings it produced)** — this is the exploration graph's **lineage**; use it to understand "which facts came from which direction, and whether they can be synthesized into a new direction." Each fact in recent_facts carries **from_intent** (which intent produced it).
   - sites_without_endpoints / findings — "which directions [may] need exploration."
   - Only when you need details of a slice, call **on demand**: list_assets (pull mode: keyword search via q, plus type/company_id/task_id filters, limit/offset paging; or fetch directly by id/ids), asset_neighbors, list_findings. The asset graph is globally shared — don't pull the whole thing by default. Assets may include assets unrelated to this task; when they appear, ignore the unrelated ones.
2. Judge goals (core duty): graph_overview's goals field already carries goals and status; for an unmet goal proven by some finding/fact, call prove_goal(goal_id, evidence_id, reason) to mark it met. **When the goal you mark via prove_goal happens to be the last unfinished one, the system automatically judges the whole task complete — no need to call goal_met yourself** — wrap-up should be driven by per-goal prove_goal calls.
   ⚠️ **Quantified-acceptance check (never stamp early)**: if a goal carries a [quantifiable acceptance condition] (e.g., "capture N flags / N vulnerabilities", "obtain some privilege / specific sensitive data", "reach a conclusion covering a given set of assets/endpoints"), then before prove_goal (or any form of wrap-up) you **MUST check the measured situation in graph_overview above** (findings count, relevant facts, whether the corresponding assets all have conclusions). If the measurement **falls short**, you are **forbidden** to mark the goal met — dispatch intents to close the gap instead — and you **must not** stamp it early on grounds of "the main part is done / mostly achieved / the core goal is taken," nor may you use goal_met to bypass this check. Example: if the goal requires "capture 3 flags" and the graph proves only 1, the goal is **unmet** — keep dispatching supplementary intents; do not mark complete.
2.5. **(Optional, only at the very start, extremely lightweight) probing to understand**: you do have execution ability like Bash, but its **only legitimate use** is this — when **the graph has almost no facts yet** (recent_facts basically empty, task just started) and the situation alone can't make the initial intents concrete, you may do a **tiny amount of read-only** probing of the target (e.g., 1–2 curls to see the homepage/fingerprint) to produce more precise **initial intents**.
   ⚠️ **Remember your role boundary: you are the "planner," not the "executor." Everything you do here exists only to [generate/articulate intents] — never to [do the work inside plan].** The **only legitimate product of probing is a more precise intent description** — never the discovery, verification, or exploitation of a vulnerability, and never enumerated endpoints/directories/parameters. Any "let me quickly test/confirm this too" impulse is out of bounds: that is the worker's job in the work phase — you just **write it as an intent and dispatch it**.
   **Three hard boundaries — hold them**:
   - **Once the graph contains any worker-produced fact (facts>0 / recent_facts non-empty), you are FORBIDDEN from probing yourself.** All judgment then rests on existing facts; this round's output can only be "dispatch new intents" or "end the round." When you see a lead you want to dig into, **the correct response is to dispatch an intent so a worker checks it — never to curl it yourself**.
   - Even at the start, probe **at most a few times (≤3) then stop**, only enough to articulate the initial intents; **never** slide into enumerating endpoints/directories one by one, trying ids one by one, decoding base64 chains, re-probing the same interface, or any injection/authorization/vulnerability testing or verification — **all of that is heavy worker work**, it is the content of the intents you generate, not something you do yourself. The moment you notice you are "digging to verify" rather than "quickly setting direction," stop immediately and write the rest as intents.
   - Probing only helps you "think clearly" — it **produces no intents itself**; what can be judged from existing facts/situation needs no probing at all.
3. **Decide whether to add exploration directions (be restrained)**: an intent is an [open exploration direction], not a fixed type/menu — combine **known facts, assets, and the task goal** and judge for yourself "to get closer to the goal, which valuable, still-uncovered directions remain." Compare each direction against open_intents + running_intents + recent_done_intents:
   - Direction already covered by an open or running intent → **do not generate** (it's being handled).
   - Direction already tried in recent_done_intents (even without yields) → **do not retry as-is**. Treat it as a [blocked route]: re-dispatch only when a [materially new mechanism] appears — a new fact, new asset, new parameter, or a clearly different approach/construction — and the new intent's summary must state "how this differs from last time." **Merely rewording, or "maybe it'll work this time," is not a new mechanism — retries are forbidden.** Conversely, if a negative conclusion is weak evidence (confidence=inferred) and the direction is critical to the goal, dispatching [one re-check intent] to prove or disprove it is legitimate (that IS a new reason).
   - Generate only for [brand-new directions currently covered by no intent].
   - All known directions already covered by existing intents → **generate nothing; end the round directly.**
   - **Keep routes diverse — don't converge onto one too early**: while the goal is unmet, if existing intents all cluster on [the same attack route / same kind of entry] and a [fundamentally different] uncovered direction exists (another entry surface, another asset class, another exploit chain), prefer adding one divergent direction rather than piling a synonymous intent on the same line. Ideally 2–3 independent, mechanically-distinct routes stay alive at once (e.g., "via the upload chain" AND "via auth bypass"); concentrate resources on one only after it produces evidence of [approaching the goal]. Judge diversity by substantive difference, not wording. (This doesn't conflict with "0 intents is normal": only add when a fundamentally different, uncovered direction actually exists; if the blank-looking route is already covered, it's still 0 intents.)
3.5. **Serial exploit chains: dispatch step by step — don't split into parallel at once.** Many exploits form a **strongly-dependent serial chain** (e.g., step 1 → 2 → 3) where each step needs the previous step's **actual output**. In that case:
   - **Do not** dispatch steps 1, 2, 3 as multiple parallel intents at once (downstream workers can't get prerequisite outputs that don't exist yet — they'd just repeat/spin);
   - **Use TodoWrite to record the whole chain as a todo** (one item per step), then **dispatch only the step whose prerequisites are satisfied this round** (usually the first);
   - Once that step produces a fact, the next wake-up (your prompt will carry your todo list) dispatches the next step, marking satisfied steps completed;
   - Don't split "the same thing" into two (e.g., "confirm the trigger point" and "trigger the trigger point" are the same step). **Parallel exploration dimensions** (e.g., enumerating several unrelated endpoints at once) are what multiple parallel intents are for.
4. Submit the filtered new directions from step 3 with **one** add_intent call (an intents array, at most the 4 highest-value; don't call it once per item):
   - summary: one free-form sentence describing the direction (what to do + why), in natural language — **do not force it into a fixed category**. Write the direction clearly in the summary; dedup relies mainly on comparing it against existing intents.
   - asset_ids: the **target asset ids this direction will test/attack** (**pass whenever possible**, 0/1/many; these are asset ids from list_assets). Whenever a direction revolves around concrete assets (a site/endpoint/parameter/host) you **must pass them** — they mark "which targets this exploration hits," used for coverage dedup and linking the intent into the asset chain; pass all when it spans multiple assets. Leave empty only for pure global recon genuinely lacking concrete target assets.
   - parent_ids: which **upstream nodes** this direction was synthesized from (optional, 0/1/many). **When multiple facts combine into one new intent, pass all those fact ids**; also pass the id of an upstream intent/finding it derives from; leave empty for top-level brand-new directions.


Better to generate nothing than to repeat or pad. Concise, restrained, efficient.`

func plannerSystem(goal, workDir string) string {
	body := renderSystem("planner", plannerDefaultTmpl, PlannerVars{Goal: goal, Now: time.Now().Format("2006-01-02 15:04:05 MST")})
	return body + artifactSpec(workDir)
}

// Plan runs one planning round. emit, if non-nil, receives the planner's execution
// steps (so users can see how it reads the situation and judges goals — the
// planner is the intent generator and was previously a black box). Returns whether
// the planner judged the goal met.
// doneIntents carries the ids of the intent(s) whose completion triggered this
// round (may be several — the engine debounces a burst; empty for non-completion
// wakes). They are surfaced in the prompt so the planner focuses on the fresh
// yields of what just finished.
func (p *Planner) Plan(ctx context.Context, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, goal string, doneIntents []int64, emit func(db.Activity)) (met bool, reason string, err error) {
	tsx := NewToolSet(ts, "planner")
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetTaskID(taskID)
	tsx.killWork = p.killWork   // enable kill_work tool (nil = unavailable)
	tsx.steerWork = p.steerWork // enable steer_work tool (nil = unavailable)
	if origin, _ := ts.OriginFactID(); origin > 0 {
		tsx.SetOwnerNode(origin) // planner-side anchors default to the task root (origin fact)
	}
	// domain tools + base default toolset (Read/Write/Edit/MultiEdit/LS/Glob/Grep/Bash)
	base := append(tsx.PlannerTools(), actool.DefaultTools()...)
	tools, def, cleanup := AugmentTools(ctx, "planner", base)
	defer cleanup()
	// Put the key situation (just-finished intents + prefetched full graph) into the
	// system prompt instead of the user input: the system section is never compacted,
	// so the situation stays present across long rounds; it's fixed within a round so
	// it also benefits from the system cache. It lands after the instructions and
	// before the deferred-tools block (deferredSystem keeps that block last).
	situational := renderDoneIntents(doneIntents) + renderGraphOverview(tsx.graphOverviewData())
	// Task-level deadline / endgame mode (injected via ctx, see taskclock.go). In the
	// endgame round the task-timeout planner wrap-up text is injected into system as
	// [this round's operating instruction] so it only does final goal judging — no new intents.
	tc := taskClockFrom(ctx)
	if tc.Final {
		situational += "\n\n[Task endgame wrap-up (special instruction for this round, overrides the normal planning flow above)]: " + resolveTaskTimeoutWrapup("planner")
	}
	system, boundary := deferredSystem(plannerSystem(goal, p.workDir)+situational, def)
	// The planner has no wall-clock budget of its own; when a deadline exists, clamp
	// MaxDuration to the remainder so a running round enters wrap-up at task time-out
	// (timeout → task-timeout text, steps → per-run text).
	maxDur, clamped := clampMaxDuration(tc.DeadlineUnix, 0)
	settle := wrapupSettlement("planner", nil)
	if tc.DeadlineUnix > 0 {
		settle = wrapupSettlementForTask("planner", nil, clamped)
	}
	opts := agentcore.Options{
		Provider:        p.prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,
		EnableWebFetch:  true, // route through the recording proxy for evidence; load its CA to verify MITM-resigned HTTPS certs
		WebFetchProxy:   p.proxyAddr,
		WebFetchCACert:  p.proxyCACert,
		// Web search (optional). ddgs needs no key; brave-free needs BraveKey; tavily needs TavilyKey.
		// WebSearchProxy is an independent egress proxy (http/https/socks5), unrelated to the traffic-recording MITM proxy; empty = direct.
		EnableWebSearch:    p.webSearch.Enabled,
		WebSearchBackend:   p.webSearch.Backend,
		BraveSearchAPIKey:  p.webSearch.BraveKey,
		TavilySearchAPIKey: p.webSearch.TavilyKey,
		WebSearchProxy:     p.webSearch.Proxy,
		BashEnv:            proxyEnv(p.proxyAddr, p.proxyCACert), // Bash subcommands default to the proxy + trust its CA
		MaxTurns:           p.maxTurns,                           // 0 = unlimited (configurable in agent management)
		MaxDuration:        maxDur,                               // 0=unlimited; with a deadline = time remaining until it
		Compaction:         compactionConfig(p.window),
		// Planning todos shared across wake-ups: serial chains persist across rounds (the session is new each time, the store is not).
		Todos: p.todoFor(ts.ID()),
		// Hitting THIS round's step budget → the SDK runs wrap-up: land the conclusions
		// already figured out (the add_intents that should go, the prove_goals that can
		// be proven, serial chains into TodoWrite) rather than stopping planning — the
		// planner gets woken again later anyway.
		// When clamped (squeezed by the task deadline) use PromptByReason instead (see wrapupSettlementForTask).
		Settlement: settle,
	}
	if p.tx != nil { // persist raw LLM conversation; one accumulating file per task's planner
		opts.Transcript = p.tx
		opts.SessionID = fmt.Sprintf("exp%d-planner", ts.ID())
	}
	// The situation (just-finished intents + full graph) was folded into the system
	// prompt above (compaction-proof, always present in-round). The user input here
	// keeps only the instruction + cross-wake-up todos (the todo list is the model's
	// own scratchpad, regenerable, fine in user).
	input := "The graph has changed — plan the next step: read the situation in the system prompt above and judge the goals. **If no uncovered new direction exists this round, just end it (producing 0 intents is normal and common, especially right after dispatching intents while waiting for worker output). NEVER call goal_met just to end the round — goal_met [immediately ends the entire task]; call it only when you have confirmed the goal is [truly achieved] (the goal result obtained / the goal vulnerability confirmed). If unmet, mark goals one by one with prove_goal — or simply call nothing and end the round.**" +
		renderPlannerTodos(opts.Todos.List())
	// With a deadline clamp, add a hard ctx backstop (soft budget + grace) so a stuck round cannot bypass the round-boundary soft timeout.
	runCtx := ctx
	if maxDur > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, maxDur+settleHardGrace)
		defer cancel()
	}
	_, _, err = captureRun(runCtx, opts, input,
		func(r db.Activity) {
			if emit != nil {
				r.Worker = "planner" // planner activity has no intent_id (it generates them)
				emit(r)
			}
		})
	return tsx.GoalMet, tsx.Reason, err
}
