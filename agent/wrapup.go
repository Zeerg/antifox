package agent

import (
	"strings"

	"antifox/engine/harness"
)

// Wrap-up prompts (wrap-up / settlement prompt): when an agent is terminated for
// [steps exhausted (MaxTurns)] or [timeout (run_seconds/MaxDuration)], the SDK's
// settlement phase injects this prompt so the agent first stores identified-but-
// unwritten content, then outputs a one-line summary — no unfinished tail.
//
// Each agent's wrap-up prompt can be overridden in the admin UI (stored in
// agents.wrapup_prompt); empty uses the built-in defaults here. Only the [prompt
// body] is editable; which tools are disabled and how many turns wrap-up itself
// gets are fixed code policy.

// WrapupOverride, if set, returns the stored wrap-up prompt for an agent key and
// whether a non-empty one exists. Wired by the server to the agents table (like
// PromptOverride for system prompts). nil / empty → the built-in default is used.
var WrapupOverride func(agentKey string) (string, bool)

// WrapupMaxTurnsOverride, if set, returns the admin-configured turn budget for the
// wrap-up phase of an agent and whether a positive one exists. Wired to the agents
// table. nil / ≤0 → the built-in per-agent default (wrapupTurnDefaults) is used.
var WrapupMaxTurnsOverride func(agentKey string) (int, bool)

// Built-in default wrap-up prompts, indexed by agent key. The worker reuses the
// historically hardcoded settleWrapUpPrompt (defined in worker.go); planner and
// mainagent each have their own; unmatched keys (custom agents) use the generic fallback.
var wrapupDefaults = map[string]string{
	"worker":    settleWrapUpPrompt,
	"planner":   plannerWrapUpDefault,
	"mainagent": mainAgentWrapUpDefault,
}

// wrapupTurnDefaults: built-in defaults for each agent's wrap-up phase [own] turn
// budget (admin values >0 override). The worker gets 4 since write-backs may take
// turns (record_fact/insert_assets); the rest get 5. Unmatched → genericWrapupTurns.
var wrapupTurnDefaults = map[string]int{
	"worker":    4,
	"planner":   5,
	"mainagent": 5,
}

const genericWrapupTurns = 5

const plannerWrapUpDefault = "Your planning turns for this round are nearly exhausted — note this is only [this round] ending; the system will wake you again to keep planning as the situation changes, this is not task termination, so you need not wrap up the whole plan here. Land the conclusions you already worked out this round — don't waste the round — but [do NOT pad intents just for wrap-up] (0 intents this round is still a perfectly normal result): (1) if you've judged exploration directions that [should be dispatched now], submit them in one add_intent batch (don't sit on decided intents); (2) for goals proven met by some finding/fact, call prove_goal to mark met (don't miss any); (3) if you identified a serial exploit chain needing steps, record it with TodoWrite so the next wake-up continues dispatching. Then end the round — no summary text needed."

const mainAgentWrapUpDefault = "Your turns are nearly exhausted — this interaction is ending. Do not start new exploration/actions. Output **one standalone plain-text sentence** summarizing current progress, key conclusions, and the suggested next step for the user."

const genericWrapUpDefault = "You are about to be terminated for budget exhaustion. First write back any completed-but-unstored results, then output **one standalone plain-text sentence** summarizing what you did and the key conclusions (this sentence is shown as the run's result)."

// WrapupDefault returns the built-in default wrap-up prompt for an agent key —
// used by the admin UI as the "restore default" value and empty-field placeholder.
func WrapupDefault(agentKey string) string {
	if d, ok := wrapupDefaults[agentKey]; ok {
		return d
	}
	return genericWrapUpDefault
}

// WrapupTurnsDefault returns the built-in wrap-up turn budget for an agent key —
// used by the admin UI as the "0 = default N" hint.
func WrapupTurnsDefault(agentKey string) int {
	if n, ok := wrapupTurnDefaults[agentKey]; ok {
		return n
	}
	return genericWrapupTurns
}

// resolveWrapup returns the effective wrap-up prompt: the DB override (if set and
// non-empty) over the built-in default.
func resolveWrapup(agentKey string) string {
	if WrapupOverride != nil {
		if t, ok := WrapupOverride(agentKey); ok && strings.TrimSpace(t) != "" {
			return t
		}
	}
	return WrapupDefault(agentKey)
}

// resolveWrapupTurns returns the effective wrap-up turn budget: a positive DB
// override over the built-in per-agent default.
func resolveWrapupTurns(agentKey string) int {
	if WrapupMaxTurnsOverride != nil {
		if v, ok := WrapupMaxTurnsOverride(agentKey); ok && v > 0 {
			return v
		}
	}
	return WrapupTurnsDefault(agentKey)
}

// wrapupSettlement builds the settlement config for an agent's run. Prompt and the
// turn budget are admin-editable per agent; disabled tools are code-owned policy so
// a user can't edit away the "stop probing" guardrail. Resolved fresh each run
// (reads DB live), so edits apply on the next run without a restart.
func wrapupSettlement(agentKey string, disabledTools []string) *harness.Settlement {
	return &harness.Settlement{
		Prompt:        resolveWrapup(agentKey),
		DisabledTools: disabledTools,
		MaxTurns:      resolveWrapupTurns(agentKey),
	}
}

// ---------- task-level timeout wrap-up text (see docs for the task-timeout design) ----------
//
// These are [two distinct sets] from the per-run wrap-up text: per-run means
// "this run's budget is used up"; task timeout means "the whole task is ending".
// Semantics are often opposite (especially planner: per-run says "don't stop,
// keep planning"; task timeout says "stop planning at the deadline, do the final
// judgment"). Only configured for worker/planner.

// WrapupTaskTimeoutOverride / …TurnsOverride: DB overrides for the task-timeout
// wrap-up text and turns (wired to agents.task_timeout_wrapup_prompt / _max_turns,
// worker/planner only).
var (
	WrapupTaskTimeoutOverride      func(agentKey string) (string, bool)
	WrapupTaskTimeoutTurnsOverride func(agentKey string) (int, bool)
)

var taskTimeoutWrapupDefaults = map[string]string{
	"worker":  workerTaskTimeoutDefault,
	"planner": plannerTaskTimeoutDefault,
}

const workerTaskTimeoutDefault = "**The entire task has hit its timeout limit and is ending** (not this run's budget — the whole exploration ran out of time). Last chance: (1) store [everything] you identified but haven't written back — new assets via insert_assets, conclusions/facts via record_fact, confirmed vulns via report_finding; (2) do not start any new commands/probes; (3) finally output **one standalone plain-text sentence** summarizing your key conclusions on this intent."

const plannerTaskTimeoutDefault = "**The entire task has hit its timeout limit and is ending** (not this round — the whole task is terminating). Based on [ALL] current facts and findings, make one final goal judgment: for each goal proven met by evidence, call prove_goal to mark it met (don't miss any). **Do not generate any new intents** (dispatched intents will no longer run anyway). End after judging — no summary text needed."

// TaskTimeoutWrapupDefault returns an agent's built-in task-timeout wrap-up text (for admin placeholder/reset-to-default).
func TaskTimeoutWrapupDefault(agentKey string) string {
	return taskTimeoutWrapupDefaults[agentKey] // unconfigured keys (mainagent/chat) return empty
}

// resolveTaskTimeoutWrapup: DB override (non-empty) > built-in default. An empty
// string means this agent has no task-timeout text (not worker/planner) — callers
// should then fall back to the per-run text.
func resolveTaskTimeoutWrapup(agentKey string) string {
	if WrapupTaskTimeoutOverride != nil {
		if t, ok := WrapupTaskTimeoutOverride(agentKey); ok && strings.TrimSpace(t) != "" {
			return t
		}
	}
	return TaskTimeoutWrapupDefault(agentKey)
}

func resolveTaskTimeoutTurns(agentKey string) int {
	if WrapupTaskTimeoutTurnsOverride != nil {
		if v, ok := WrapupTaskTimeoutTurnsOverride(agentKey); ok && v > 0 {
			return v
		}
	}
	return resolveWrapupTurns(agentKey) // default: reuse the per-run turns
}

// wrapupSettlementForTask builds settlement for a worker/planner run that is aware
// of the task deadline. See §5 of the design doc:
//   - clamped=true  → this run is squeezed by the task deadline: wrap-up by Timeout
//     = task deadline reached → task-timeout text; wrap-up by MaxTurns = steps ran out
//     inside the clamped window with minutes left → fall back to per-run text.
//   - clamped=false → task is far from deadline: both reasons use the per-run text
//     (i.e. degrades to wrapupSettlement).
//
// The PromptByReason handed to the harness picks at wrap-up time by the ACTUAL reason — no build-time mismatch.
func wrapupSettlementForTask(agentKey string, disabledTools []string, clamped bool) *harness.Settlement {
	perRun := resolveWrapup(agentKey)
	st := &harness.Settlement{
		Prompt:        perRun, // fallback (also the value for both reasons when non-clamped)
		DisabledTools: disabledTools,
		MaxTurns:      resolveWrapupTurns(agentKey),
	}
	if clamped {
		if tt := resolveTaskTimeoutWrapup(agentKey); tt != "" {
			st.PromptByReason = map[harness.TerminalReason]string{
				harness.ReasonTimeout:  tt,     // task deadline reached
				harness.ReasonMaxTurns: perRun, // steps ran out while task time remains
			}
			st.MaxTurns = resolveTaskTimeoutTurns(agentKey)
		}
	}
	return st
}
