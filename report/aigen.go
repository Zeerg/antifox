package report

// AI narrative layer: turns thin findings ({vulnclass, severity, summary, poc})
// into professional Chinese report prose (description / test process / risk /
// remediation + CVSS) via the platform's active LLM profile. Report-level and
// per-finding calls run concurrently. All AI output is JSON; parse failures fall
// back to the raw finding fields (assembly in build.go), so generation never
// hard-fails on a bad LLM response.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"antifox/agent"
	"antifox/db"
	"antifox/engine/agentcore"
	acperm "antifox/engine/permission"
	actool "antifox/engine/tool"
)

// complete runs one system+user → text completion on the active LLM profile.
// Returns an error when no profile is configured (caller falls back to skeleton).
func complete(ctx context.Context, pg *db.DB, system, user string, maxTokens int) (string, error) {
	// The report/enrichment role can be bound to a specific LLM (role division) —
	// unbound means the global active profile. This lets enrichment run on a
	// stronger model (e.g. Claude) without touching the pentest agents' model.
	p, err := pg.ReportRoleProfile()
	if err != nil || p == nil || strings.TrimSpace(p.APIKey) == "" {
		return "", fmt.Errorf("no active LLM profile")
	}
	cfg := agent.ConfigFrom(p.Format, p.Model, p.BaseURL, p.APIKey, p.Proxy)
	cfg.RatePerSecond, cfg.RatePerMinute = p.RatePerSecond, p.RatePerMinute
	cfg.ReasoningEffort = p.ReasoningEffort
	prov, err := cfg.NewProvider()
	if err != nil {
		return "", err
	}
	cctx, cancel := context.WithTimeout(ctx, 6*time.Minute)
	defer cancel()
	out, err := agentcore.Run(cctx, agentcore.Options{
		Provider:       prov,
		SystemPrompt:   []string{system},
		Tools:          []actool.CoreTool{}, // non-nil empty → no default tools offered
		PermissionMode: acperm.ModeBypass,
		MaxTurns:       1,
		MaxTokens:      maxTokens,
	}, user)
	if err != nil {
		return "", err
	}
	return cleanJSON(out), nil
}

// ---------------------------------------------------------------------------
// Report-level narrative (background / service result / remediation / checklist)
// ---------------------------------------------------------------------------

type reportLevelOut struct {
	Background            []string `json:"background"`
	ServiceResult         string   `json:"service_result"`
	RemediationConclusion string   `json:"remediation_conclusion"`
	ChecklistHits         []string `json:"checklist_hits"`
}

const sysReportLevel = "You are a senior penetration-test report writer at %s, skilled at professional, client-readable, technically rigorous reports. Output strict JSON only — no markdown code blocks."

const userReportLevel = `Write the report-level overview content from the following project and findings list.

Project name: %s
Client name: %s
Findings list:
%s
Requirements (professional deliverable tone; avoid phrasing like "this test was conducted today"):
- background: string array, 2 paragraphs. First states the client engaged %s for a penetration test and its objectives; second states the scope and the combined manual+tooling approach. 60-130 chars each.
- service_result: 1 paragraph summarizing which systems were tested and the count/severity distribution of findings.
- remediation_conclusion: 1 paragraph of remediation conclusion (first-round tests default to all-pending; recommend prompt remediation and retesting).
- checklist_hits: string array of standard checklist item names inferred from the finding types, in the report's language (e.g. "SQL Injection", "Unauthorized Access", "Authentication Bypass", "Sensitive Information Disclosure", "Command Injection", "Cross-Site Scripting (XSS)", "Vertical Privilege Escalation").

Output JSON only: {"background":["...","..."],"service_result":"...","remediation_conclusion":"...","checklist_hits":["...","..."]}`

// reportLevelPromptData feeds the editable report-level prompt template.
type reportLevelPromptData struct {
	Company, Project, Client, FindingsList, LangDirective string
}

// vulnPromptData feeds the editable per-vuln prompt template.
type vulnPromptData struct {
	Company, VulnClass, Severity, Summary, PoC, LangDirective string
}

func aiReportLevel(ctx context.Context, pg *db.DB, in *GenInput, sk *skillContent) reportLevelOut {
	var out reportLevelOut
	loc := normLocale(in.Locale)
	var sb strings.Builder
	// Feed the full test scope / target systems as narrative context (via the
	// FindingsList channel — both the skill and fallback prompt paths carry it) so
	// the overview can name specific systems — while the cover project name stays
	// short (ProjectName) and unaffected.
	if sc := strings.TrimSpace(in.Scope); sc != "" {
		fmt.Fprintf(&sb, "[Test scope / target systems] %s\n\n[Findings list]\n", truncateRune(sc, 1500))
	}
	for _, f := range in.Findings {
		fmt.Fprintf(&sb, "- [%s] %s：%s\n", severityName(loc, f.Severity), nz(f.VulnClass, "-"), truncateRune(f.Summary, 80))
	}
	dir := outputLangDirective(loc)
	data := reportLevelPromptData{Company: in.CompanyName, Project: in.ProjectName, Client: in.ClientName, FindingsList: sb.String(), LangDirective: dir}
	sys := renderPrompt(sk.reportLevelSys, data)
	if sys == "" {
		sys = fmt.Sprintf(sysReportLevel, in.CompanyName)
	}
	user := renderPrompt(sk.reportLevelUser, data)
	if user == "" {
		user = fmt.Sprintf(userReportLevel, in.ProjectName, in.ClientName, sb.String(), in.CompanyName) +
			"\n\nOutput-language requirement: " + dir
	}
	raw, err := complete(ctx, pg, sys, user, 4000)
	if err != nil {
		return out
	}
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

// ---------------------------------------------------------------------------
// Per-finding narrative (description / test process / risk / remediation / CVSS)
// ---------------------------------------------------------------------------

type Enrichment struct {
	Title        string            `json:"title"`  // concise professional vuln name
	Target       string            `json:"target"` // affected host / URL, extracted from evidence
	Description  []string          `json:"description"`
	Module       string            `json:"module"`
	TestProcess  []procBlock       `json:"test_process"`
	RiskAnalysis []string          `json:"risk_analysis"`
	Remediation  []string          `json:"remediation"`
	CVSSScore    float64           `json:"cvss_score"`
	CVSSVector   string            `json:"cvss_vector"`
	CVSSMetrics  map[string]string `json:"cvss_metrics"`
}

const sysVuln = "You are a senior penetration-test report writer at %s. Rewrite raw vulnerability records into DELIVERABLE-grade report prose — as a senior consultant writing to a client: concise, professional, factual. Output strict JSON only — no markdown code blocks, no pleasantries, disclaimers, or boilerplate. HTTP requests/commands/responses must be quoted verbatim, never fabricated."

const userVuln = `Rewrite the following vulnerability into report prose. Core requirement: CONCISE, SPECIFIC, RESTRAINED — less is more; no padding, no filler, no truisms; every sentence must be real information about THIS vulnerability on THIS target.

Vulnerability type/raw name: %s
Severity: %s
Raw summary:
%s
Raw reproduction/evidence:
%s

Field requirements:
- title: a canonical, professional vulnerability name (10-26 chars). If the raw name is already canonical (incl. a CVE), keep or lightly adjust — do not copy the summary.
- target: affected host or URL, extracted from summary/evidence; empty string when undeterminable.
- description: 1 paragraph, 2-3 sentences — what the vulnerability is, where it lives, and its root cause. No OWASP taxonomy dumping, no remediation recap, no vague filler.
- module: the owning functional module (short, e.g. "external account login / unauthenticated API").
- risk_analysis: 2-4 items, one sentence each — concrete consequences of THIS vulnerability on THIS target (who can do what, reach which data or privileges). No boilerplate.
- remediation: 2-4 items, one sentence each — specific and actionable (which point to change, how, what to verify). No platitudes.
- CVSS 3.1: cvss_score (number), cvss_vector (e.g. "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), cvss_metrics (the eight English values).

Do not output test_process — the reproduction is generated by the platform directly from real evidence; return "test_process":[].

Output JSON only: {"title":"...","target":"...","description":["..."],"module":"...","test_process":[],"risk_analysis":["..."],"remediation":["..."],"cvss_score":0,"cvss_vector":"...","cvss_metrics":{...}}`

func aiVulnNarrative(ctx context.Context, pg *db.DB, locale string, f FindingInput, companyName string, sk *skillContent) Enrichment {
	var out Enrichment
	loc := normLocale(locale)
	dir := outputLangDirective(loc)
	data := vulnPromptData{Company: companyName, VulnClass: nz(f.VulnClass, "-"), Severity: severityName(loc, f.Severity), Summary: nz(f.Summary, "-"), PoC: nz(f.PoC, "-"), LangDirective: dir}
	sys := renderPrompt(sk.vulnSys, data)
	if sys == "" {
		sys = fmt.Sprintf(sysVuln, companyName)
	}
	user := renderPrompt(sk.vulnUser, data)
	if user == "" {
		user = fmt.Sprintf(userVuln,
			nz(f.VulnClass, "-"), severityName(loc, f.Severity), nz(f.Summary, "-"), nz(f.PoC, "-")) +
			"\n\nOutput-language requirement: " + dir
	}
	// Ground the PROSE (description / risk / remediation) in the ACTUAL work transcript
	// (real tool calls / requests / responses / analysis recorded when the finding was
	// made) so it reflects what actually happened, not an expansion of the one-liner.
	if tr := strings.TrimSpace(f.Transcript); tr != "" {
		user += "\n\n=== REAL work transcript when this finding was discovered (tool calls/requests/responses/analysis) ===\n" +
			"Base description/risk_analysis on real observations in the transcript; never fabricate or guess content not present.\n\n" + tr
	}
	// PROSE-ONLY, ALWAYS. We never ask the model to reconstruct a verbatim test_process:
	// that large generation is slow and unreliable (many models time out / return nothing
	// on it) AND risks fabricating a PoC (the user's key pain). Instead test_process is
	// filled DETERMINISTICALLY below from REAL evidence — the agent's in-situ reproduction if
	// present, else the raw PoC. The model only writes prose (title/desc/module/risk/
	// remediation/CVSS), which is small, fast, and reliable on any model.
	if len(f.Reproduction) > 2 { // ""/"{}" carry nothing
		user += "\n\n=== Reproduction already recorded in-place by the test engine ===\n" +
			"This vulnerability's entry point/prerequisites/steps/provenance were recorded IN PLACE during testing and go straight into the report's test_process. You do NOT need to (and must not) rebuild test_process — return \"test_process\":[]."
	} else {
		user += "\n\n=== test_process is provided directly by real evidence ===\n" +
			"The test_process section is generated by the platform from REAL PoC/evidence verbatim. You do NOT need to (and must not) rebuild or fabricate test_process — return \"test_process\":[]."
	}
	user += "Focus on making title / description / module / risk_analysis / remediation and CVSS solid and professional, grounded in the summary and real transcript observations above; never fabricate content absent from the transcript."
	raw, err := complete(ctx, pg, sys, user, 4000)
	if err != nil {
		return out
	}
	_ = json.Unmarshal([]byte(raw), &out)
	// Fill test_process from REAL evidence, never the model's reconstruction: the agent's
	// in-situ reproduction wins; else the raw PoC (deterministic). This makes every consumer
	// (persisted enrichment → findings page UI, and the report) show real, non-fabricated
	// steps — and keeps the generation prose-only (small, reliable).
	if b := reproToBlocks(f.Reproduction, loc, nil); len(b) > 0 {
		out.TestProcess = b
	} else if len(out.TestProcess) == 0 && strings.TrimSpace(f.PoC) != "" {
		out.TestProcess = proofToBlocks(f.PoC)
	}
	return out
}

// EnrichFinding is the exported per-finding AI enrichment, shared by the report
// pipeline and the findings-management "AI analysis" endpoint. locale controls the
// output language (zh-CN | zh-TW | en-US); skillDir enables the editable
// report-generation prompt (falls back to the built-in prompt when unset/missing).
// Returns a zero Enrichment (not an error) when no LLM profile is configured —
// callers keep whatever raw fields the finding already has.
func EnrichFinding(ctx context.Context, pg *db.DB, skillDir, locale string, f FindingInput, companyName string) Enrichment {
	if strings.TrimSpace(companyName) == "" {
		companyName = pick(locale, "安全服务团队", "安全服務團隊", "Security Services Team")
	}
	sk := loadSkillContent(skillDir, locale)
	return aiVulnNarrative(ctx, pg, locale, f, companyName, sk)
}

// cleanJSON strips markdown fences and surrounding prose from an LLM response.
func cleanJSON(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "{"); i >= 0 {
		if j := strings.LastIndex(s, "}"); j > i {
			s = s[i : j+1] // strip leading AND trailing prose around the JSON object
		}
	}
	return s
}
