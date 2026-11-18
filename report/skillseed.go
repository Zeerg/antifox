package report

// Seeds the editable report-generation skill on startup by materializing the
// built-in Go defaults (defaults.go) into files under <skillDir>/report-generation/.
// Only writes files that are MISSING, so user edits in the Skills page are never
// overwritten. This makes the built-in skeleton + prompts editable without ever
// requiring a hand-maintained copy: the Go defaults remain the single source, and
// this projects them to disk once so they can be tuned and hot-reloaded.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

var seedLocales = []string{"zh-CN", "zh-TW", "en-US"}

// SeedSkillFiles writes any missing report-generation skill files. Best-effort:
// returns the first write error but always attempts every file.
func SeedSkillFiles(skillDir string) error {
	if strings.TrimSpace(skillDir) == "" {
		return nil
	}
	base := filepath.Join(skillDir, reportSkillName)
	var firstErr error
	put := func(rel, content string) {
		if err := writeIfMissing(filepath.Join(base, rel), content); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	putJSON := func(rel string, v any) {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			return
		}
		put(rel, string(b)+"\n")
	}

	put("SKILL.md", skillMD)
	put(filepath.Join("prompts", "report-level.tmpl"), promptReportLevelTmpl)
	put(filepath.Join("prompts", "vuln-narrative.tmpl"), promptVulnTmpl)

	for _, loc := range seedLocales {
		d := filepath.Join("skeleton", loc)
		putJSON(filepath.Join(d, "methodology.json"), map[string]any{
			"intro": methodologyIntro(loc), "phases": methodology(loc),
		})
		putJSON(filepath.Join(d, "tools.json"), tools(loc))
		putJSON(filepath.Join(d, "standards.json"), standards(loc))
		putJSON(filepath.Join(d, "checklist.json"), checklist(loc))
		putJSON(filepath.Join(d, "personnel.json"), defaultPersonnel(loc))
	}
	return firstErr
}

// writeIfMissing creates parent dirs and writes content only when path is absent.
func writeIfMissing(path, content string) error {
	if _, err := os.Stat(path); err == nil {
		return nil // exists → keep user edits
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

const skillMD = `---
name: report-generation
description: Editable content for penetration-test report generation — AI rewrite prompts and the fixed skeleton (methodology/checklist/tools/reference standards/testers), split into per-language files. The report engine reads them from disk on every generation, so edits take effect immediately.
---

# Report generation (editable content)

This skill holds the **editable content for penetration-test reports**, consumed by the "Report Management" generation pipeline. Edits take effect on the **next generation** — no restart or rebuild needed; any missing or corrupt file falls back to the built-in default.

## Layout

- ` + "`prompts/report-level.tmpl`" + ` — AI prompt for report-level narrative (background / service results / remediation conclusion / matched checklist items).
- ` + "`prompts/vuln-narrative.tmpl`" + ` — AI prompt for rewriting a single vulnerability (description / reproduction / risk / remediation / CVSS).
- ` + "`skeleton/<lang>/methodology.json`" + ` — 2.2 test process: ` + "`{intro, phases:[{name,desc}]}`" + `.
- ` + "`skeleton/<lang>/checklist.json`" + ` — 2.3 test checklist: ` + "`[{category,name,desc}]`" + `. Items the AI marks as hit render as "fail".
- ` + "`skeleton/<lang>/tools.json`" + ` — 2.4 test tools: ` + "`[{name,desc}]`" + `.
- ` + "`skeleton/<lang>/standards.json`" + ` — 2.5 reference standards: ` + "`[\"...\"]`" + `.
- ` + "`skeleton/<lang>/personnel.json`" + ` — 2.1 tester defaults: ` + "`[{name,role,contact}]`" + ` (user-entered values in report settings win).

Language dirs: ` + "`zh-CN`" + ` (Simplified) / ` + "`zh-TW`" + ` (Traditional) / ` + "`en-US`" + ` (English).

## Prompt template variables

Prompts are Go ` + "`text/template`" + `, split into system and user sections by ` + "`===USER===`" + `:

- Report level: ` + "`{{.Company}}` `{{.Project}}` `{{.Client}}` `{{.FindingsList}}` `{{.LangDirective}}`" + `
- Vulnerability level: ` + "`{{.Company}}` `{{.VulnClass}}` `{{.Severity}}` `{{.Summary}}` `{{.PoC}}` `{{.LangDirective}}`" + `

` + "`{{.LangDirective}}`" + ` injects the target-language directive (zh-CN/zh-TW/en-US), so the prompt itself is language-agnostic and shared across all three locales.
`

const promptReportLevelTmpl = `You are a senior penetration-test report writer at {{.Company}}, skilled at professional, client-readable, technically rigorous reports. Output strict JSON only — no markdown code blocks.
===USER===
Write the report-level overview content from the following project and findings list.

Project name: {{.Project}}
Client name: {{.Client}}
Findings list:
{{.FindingsList}}
Requirements (professional deliverable tone; avoid phrasing like "this test was conducted today"):
- background: string array, 2 paragraphs. First states the client engaged {{.Company}} for a penetration test and its objectives; second states the scope and the combined manual+tooling approach. 60-130 chars each.
- service_result: 1 paragraph summarizing which systems were tested and the count/severity distribution of findings.
- remediation_conclusion: 1 paragraph of remediation conclusion (first-round tests default to all-pending; recommend prompt remediation and retesting).
- checklist_hits: string array of standard checklist item names inferred from the finding types, in the report's language (e.g. "SQL Injection", "Unauthorized Access", "Authentication Bypass", "Sensitive Information Disclosure", "Command Injection", "Cross-Site Scripting (XSS)", "Vertical Privilege Escalation").

Output JSON only: {"background":["...","..."],"service_result":"...","remediation_conclusion":"...","checklist_hits":["...","..."]}

Output-language requirement: {{.LangDirective}}
`

const promptVulnTmpl = `You are a senior penetration-test report writer at {{.Company}}. Rewrite raw vulnerability records into DELIVERABLE-grade report prose — as a senior consultant writing to a client: concise, professional, factual. Output strict JSON only — no markdown code blocks, no pleasantries, disclaimers, or generic boilerplate. HTTP requests/commands/responses must be quoted verbatim, never fabricated.
===USER===
Rewrite the following vulnerability into report prose. Core requirement: CONCISE, SPECIFIC, RESTRAINED — less is more; no padding, no filler, no truisms; every sentence must be real information about THIS vulnerability on THIS target.

Vulnerability type/raw name: {{.VulnClass}}
Severity: {{.Severity}}
Raw summary:
{{.Summary}}
Raw reproduction/evidence:
{{.PoC}}

Field requirements:
- title: a canonical, professional vulnerability name (10-26 chars, e.g. "External Account Auth Bypass Leading to Admin Takeover"). If the raw name is already canonical (incl. a CVE), keep or lightly adjust — do not copy the summary.
- target: affected host or URL, extracted from summary/evidence; empty string when undeterminable.
- description: 1 paragraph, 2-3 sentences. Cover only three things — what the vulnerability is, where it lives, and its root cause. No OWASP taxonomy dumping, no remediation recap, no vague filler.
- module: the owning functional module (short, e.g. "external account login / unauthenticated API").
- risk_analysis: 2-4 items, one sentence each — concrete consequences THIS vulnerability can cause on THIS target (who can do what, reach which data or privileges). Write fewer when there are no concrete consequences; no "may affect system security" boilerplate.
- remediation: 2-4 items, one sentence each — specific and actionable (which point to change, how, what to verify). No "raise security awareness" / "regular audits" platitudes.
- CVSS 3.1: cvss_score (number), cvss_vector (e.g. "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), cvss_metrics (the eight English values, e.g. {"AV":"Network","AC":"Low","PR":"None","UI":"None","S":"Unchanged","C":"High","I":"High","A":"High"}).

Do not output test_process — the reproduction is generated by the platform directly from real evidence; return "test_process":[].

Output JSON only: {"title":"...","target":"...","description":["..."],"module":"...","test_process":[],"risk_analysis":["..."],"remediation":["..."],"cvss_score":0,"cvss_vector":"...","cvss_metrics":{...}}

Output-language requirement: {{.LangDirective}}
`
