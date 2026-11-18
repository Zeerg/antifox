---
name: report-generation
description: Editable content for penetration-test report generation — AI rewrite prompts and fixed skeletons (methodology/checklist/tools/standards/personnel), one file set per language. The report engine reads from disk on every generation, so edits take effect immediately.
---

# Report generation (editable content)

This skill stores the **editable content of penetration-test reports**, consumed by the Report Management generation pipeline. Edits take effect on the **next generation** — no restart or rebuild needed; if any file is missing or corrupt, the engine falls back to built-in defaults.

## Structure

- `prompts/report-level.tmpl` — AI prompt for report-level narrative (background / service result / remediation conclusion / hit checklist items).
- `prompts/vuln-narrative.tmpl` — AI prompt for rewriting a single vulnerability (description / reproduction / risk / remediation / CVSS).
- `skeleton/<lang>/methodology.json` — Section 2.2 test methodology: `{intro, phases:[{name,desc}]}`.
- `skeleton/<lang>/checklist.json` — Section 2.3 test checklist: `[{category,name,desc}]`. Items the AI marks as hit render as "fail".
- `skeleton/<lang>/tools.json` — Section 2.4 test tools: `[{name,desc}]`.
- `skeleton/<lang>/standards.json` — Section 2.5 referenced standards: `["..."]`.
- `skeleton/<lang>/personnel.json` — Section 2.1 default testers: `[{name,role,contact}]` (user-entered values in report settings take precedence).

Language directories: `zh-CN` (Simplified) / `zh-TW` (Traditional) / `en-US` (English).

## Prompt template variables

Prompts are Go `text/template`; `===USER===` separates the system and user sections:

- Report level: `{{.Company}}` `{{.Project}}` `{{.Client}}` `{{.FindingsList}}` `{{.LangDirective}}`
- Vulnerability level: `{{.Company}}` `{{.VulnClass}}` `{{.Severity}}` `{{.Summary}}` `{{.PoC}}` `{{.LangDirective}}`

`{{.LangDirective}}` injects the target-language directive (Simplified / Traditional / English), so one prompt serves all three languages.
