package report

// Retroactive finding extraction: pull confirmed vulnerabilities out of a task's
// agent transcript (synthesis + worker conclusions) that were described but never
// recorded via report_finding — so they can be back-filled as finding nodes.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"antifox/db"
)

// ExtractedFinding is one vuln pulled from the transcript.
type ExtractedFinding struct {
	VulnClass string `json:"vulnclass"`
	Severity  string `json:"severity"` // high|medium|low
	Summary   string `json:"summary"`
	Target    string `json:"target"`
	Evidence  string `json:"evidence"`
}

const sysExtract = "You are a senior penetration-testing expert. Extract CONFIRMED vulnerabilities from penetration-test execution/summary records. Output strict JSON only — no markdown code blocks. Evidence must preserve the real original text from the record; never fabricate."

const userExtract = `From the following penetration-test execution and summary records, extract all CONFIRMED vulnerabilities and PROVEN exposure/information-disclosure risks (no unverified guesses or negative conclusions).

Already-recorded findings (do not output these again):
%s
Execution/summary records:
%s

Requirements:
- One confirmed finding per entry: vulnclass (vulnerability type/name, e.g. "Stored XSS", "Hardcoded Credentials", "Unauthorized Access"), severity (critical|high|medium|low; critical = can directly cause total system/data compromise), summary (one-line summary including the affected object), target (affected host or URL), evidence (key PoC/request/command/response verbatim, preserving real content).
- Only extract vulnerabilities/exposures EXPLICITLY VERIFIED in the record; do not repeat semantic duplicates of the "already recorded" list above.
- **Also extract exposure/info-leak items**: unauthorized-reachable sensitive/admin/debug interfaces actually accessed with response evidence, exposed Swagger/API docs, published configs or backups/source, sensitive data leaks, etc. Assign severity by sensitivity (general info leak = low, unauthorized sensitive/admin interface = medium, account takeover or credential/secret disclosure = high). Still exclude pure speculation (version/CVE matching, "looks injectable"); a merely "existing interface" without unauthorized exposure does not count.
- If there are no new vulnerabilities/exposures, output an empty findings array.

Output JSON only: {"findings":[{"vulnclass":"...","severity":"high","summary":"...","target":"...","evidence":"..."}]}`

// ExtractFindings asks the active LLM to extract confirmed vulns from the
// transcript, excluding ones already recorded (passed as short labels).
func ExtractFindings(ctx context.Context, pg *db.DB, transcript string, existing []string) ([]ExtractedFinding, error) {
	if strings.TrimSpace(transcript) == "" {
		return nil, fmt.Errorf("no transcripts to analyze")
	}
	var ex strings.Builder
	for _, e := range existing {
		ex.WriteString("- ")
		ex.WriteString(e)
		ex.WriteString("\n")
	}
	if ex.Len() == 0 {
		ex.WriteString("(none)\n")
	}
	raw, err := complete(ctx, pg, sysExtract, fmt.Sprintf(userExtract, ex.String(), transcript), 4000)
	if err != nil {
		return nil, err
	}
	var out struct {
		Findings []ExtractedFinding `json:"findings"`
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, fmt.Errorf("failed to parse AI output")
	}
	return out.Findings, nil
}
