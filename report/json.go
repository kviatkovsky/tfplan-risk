package report

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/kviatkovsky/tfplan-risk/engine"
	"github.com/kviatkovsky/tfplan-risk/rules"
)

// JSONSchemaVersion is bumped on any breaking change to the JSON output.
// Adding fields is not breaking. See docs/json-output.md.
const JSONSchemaVersion = 1

// JSON renders the machine-readable report.
type JSON struct {
	ToolVersion string
}

type jsonReport struct {
	Version  int           `json:"version"`
	Tool     jsonTool      `json:"tool"`
	Plan     jsonPlan      `json:"plan"`
	Summary  jsonSummary   `json:"summary"`
	Gate     jsonGate      `json:"gate"`
	Findings []jsonFinding `json:"findings"`
}

type jsonTool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type jsonPlan struct {
	FormatVersion    string `json:"format_version"`
	TerraformVersion string `json:"terraform_version"`
}

type jsonSummary struct {
	Score       int            `json:"score"`
	MaxSeverity *string        `json:"max_severity"`
	Changes     map[string]int `json:"changes"`
	Findings    map[string]int `json:"findings"`
	Suppressed  int            `json:"suppressed"`
}

type jsonGate struct {
	FailOn   *string `json:"fail_on"`
	MaxScore *int    `json:"max_score"`
	Failed   bool    `json:"failed"`
	Reason   string  `json:"reason,omitempty"`
}

type jsonFinding struct {
	RuleID         string `json:"rule_id"`
	Severity       string `json:"severity"`
	Category       string `json:"category"`
	Address        string `json:"address"`
	Action         string `json:"action"`
	Message        string `json:"message"`
	Suggestion     string `json:"suggestion"`
	Suppressed     bool   `json:"suppressed"`
	SuppressReason string `json:"suppress_reason,omitempty"`
}

// Render implements Renderer.
func (j JSON) Render(ctx context.Context, w io.Writer, r engine.Result) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	out := jsonReport{
		Version: JSONSchemaVersion,
		Tool:    jsonTool{Name: "tfplan-risk", Version: j.ToolVersion},
		Plan:    jsonPlan{FormatVersion: r.FormatVersion, TerraformVersion: r.TerraformVersion},
		Summary: jsonSummary{
			Score:      r.Score,
			Changes:    map[string]int{},
			Findings:   map[string]int{},
			Suppressed: r.Summary.Suppressed,
		},
		Gate: jsonGate{
			MaxScore: r.Gate.MaxScore,
			Failed:   r.Gate.Failed,
			Reason:   r.Gate.Reason,
		},
		Findings: make([]jsonFinding, 0, len(r.Findings)),
	}
	if r.Summary.HasFindings {
		s := r.Summary.MaxSeverity.String()
		out.Summary.MaxSeverity = &s
	}
	for a, n := range r.Summary.Changes {
		out.Summary.Changes[string(a)] = n
	}
	for _, s := range rules.AllSeverities {
		out.Summary.Findings[s.String()] = r.Summary.Findings[s]
	}
	if r.Gate.FailOn != nil {
		s := r.Gate.FailOn.String()
		out.Gate.FailOn = &s
	}
	for _, f := range r.Findings {
		out.Findings = append(out.Findings, jsonFinding{
			RuleID:         f.RuleID,
			Severity:       f.Severity.String(),
			Category:       string(f.Category),
			Address:        f.Address,
			Action:         string(f.Action),
			Message:        f.Message,
			Suggestion:     f.Suggestion,
			Suppressed:     f.Suppressed,
			SuppressReason: f.SuppressReason,
		})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("encode json report: %w", err)
	}
	return nil
}
