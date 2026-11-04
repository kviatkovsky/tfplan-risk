package report

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/kviatkovsky/tfplan-risk/engine"
	"github.com/kviatkovsky/tfplan-risk/rules"
)

// Table renders an aligned, optionally colored terminal report.
type Table struct {
	Color bool
}

const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
	ansiRed    = "\x1b[31m"
	ansiYellow = "\x1b[33m"
	ansiCyan   = "\x1b[36m"
)

var severityColor = map[rules.Severity]string{
	rules.SeverityCritical: ansiBold + ansiRed,
	rules.SeverityHigh:     ansiRed,
	rules.SeverityMedium:   ansiYellow,
	rules.SeverityLow:      ansiCyan,
	rules.SeverityInfo:     ansiDim,
}

// planAddress labels plan-level findings, which have no resource address.
const planAddress = "(plan)"

// Render implements Renderer.
func (t Table) Render(ctx context.Context, w io.Writer, r engine.Result) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	bw := bufio.NewWriter(w)
	findings := active(r.Findings)

	addrWidth, actionWidth := 0, 0
	for _, f := range findings {
		addrWidth = max(addrWidth, len(address(f)))
		actionWidth = max(actionWidth, len(f.Action))
	}

	if len(findings) == 0 {
		fmt.Fprintln(bw, t.paint(ansiBold, "No risky changes found."))
	}
	for _, f := range findings {
		// Pad before coloring: escape codes would otherwise break alignment.
		sev := fmt.Sprintf("%-8s", strings.ToUpper(f.Severity.String()))
		fmt.Fprintf(bw, "%s  %-*s  %-*s  %s %s\n",
			t.paint(severityColor[f.Severity], sev),
			addrWidth, address(f),
			actionWidth, strings.ToUpper(string(f.Action)),
			f.Message,
			t.paint(ansiDim, "["+f.RuleID+"]"))
	}

	fmt.Fprintln(bw)
	summary := "Plan: " + changeSummary(r.Summary.Changes) + "."
	if r.Summary.Suppressed > 0 {
		summary += fmt.Sprintf(" %d finding(s) suppressed by config.", r.Summary.Suppressed)
	}
	fmt.Fprintln(bw, t.paint(ansiDim, summary))

	score := fmt.Sprintf("Risk score: %d/100", r.Score)
	if r.Summary.HasFindings {
		score += " (max severity: " + r.Summary.MaxSeverity.String() + ")"
	}
	fmt.Fprintln(bw, t.paint(ansiBold, score))
	if r.Gate.Failed {
		fmt.Fprintln(bw, t.paint(ansiBold+ansiRed, "FAIL: "+r.Gate.Reason))
	}
	return bw.Flush()
}

func (t Table) paint(code, s string) string {
	if !t.Color {
		return s
	}
	return code + s + ansiReset
}

func address(f engine.Finding) string {
	if f.Address == "" {
		return planAddress
	}
	return f.Address
}
