// Package report renders engine results for humans and machines.
package report

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/kviatkovsky/tfplan-risk/engine"
	"github.com/kviatkovsky/tfplan-risk/plan"
)

// Renderer writes a result in one output format.
type Renderer interface {
	Render(ctx context.Context, w io.Writer, r engine.Result) error
}

// Options configure renderers. Each renderer uses the fields relevant to it.
type Options struct {
	// Color enables ANSI colors (table only).
	Color bool
	// ToolVersion is embedded in machine-readable output.
	ToolVersion string
}

// Formats lists the supported --format values.
var Formats = []string{"table", "json"}

// New returns the renderer for format.
func New(format string, opts Options) (Renderer, error) {
	switch format {
	case "table":
		return Table{Color: opts.Color}, nil
	case "json":
		return JSON{ToolVersion: opts.ToolVersion}, nil
	}
	return nil, fmt.Errorf("unknown format %q (want one of: %s)", format, strings.Join(Formats, ", "))
}

// actionOrder is the order in which plan change counts are listed.
var actionOrder = []plan.Action{
	plan.ActionCreate, plan.ActionUpdate, plan.ActionReplace, plan.ActionDelete, plan.ActionForget,
}

// changeSummary renders e.g. "2 to create, 1 to replace".
func changeSummary(counts map[plan.Action]int) string {
	var parts []string
	for _, a := range actionOrder {
		if n := counts[a]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d to %s", n, a))
		}
	}
	if len(parts) == 0 {
		return "no changes"
	}
	return strings.Join(parts, ", ")
}

func active(fs []engine.Finding) []engine.Finding {
	return slices.DeleteFunc(slices.Clone(fs), func(f engine.Finding) bool { return f.Suppressed })
}
