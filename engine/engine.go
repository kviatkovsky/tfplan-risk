// Package engine runs rules over a plan, applies configuration (severity
// overrides, disabled rules, ignores) and computes the risk score and gate.
package engine

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/kviatkovsky/tfplan-risk/config"
	"github.com/kviatkovsky/tfplan-risk/internal/glob"
	"github.com/kviatkovsky/tfplan-risk/plan"
	"github.com/kviatkovsky/tfplan-risk/rules"
)

// Finding is a rule finding plus its suppression state.
type Finding struct {
	rules.Finding
	Suppressed     bool
	SuppressReason string
}

// Gate is the pass/fail threshold.
type Gate struct {
	// FailOn is the minimum severity that fails; nil disables the check.
	FailOn *rules.Severity
	// MaxScore fails when the score is strictly above it; nil disables it.
	MaxScore *int
}

// GateResult records how the gate was evaluated.
type GateResult struct {
	Gate
	Failed bool
	Reason string
}

// Summary counts plan changes and active findings.
type Summary struct {
	Changes    map[plan.Action]int
	Findings   map[rules.Severity]int
	Suppressed int
	// MaxSeverity is the highest severity of an active finding; valid only
	// when HasFindings is true.
	MaxSeverity rules.Severity
	HasFindings bool
}

// Result is the outcome of a run.
type Result struct {
	FormatVersion    string
	TerraformVersion string
	// Findings are sorted by severity (desc), then address, then rule ID.
	Findings []Finding
	Score    int
	Summary  Summary
	Gate     GateResult
}

// Engine evaluates a configured rule set. Build one with New.
type Engine struct {
	reg      *rules.Registry
	disabled map[string]bool
	severity map[string]rules.Severity
	ignores  []config.Ignore
	gate     Gate
}

// New configures the rules in reg from cfg. Rule options are applied to the
// rule instances, so reg must not be shared with another engine.
func New(reg *rules.Registry, cfg config.Config, gate Gate) (*Engine, error) {
	e := &Engine{
		reg:      reg,
		disabled: map[string]bool{},
		severity: map[string]rules.Severity{},
		ignores:  cfg.Ignore,
		gate:     gate,
	}
	var errs []error
	for _, id := range sortedKeys(cfg.Rules) {
		rc := cfg.Rules[id]
		rule, ok := reg.Get(id)
		if !ok {
			errs = append(errs, fmt.Errorf("rules.%s: unknown rule ID (run `tfplan-risk rules` for the list)", id))
			continue
		}
		if rc.Enabled != nil && !*rc.Enabled {
			e.disabled[id] = true
		}
		if rc.Severity != nil {
			e.severity[id] = *rc.Severity
		}
		if len(rc.Options) > 0 {
			c, ok := rule.(rules.Configurable)
			if !ok {
				errs = append(errs, fmt.Errorf("rules.%s: rule takes no options, got %v", id, sortedKeys(rc.Options)))
				continue
			}
			if err := c.Configure(config.DecodeOptions(id, rc.Options)); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if len(cfg.StatefulTypesExtra) > 0 {
		for _, r := range reg.Rules() {
			if x, ok := r.(rules.StatefulTypesExtender); ok {
				x.AddStatefulTypes(cfg.StatefulTypesExtra)
			}
		}
	}
	for i, ig := range cfg.Ignore {
		for _, pattern := range ig.Rules {
			if !matchesAnyRule(reg, pattern) {
				errs = append(errs, fmt.Errorf("ignore[%d]: rule pattern %q matches no rule", i, pattern))
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return e, nil
}

func matchesAnyRule(reg *rules.Registry, pattern string) bool {
	for _, m := range reg.Metas() {
		if glob.Match(pattern, m.ID) {
			return true
		}
	}
	return false
}

// Run evaluates all enabled rules against p.
func (e *Engine) Run(ctx context.Context, p *plan.Plan) (Result, error) {
	res := Result{
		FormatVersion:    p.FormatVersion,
		TerraformVersion: p.TerraformVersion,
		Summary: Summary{
			Changes:  map[plan.Action]int{},
			Findings: map[rules.Severity]int{},
		},
	}

	var raw []rules.Finding
	for i, c := range p.Changes {
		if i%256 == 0 {
			if err := ctx.Err(); err != nil {
				return Result{}, err
			}
		}
		if c.Mode != plan.ModeManaged {
			continue
		}
		res.Summary.Changes[c.Action]++
		if c.Action == plan.ActionNoOp {
			continue
		}
		for _, r := range e.reg.Rules() {
			if e.disabled[r.Meta().ID] {
				continue
			}
			raw = append(raw, r.Evaluate(c)...)
		}
	}
	for _, r := range e.reg.PlanRules() {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if e.disabled[r.Meta().ID] {
			continue
		}
		raw = append(raw, r.EvaluatePlan(p)...)
	}

	res.Findings = make([]Finding, 0, len(raw))
	for _, f := range raw {
		if s, ok := e.severity[f.RuleID]; ok {
			f.Severity = s
		}
		ef := Finding{Finding: f}
		if reason, ok := e.suppressed(f); ok {
			ef.Suppressed, ef.SuppressReason = true, reason
			res.Summary.Suppressed++
		} else {
			res.Summary.Findings[f.Severity]++
			if !res.Summary.HasFindings || f.Severity > res.Summary.MaxSeverity {
				res.Summary.MaxSeverity = f.Severity
			}
			res.Summary.HasFindings = true
		}
		res.Findings = append(res.Findings, ef)
	}
	slices.SortStableFunc(res.Findings, func(a, b Finding) int {
		return cmp.Or(
			cmp.Compare(b.Severity, a.Severity),
			cmp.Compare(a.Address, b.Address),
			cmp.Compare(a.RuleID, b.RuleID),
		)
	})

	res.Score = Score(res.Findings)
	res.Gate = e.evaluateGate(res)
	return res, nil
}

func (e *Engine) suppressed(f rules.Finding) (string, bool) {
	for _, ig := range e.ignores {
		if !glob.Match(ig.Address, f.Address) {
			continue
		}
		if len(ig.Rules) == 0 || glob.MatchAny(ig.Rules, f.RuleID) {
			return ig.Reason, true
		}
	}
	return "", false
}

func (e *Engine) evaluateGate(res Result) GateResult {
	g := GateResult{Gate: e.gate}
	if fo := e.gate.FailOn; fo != nil {
		n := 0
		for _, s := range rules.AllSeverities {
			if s >= *fo {
				n += res.Summary.Findings[s]
			}
		}
		if n > 0 {
			g.Failed = true
			g.Reason = fmt.Sprintf("%d finding(s) at or above %s", n, *fo)
		}
	}
	if ms := e.gate.MaxScore; ms != nil && res.Score > *ms {
		reason := fmt.Sprintf("risk score %d is above max-score %d", res.Score, *ms)
		if g.Failed {
			g.Reason += "; " + reason
		} else {
			g.Failed, g.Reason = true, reason
		}
	}
	return g
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
