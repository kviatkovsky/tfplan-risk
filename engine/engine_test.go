package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/kviatkovsky/tfplan-risk/config"
	"github.com/kviatkovsky/tfplan-risk/plan"
	"github.com/kviatkovsky/tfplan-risk/rules"
	"github.com/kviatkovsky/tfplan-risk/rules/builtin"
)

func ptr[T any](v T) *T { return &v }

// stub emits one finding per change of its type, with the given severity.
type stub struct {
	id   string
	typ  string
	sev  rules.Severity
	opts struct {
		Note string `yaml:"note"`
	}
}

func (s *stub) Meta() rules.Meta {
	return rules.Meta{ID: s.id, Title: "t", Description: "d", Category: rules.CategoryHygiene}
}

func (s *stub) Evaluate(c plan.Change) []rules.Finding {
	if c.Type != s.typ {
		return nil
	}
	return []rules.Finding{rules.New(s.Meta(), c, s.sev, "changed"+s.opts.Note)}
}

func (s *stub) Configure(decode func(any) error) error { return decode(&s.opts) }

type planStub struct{ stub }

func (p *planStub) EvaluatePlan(pl *plan.Plan) []rules.Finding {
	return []rules.Finding{{RuleID: p.id, Severity: p.sev, Category: rules.CategoryAvailability, Message: "plan-level"}}
}

type noOpts struct{ stub }

func (noOpts) Configure() {} // does not satisfy rules.Configurable

func registry(t *testing.T) *rules.Registry {
	t.Helper()
	r := rules.NewRegistry()
	if err := r.Register(
		&stub{id: "TPR-T-001", typ: "a", sev: rules.SeverityCritical},
		&stub{id: "TPR-T-002", typ: "b", sev: rules.SeverityMedium},
		&noOpts{stub{id: "TPR-T-003", typ: "c", sev: rules.SeverityLow}},
	); err != nil {
		t.Fatal(err)
	}
	if err := r.RegisterPlan(&planStub{stub{id: "TPR-PLAN-001", sev: rules.SeverityHigh}}); err != nil {
		t.Fatal(err)
	}
	return r
}

var testPlan = &plan.Plan{
	FormatVersion:    "1.2",
	TerraformVersion: "1.17.1",
	Changes: []plan.Change{
		{Address: "b.two", Type: "b", Mode: plan.ModeManaged, Action: plan.ActionUpdate},
		{Address: "a.one", Type: "a", Mode: plan.ModeManaged, Action: plan.ActionDelete},
		{Address: "module.sandbox.a.x", Type: "a", Mode: plan.ModeManaged, Action: plan.ActionReplace},
		{Address: "c.three", Type: "c", Mode: plan.ModeManaged, Action: plan.ActionCreate},
		{Address: "a.noop", Type: "a", Mode: plan.ModeManaged, Action: plan.ActionNoOp},
		{Address: "data.a.d", Type: "a", Mode: plan.ModeData, Action: plan.ActionRead},
	},
}

type row struct {
	ID, Addr, Sev, Msg string
	Suppressed         bool
	Reason             string
}

func rows(fs []Finding) []row {
	out := make([]row, 0, len(fs))
	for _, f := range fs {
		out = append(out, row{f.RuleID, f.Address, f.Severity.String(), f.Message, f.Suppressed, f.SuppressReason})
	}
	return out
}

func TestRun(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		cfg       config.Config
		gate      Gate
		want      []row
		score     int
		failed    bool
		reason    string
		maxSev    rules.Severity
		suppress  int
		hasActive bool
	}{
		{
			name: "defaults",
			gate: Gate{FailOn: ptr(rules.SeverityCritical)},
			want: []row{
				{"TPR-T-001", "a.one", "critical", "changed", false, ""},
				{"TPR-T-001", "module.sandbox.a.x", "critical", "changed", false, ""},
				{"TPR-PLAN-001", "", "high", "plan-level", false, ""},
				{"TPR-T-002", "b.two", "medium", "changed", false, ""},
				{"TPR-T-003", "c.three", "low", "changed", false, ""},
			},
			score: 87, failed: true, reason: "2 finding(s) at or above critical",
			maxSev: rules.SeverityCritical, hasActive: true,
		},
		{
			name: "overrides, disabled rule, ignores and options",
			cfg: config.Config{
				Rules: map[string]config.RuleConfig{
					"TPR-T-002":    {Severity: ptr(rules.SeverityHigh), Options: map[string]any{"note": "!"}},
					"TPR-PLAN-001": {Enabled: ptr(false)},
					"TPR-T-003":    {Enabled: ptr(true)},
				},
				Ignore: []config.Ignore{
					{Address: "module.sandbox.*", Reason: "disposable"},
					{Address: "c.*", Rules: []string{"TPR-T-00?"}, Reason: "known"},
					{Address: "a.one", Rules: []string{"TPR-T-002"}, Reason: "does not match the rule"},
				},
			},
			gate: Gate{FailOn: ptr(rules.SeverityHigh), MaxScore: ptr(10)},
			want: []row{
				{"TPR-T-001", "a.one", "critical", "changed", false, ""},
				{"TPR-T-001", "module.sandbox.a.x", "critical", "changed", true, "disposable"},
				{"TPR-T-002", "b.two", "high", "changed!", false, ""},
				{"TPR-T-003", "c.three", "low", "changed", true, "known"},
			},
			score: 67, failed: true, reason: "2 finding(s) at or above high; risk score 67 is above max-score 10",
			maxSev: rules.SeverityCritical, suppress: 2, hasActive: true,
		},
		{
			name: "everything ignored, max score only",
			cfg:  config.Config{Ignore: []config.Ignore{{Address: "*", Rules: []string{"*"}, Reason: "all"}}},
			gate: Gate{MaxScore: ptr(0)},
			want: []row{
				{"TPR-T-001", "a.one", "critical", "changed", true, "all"},
				{"TPR-T-001", "module.sandbox.a.x", "critical", "changed", true, "all"},
				{"TPR-PLAN-001", "", "high", "plan-level", true, "all"},
				{"TPR-T-002", "b.two", "medium", "changed", true, "all"},
				{"TPR-T-003", "c.three", "low", "changed", true, "all"},
			},
			score: 0, suppress: 5,
		},
		{
			name: "score gate only",
			gate: Gate{MaxScore: ptr(50)},
			want: []row{
				{"TPR-T-001", "a.one", "critical", "changed", false, ""},
				{"TPR-T-001", "module.sandbox.a.x", "critical", "changed", false, ""},
				{"TPR-PLAN-001", "", "high", "plan-level", false, ""},
				{"TPR-T-002", "b.two", "medium", "changed", false, ""},
				{"TPR-T-003", "c.three", "low", "changed", false, ""},
			},
			score: 87, failed: true, reason: "risk score 87 is above max-score 50",
			maxSev: rules.SeverityCritical, hasActive: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e, err := New(registry(t), tt.cfg, tt.gate)
			if err != nil {
				t.Fatal(err)
			}
			res, err := e.Run(context.Background(), testPlan)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, rows(res.Findings)); diff != "" {
				t.Errorf("findings mismatch (-want +got):\n%s", diff)
			}
			if res.Score != tt.score {
				t.Errorf("Score = %d, want %d", res.Score, tt.score)
			}
			if res.Gate.Failed != tt.failed || res.Gate.Reason != tt.reason {
				t.Errorf("Gate = %+v, want failed=%v reason=%q", res.Gate, tt.failed, tt.reason)
			}
			if res.Summary.HasFindings != tt.hasActive || (tt.hasActive && res.Summary.MaxSeverity != tt.maxSev) {
				t.Errorf("Summary max = %v/%v, want %v/%v", res.Summary.MaxSeverity, res.Summary.HasFindings, tt.maxSev, tt.hasActive)
			}
			if res.Summary.Suppressed != tt.suppress {
				t.Errorf("Suppressed = %d, want %d", res.Summary.Suppressed, tt.suppress)
			}
			wantChanges := map[plan.Action]int{plan.ActionUpdate: 1, plan.ActionDelete: 1, plan.ActionReplace: 1, plan.ActionCreate: 1, plan.ActionNoOp: 1}
			if diff := cmp.Diff(wantChanges, res.Summary.Changes); diff != "" {
				t.Errorf("Changes mismatch (-want +got):\n%s", diff)
			}
			if res.TerraformVersion != "1.17.1" || res.FormatVersion != "1.2" {
				t.Errorf("plan versions not propagated: %+v", res)
			}
		})
	}
}

func TestNewErrors(t *testing.T) {
	t.Parallel()
	cfg := config.Config{
		Rules: map[string]config.RuleConfig{
			"TPR-NOPE-001": {Enabled: ptr(false)},
			"TPR-T-003":    {Options: map[string]any{"x": 1}},
			"TPR-T-001":    {Options: map[string]any{"bogus": 1}},
		},
		Ignore: []config.Ignore{{Address: "*", Rules: []string{"TPR-ZZZ-*"}, Reason: "r"}},
	}
	_, err := New(registry(t), cfg, Gate{})
	if err == nil {
		t.Fatal("New() error = nil")
	}
	for _, want := range []string{
		"rules.TPR-NOPE-001: unknown rule ID",
		"rules.TPR-T-003: rule takes no options, got [x]",
		"rules.TPR-T-001: unknown option bogus",
		`ignore[0]: rule pattern "TPR-ZZZ-*" matches no rule`,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("New() error = %q, want it to contain %q", err, want)
		}
	}
}

func TestRunCanceled(t *testing.T) {
	t.Parallel()
	e, err := New(registry(t), config.Config{}, Gate{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.Run(ctx, testPlan); !errors.Is(err, context.Canceled) {
		t.Errorf("Run() error = %v, want context.Canceled", err)
	}
	if _, err := e.Run(ctx, &plan.Plan{}); !errors.Is(err, context.Canceled) {
		t.Errorf("Run(empty plan) error = %v, want context.Canceled", err)
	}
}

func TestScore(t *testing.T) {
	t.Parallel()
	f := func(s rules.Severity, n int) []Finding {
		out := make([]Finding, n)
		for i := range out {
			out[i].Severity = s
		}
		return out
	}
	tests := []struct {
		name string
		in   []Finding
		want int
	}{
		{"nothing", nil, 0},
		{"info only", f(rules.SeverityInfo, 100), 0},
		{"one low", f(rules.SeverityLow, 1), 2},
		{"one medium", f(rules.SeverityMedium, 1), 10},
		{"one high", f(rules.SeverityHigh, 1), 26},
		{"one critical", f(rules.SeverityCritical, 1), 55},
		{"two critical", f(rules.SeverityCritical, 2), 80},
		{"suppressed ignored", []Finding{{Suppressed: true, Finding: rules.Finding{Severity: rules.SeverityCritical}}}, 0},
		{"saturates", f(rules.SeverityCritical, 20), 100},
	}
	for _, tt := range tests {
		if got := Score(tt.in); got != tt.want {
			t.Errorf("%s: Score() = %d, want %d", tt.name, got, tt.want)
		}
	}
}

// TestFixtures runs the built-in rule set end to end over every fixture.
func TestFixtures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		fixture string
		score   int
		maxSev  rules.Severity
		count   int
	}{
		{"rds-replace", 55, rules.SeverityCritical, 1},
		{"s3-delete", 55, rules.SeverityCritical, 1},
		{"sg-open-db-port", 80, rules.SeverityCritical, 2},
		{"iam-wildcard", 86, rules.SeverityCritical, 5},
	}
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			t.Parallel()
			fh, err := os.Open(filepath.Join("..", "internal", "testdata", "plans", tt.fixture+".json"))
			if err != nil {
				t.Fatal(err)
			}
			defer fh.Close()
			p, err := plan.Parse(context.Background(), fh)
			if err != nil {
				t.Fatal(err)
			}
			reg, err := builtin.New()
			if err != nil {
				t.Fatal(err)
			}
			e, err := New(reg, config.Config{}, Gate{FailOn: ptr(rules.SeverityCritical)})
			if err != nil {
				t.Fatal(err)
			}
			res, err := e.Run(context.Background(), p)
			if err != nil {
				t.Fatal(err)
			}
			if res.Score != tt.score || res.Summary.MaxSeverity != tt.maxSev || len(res.Findings) != tt.count || !res.Gate.Failed {
				t.Errorf("score=%d max=%v findings=%d failed=%v; want %d %v %d true\n%v",
					res.Score, res.Summary.MaxSeverity, len(res.Findings), res.Gate.Failed, tt.score, tt.maxSev, tt.count, rows(res.Findings))
			}
		})
	}
}

func TestStatefulTypesExtra(t *testing.T) {
	t.Parallel()
	reg, err := builtin.New()
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(reg, config.Config{StatefulTypesExtra: []string{"aws_opensearch_domain"}}, Gate{})
	if err != nil {
		t.Fatal(err)
	}
	p := &plan.Plan{Changes: []plan.Change{{Address: "aws_opensearch_domain.d", Type: "aws_opensearch_domain", Mode: plan.ModeManaged, Action: plan.ActionDelete}}}
	res, err := e.Run(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].RuleID != "TPR-DATA-001" {
		t.Errorf("findings = %v", rows(res.Findings))
	}
}
