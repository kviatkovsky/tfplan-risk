package rules

import (
	"strings"
	"testing"

	"github.com/kviatkovsky/tfplan-risk/plan"
)

func TestSeverity(t *testing.T) {
	t.Parallel()
	for _, s := range AllSeverities {
		got, err := ParseSeverity(strings.ToUpper(s.String()))
		if err != nil || got != s {
			t.Errorf("ParseSeverity(%q) = %v, %v", s, got, err)
		}
		b, _ := s.MarshalText()
		var back Severity
		if err := back.UnmarshalText(b); err != nil || back != s {
			t.Errorf("text round trip of %v = %v, %v", s, back, err)
		}
	}
	if _, err := ParseSeverity("severe"); err == nil {
		t.Error("ParseSeverity(severe) want error")
	}
	var s Severity
	if err := s.UnmarshalText([]byte("nope")); err == nil {
		t.Error("UnmarshalText(nope) want error")
	}
	if got := Severity(42).String(); got != "severity(42)" {
		t.Errorf("Severity(42).String() = %q", got)
	}
}

type fakeRule struct{ m Meta }

func (f fakeRule) Meta() Meta                     { return f.m }
func (f fakeRule) Evaluate(plan.Change) []Finding { return nil }
func (f fakeRule) EvaluatePlan(*plan.Plan) []Finding {
	return nil
}

func meta(id string) Meta {
	return Meta{ID: id, Title: "t", Description: "d", Category: CategoryHygiene}
}

func TestRegistry(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	if err := r.Register(fakeRule{meta("TPR-B-002")}, fakeRule{meta("TPR-A-001")}); err != nil {
		t.Fatal(err)
	}
	if err := r.RegisterPlan(fakeRule{meta("TPR-PLAN-001")}); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		reg     func() error
		wantErr string
	}{
		{"duplicate", func() error { return r.Register(fakeRule{meta("TPR-A-001")}) }, "duplicate"},
		{"duplicate across kinds", func() error { return r.RegisterPlan(fakeRule{meta("TPR-B-002")}) }, "duplicate"},
		{"bad id", func() error { return r.Register(fakeRule{meta("tpr-a-1")}) }, "does not match"},
		{"missing title", func() error { return r.Register(fakeRule{Meta{ID: "TPR-C-001"}}) }, "required"},
		{"bad plan id", func() error { return r.RegisterPlan(fakeRule{meta("X")}) }, "does not match"},
	}
	for _, tt := range tests {
		err := tt.reg()
		if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
			t.Errorf("%s: err = %v, want %q", tt.name, err, tt.wantErr)
		}
	}

	if len(r.Rules()) != 2 || len(r.PlanRules()) != 1 {
		t.Errorf("Rules()=%d PlanRules()=%d", len(r.Rules()), len(r.PlanRules()))
	}
	var ids []string
	for _, m := range r.Metas() {
		ids = append(ids, m.ID)
	}
	if got := strings.Join(ids, ","); got != "TPR-A-001,TPR-B-002,TPR-PLAN-001" {
		t.Errorf("Metas() order = %s", got)
	}
	if _, ok := r.Get("TPR-PLAN-001"); !ok {
		t.Error("Get(TPR-PLAN-001) not found")
	}
	if _, ok := r.Get("TPR-X-999"); ok {
		t.Error("Get(TPR-X-999) found")
	}
}

func TestFormat(t *testing.T) {
	t.Parallel()
	long := make([]any, 50)
	for i := range long {
		long[i] = "abc"
	}
	tests := []struct {
		in   any
		want string
	}{
		{nil, "null"},
		{"x", `"x"`},
		{true, "true"},
		{float64(5432), "5432"},
		{plan.Redacted{}, "(sensitive)"},
		{[]any{"a", float64(1)}, `["a",1]`},
		{map[string]any{"k": "v"}, `{"k":"v"}`},
		{func() {}, "(unprintable)"},
	}
	for _, tt := range tests {
		if got := FormatValue(tt.in); got != tt.want {
			t.Errorf("FormatValue(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
	if got := FormatValue(long); len(got) != 80 || !strings.HasSuffix(got, "...") {
		t.Errorf("FormatValue(long) = %q (len %d)", got, len(got))
	}

	c := plan.Change{
		Before:       map[string]any{"v": "15"},
		After:        map[string]any{"v": "16", "id": nil},
		AfterUnknown: map[string]any{"id": true},
	}
	if got := FormatBefore(c, "v"); got != `"15"` {
		t.Errorf("FormatBefore = %s", got)
	}
	if got := FormatAfter(c, "v"); got != `"16"` {
		t.Errorf("FormatAfter = %s", got)
	}
	if got := FormatAfter(c, "id"); got != UnknownValue {
		t.Errorf("FormatAfter(unknown) = %s", got)
	}

	f := New(Meta{ID: "TPR-X-001", Category: CategorySecurity, Suggestion: "fix"}, plan.Change{Address: "a.b", Action: plan.ActionUpdate}, SeverityHigh, "msg")
	if f.RuleID != "TPR-X-001" || f.Address != "a.b" || f.Suggestion != "fix" || f.Severity != SeverityHigh || f.Category != CategorySecurity {
		t.Errorf("New() = %+v", f)
	}
}
