package report

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/kviatkovsky/tfplan-risk/config"
	"github.com/kviatkovsky/tfplan-risk/engine"
	"github.com/kviatkovsky/tfplan-risk/plan"
	"github.com/kviatkovsky/tfplan-risk/rules"
	"github.com/kviatkovsky/tfplan-risk/rules/builtin"
)

var update = flag.Bool("update", false, "rewrite golden files")

func ptr[T any](v T) *T { return &v }

func fixtureResult(t *testing.T, name string, cfg config.Config) engine.Result {
	t.Helper()
	fh, err := os.Open(filepath.Join("..", "internal", "testdata", "plans", name+".json"))
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
	e, err := engine.New(reg, cfg, engine.Gate{FailOn: ptr(rules.SeverityCritical)})
	if err != nil {
		t.Fatal(err)
	}
	res, err := e.Run(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// handResult covers what fixtures do not: plan-level and suppressed
// findings, max-score gate, info severity.
var handResult = engine.Result{
	FormatVersion:    "1.2",
	TerraformVersion: "1.17.1",
	Findings: []engine.Finding{
		{Finding: rules.Finding{RuleID: "TPR-PLAN-001", Severity: rules.SeverityHigh, Category: rules.CategoryAvailability, Message: "14 resources deleted (threshold 10)", Suggestion: "split the change"}},
		{Finding: rules.Finding{RuleID: "TPR-SEC-002", Severity: rules.SeverityInfo, Category: rules.CategorySecurity, Address: "aws_iam_role_policy.p", Action: plan.ActionCreate, Message: "policy is known only after apply", Suggestion: "review"}},
		{Finding: rules.Finding{RuleID: "TPR-DATA-001", Severity: rules.SeverityCritical, Category: rules.CategoryDataLoss, Address: "module.sandbox.aws_s3_bucket.tmp", Action: plan.ActionDelete, Message: "stateful resource deleted -> data loss", Suggestion: "snapshot"}, Suppressed: true, SuppressReason: "sandbox is disposable"},
	},
	Score: 26,
	Summary: engine.Summary{
		Changes:     map[plan.Action]int{plan.ActionDelete: 14, plan.ActionCreate: 1, plan.ActionNoOp: 3},
		Findings:    map[rules.Severity]int{rules.SeverityHigh: 1, rules.SeverityInfo: 1},
		Suppressed:  1,
		MaxSeverity: rules.SeverityHigh,
		HasFindings: true,
	},
	Gate: engine.GateResult{Gate: engine.Gate{MaxScore: ptr(20)}, Failed: true, Reason: "risk score 26 is above max-score 20"},
}

var emptyResult = engine.Result{
	FormatVersion: "1.2",
	Summary:       engine.Summary{Changes: map[plan.Action]int{plan.ActionNoOp: 2}, Findings: map[rules.Severity]int{}},
	Gate:          engine.GateResult{Gate: engine.Gate{FailOn: ptr(rules.SeverityCritical)}},
}

func TestGolden(t *testing.T) {
	t.Parallel()
	results := map[string]engine.Result{
		"hand":  handResult,
		"empty": emptyResult,
	}
	for _, f := range []string{"rds-replace", "s3-delete", "sg-open-db-port", "iam-wildcard"} {
		results[f] = fixtureResult(t, f, config.Config{})
	}
	formats := []struct {
		ext  string
		name string
		opts Options
	}{
		{"txt", "table", Options{}},
		{"ansi.txt", "table", Options{Color: true}},
		{"json", "json", Options{ToolVersion: "v0.0.0-test"}},
	}
	for name, res := range results {
		for _, f := range formats {
			t.Run(name+"."+f.ext, func(t *testing.T) {
				t.Parallel()
				r, err := New(f.name, f.opts)
				if err != nil {
					t.Fatal(err)
				}
				var buf bytes.Buffer
				if err := r.Render(context.Background(), &buf, res); err != nil {
					t.Fatal(err)
				}
				assertGolden(t, filepath.Join("testdata", "golden", name+"."+f.ext), buf.Bytes())
			})
		}
	}
}

func assertGolden(t *testing.T, path string, got []byte) {
	t.Helper()
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden file (run `make golden` to create it): %v", err)
	}
	if diff := cmp.Diff(string(want), string(got)); diff != "" {
		t.Errorf("%s mismatch (-want +got):\n%s", path, diff)
	}
}

func TestNewUnknownFormat(t *testing.T) {
	t.Parallel()
	if _, err := New("xml", Options{}); err == nil || !strings.Contains(err.Error(), "table, json") {
		t.Errorf("New(xml) error = %v", err)
	}
}

func TestRenderCanceled(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, f := range Formats {
		r, err := New(f, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Render(ctx, &bytes.Buffer{}, emptyResult); !errors.Is(err, context.Canceled) {
			t.Errorf("%s: Render() error = %v, want context.Canceled", f, err)
		}
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestRenderWriteError(t *testing.T) {
	t.Parallel()
	for _, f := range Formats {
		r, err := New(f, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Render(context.Background(), failWriter{}, handResult); err == nil {
			t.Errorf("%s: Render() error = nil, want write error", f)
		}
	}
}

func TestNoSensitiveValuesInOutput(t *testing.T) {
	t.Parallel()
	res := fixtureResult(t, "rds-replace", config.Config{})
	for _, f := range Formats {
		r, err := New(f, Options{})
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		if err := r.Render(context.Background(), &buf, res); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(buf.String(), "example-secret") {
			t.Errorf("%s output contains a sensitive value", f)
		}
	}
}
