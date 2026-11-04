package config

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/kviatkovsky/tfplan-risk/rules"
)

func ptr[T any](v T) *T { return &v }

func TestParse(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		input   string
		want    Config
		wantErr []string
	}{
		{name: "empty document", input: "", want: Config{}},
		{
			name: "full example",
			input: `
fail_on: high
max_score: 60
rules:
  TPR-SEC-001:
    severity: medium
    allow_ports: [80, 443]
  TPR-AVAIL-003:
    enabled: false
ignore:
  - address: "module.sandbox.*"
    rules: ["*"]
    reason: sandbox is disposable
stateful_types_extra: ["aws_opensearch_domain"]
`,
			want: Config{
				FailOn:   ptr(rules.SeverityHigh),
				MaxScore: ptr(60),
				Rules: map[string]RuleConfig{
					"TPR-SEC-001":   {Severity: ptr(rules.SeverityMedium), Options: map[string]any{"allow_ports": []any{80, 443}}},
					"TPR-AVAIL-003": {Enabled: ptr(false)},
				},
				Ignore:             []Ignore{{Address: "module.sandbox.*", Rules: []string{"*"}, Reason: "sandbox is disposable"}},
				StatefulTypesExtra: []string{"aws_opensearch_domain"},
			},
		},
		{name: "fail_on none", input: "fail_on: NONE", want: Config{FailOnNone: true}},
		{name: "unknown top-level key", input: "fail_onn: high", wantErr: []string{`line 1: unknown key "fail_onn"`, "allowed: fail_on, max_score"}},
		{name: "unknown ignore key", input: "ignore:\n  - address: x\n    reason: y\n    because: z", wantErr: []string{`unknown key "because"`, "allowed: address, rules, reason"}},
		{name: "bad severity", input: "fail_on: severe", wantErr: []string{"fail_on", "unknown severity"}},
		{name: "bad rule severity", input: "rules:\n  TPR-X-001:\n    severity: huge", wantErr: []string{"unknown severity"}},
		{name: "ignore without reason", input: "ignore:\n  - address: aws_s3_bucket.tmp", wantErr: []string{"ignore[0] (aws_s3_bucket.tmp): reason is required"}},
		{name: "ignore without address", input: "ignore:\n  - reason: x", wantErr: []string{"ignore[0]: address is required"}},
		{name: "max_score out of range", input: "max_score: 101", wantErr: []string{"max_score: 101"}},
		{name: "empty stateful type", input: "stateful_types_extra: ['']", wantErr: []string{"stateful_types_extra[0]"}},
		{name: "wrong type", input: "max_score: lots", wantErr: []string{"invalid config"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Parse(strings.NewReader(tt.input))
			if len(tt.wantErr) > 0 {
				if err == nil {
					t.Fatalf("Parse() error = nil, want %q", tt.wantErr)
				}
				for _, w := range tt.wantErr {
					if !strings.Contains(err.Error(), w) {
						t.Errorf("Parse() error = %q, want it to contain %q", err, w)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse() error: %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Parse() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	good := filepath.Join(dir, "good.yaml")
	if err := os.WriteFile(good, []byte("fail_on: low\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(ctx, good)
	if err != nil || cfg.FailOn == nil || *cfg.FailOn != rules.SeverityLow {
		t.Fatalf("Load(good) = %+v, %v", cfg, err)
	}

	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("nope: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(ctx, bad); err == nil || !strings.Contains(err.Error(), "bad.yaml") {
		t.Errorf("Load(bad) error = %v, want file name in error", err)
	}

	if _, err := Load(ctx, filepath.Join(dir, "missing.yaml")); err == nil {
		t.Error("Load(explicit missing file) want error")
	}

	// Implicit default file: absent is fine, present is loaded.
	t.Chdir(dir)
	if cfg, err := Load(ctx, ""); err != nil || cfg.FailOn != nil {
		t.Errorf("Load(\"\") without default file = %+v, %v", cfg, err)
	}
	if err := os.WriteFile(DefaultFile, []byte("fail_on: medium\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if cfg, err := Load(ctx, ""); err != nil || cfg.FailOn == nil || *cfg.FailOn != rules.SeverityMedium {
		t.Errorf("Load(\"\") with default file = %+v, %v", cfg, err)
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := Load(canceled, good); err == nil {
		t.Error("Load(canceled ctx) want error")
	}
}

func TestDecodeOptions(t *testing.T) {
	t.Parallel()
	type opts struct {
		AllowPorts []int `yaml:"allow_ports"`
	}
	var o opts
	if err := DecodeOptions("TPR-SEC-001", map[string]any{"allow_ports": []any{80, 8080}})(&o); err != nil {
		t.Fatal(err)
	}
	if !cmp.Equal(o.AllowPorts, []int{80, 8080}) {
		t.Errorf("AllowPorts = %v", o.AllowPorts)
	}
	err := DecodeOptions("TPR-SEC-001", map[string]any{"allow_port": 1})(&o)
	if err == nil || !strings.Contains(err.Error(), "rules.TPR-SEC-001: unknown option allow_port") {
		t.Errorf("unknown option error = %v", err)
	}
	if err := DecodeOptions("X", nil)(&o); err != nil {
		t.Errorf("empty options error = %v", err)
	}
	err = DecodeOptions("X", map[string]any{"allow_ports": "eighty"})(&o)
	if err == nil || !strings.Contains(err.Error(), "rules.X:") {
		t.Errorf("wrong type error = %v", err)
	}
}
