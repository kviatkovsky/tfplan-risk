package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func fixture(name string) string {
	return filepath.Join("..", "..", "internal", "testdata", "plans", name+".json")
}

func env(kv ...string) func(string) string {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return func(k string) string { return m[k] }
}

func TestRun(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	lenient := write("lenient.yaml", "fail_on: none\n")
	strict := write("strict.yaml", "fail_on: info\nmax_score: 10\n")
	scored := write("scored.yaml", "max_score: 10\n")
	ignoreAll := write("ignore.yaml", "ignore:\n  - address: \"*\"\n    reason: test\n")
	broken := write("broken.yaml", "fail_onn: high\n")
	empty := write("empty.json", "{\"format_version\":\"1.2\",\"resource_changes\":[]}")
	fakeTF := write("terraform", "#!/bin/sh\ncat "+mustAbs(t, fixture("s3-delete"))+"\n")
	failTF := write("terraform-fail", "#!/bin/sh\necho 'plan file is corrupt' >&2\nexit 1\n")
	for _, p := range []string{fakeTF, failTF} {
		if err := os.Chmod(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		name       string
		args       []string
		stdin      string
		env        func(string) string
		wantCode   int
		wantStdout []string
		wantStderr []string
		unix       bool
	}{
		{name: "file argument, default gate fails on critical", args: []string{fixture("s3-delete")}, wantCode: 2,
			wantStdout: []string{"CRITICAL  aws_s3_bucket.logs  DELETE  stateful resource deleted", "Risk score: 55/100", "FAIL: 1 finding(s) at or above critical"}},
		{name: "stdin", args: []string{"-"}, stdin: readFile(t, fixture("sg-open-db-port")), wantCode: 2,
			wantStdout: []string{"aws_vpc_security_group_ingress_rule.ssh", "port 22/tcp (SSH)"}},
		{name: "implicit stdin", stdin: readFile(t, fixture("sg-open-db-port")), wantCode: 2, wantStdout: []string{"Risk score: 80/100"}},
		{name: "flags after file", args: []string{fixture("rds-replace"), "--format", "json", "--fail-on", "none"}, wantCode: 0,
			wantStdout: []string{`"version": 1`, `"rule_id": "TPR-DATA-001"`, `"fail_on": null`}},
		{name: "config fail_on none", args: []string{"--config", lenient, fixture("iam-wildcard")}, wantCode: 0},
		{name: "flag overrides config", args: []string{"--config", lenient, "--fail-on", "high", fixture("iam-wildcard")}, wantCode: 2},
		{name: "max-score flag", args: []string{"--fail-on", "none", "--max-score", "50", fixture("s3-delete")}, wantCode: 2,
			wantStdout: []string{"risk score 55 is above max-score 50"}},
		{name: "max-score from config", args: []string{"--config", scored, "--fail-on", "none", fixture("s3-delete")}, wantCode: 2},
		{name: "strict config", args: []string{"--config", strict, empty}, wantCode: 0, wantStdout: []string{"No risky changes found.", "Plan: no changes."}},
		{name: "ignored findings pass", args: []string{"--config", ignoreAll, fixture("s3-delete")}, wantCode: 0,
			wantStdout: []string{"1 finding(s) suppressed by config"}},
		{name: "NO_COLOR is irrelevant for buffers but accepted", args: []string{fixture("s3-delete")}, env: env("NO_COLOR", "1"), wantCode: 2},
		{name: "debug logging", args: []string{"--log-level", "debug", fixture("s3-delete")}, wantCode: 2, wantStderr: []string{"plan parsed", "rules evaluated"}},
		{name: "terraform-bin converts binary plan", args: []string{"--terraform-bin", fakeTF, "plan.bin"}, wantCode: 2, unix: true,
			wantStdout: []string{"aws_s3_bucket.logs"}},
		{name: "terraform-bin failure", args: []string{"--terraform-bin", failTF, "plan.bin"}, wantCode: 1, unix: true,
			wantStderr: []string{"plan file is corrupt"}},
		{name: "version", args: []string{"version"}, wantCode: 0, wantStdout: []string{"tfplan-risk "}},
		{name: "help", args: []string{"-h"}, wantCode: 0, wantStderr: []string{"Usage:", "-fail-on"}},
		{name: "unknown flag", args: []string{"--nope"}, wantCode: 1, wantStderr: []string{"flag provided but not defined"}},
		{name: "extra args", args: []string{"a.json", "b.json"}, wantCode: 1, wantStderr: []string{"unexpected arguments", "Usage:"}},
		{name: "bad flag after file", args: []string{"a.json", "--nope"}, wantCode: 1},
		{name: "max-score range", args: []string{"--max-score", "101"}, wantCode: 1, wantStderr: []string{"--max-score must be between 0 and 100"}},
		{name: "terraform-bin needs file", args: []string{"--terraform-bin", "terraform"}, wantCode: 1, wantStderr: []string{"needs a plan file"}},
		{name: "bad log level", args: []string{"--log-level", "loud"}, wantCode: 1, wantStderr: []string{"--log-level"}},
		{name: "bad fail-on", args: []string{"--fail-on", "severe", fixture("s3-delete")}, wantCode: 1, wantStderr: []string{"--fail-on: unknown severity"}},
		{name: "bad format", args: []string{"--format", "xml", fixture("s3-delete")}, wantCode: 1, wantStderr: []string{`unknown format "xml"`}},
		{name: "broken config", args: []string{"--config", broken, fixture("s3-delete")}, wantCode: 1, wantStderr: []string{`unknown key "fail_onn"`}},
		{name: "missing file", args: []string{filepath.Join(dir, "nope.json")}, wantCode: 1, wantStderr: []string{"open plan"}},
		{name: "not a plan", stdin: "Terraform will perform the following actions", wantCode: 1, wantStderr: []string{"parse plan", "expected a JSON object"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.unix && runtime.GOOS == "windows" {
				t.Skip("shell script stub")
			}
			getenv := tt.env
			if getenv == nil {
				getenv = env()
			}
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), tt.args, strings.NewReader(tt.stdin), &stdout, &stderr, getenv)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tt.wantCode, stdout.String(), stderr.String())
			}
			for _, w := range tt.wantStdout {
				if !strings.Contains(stdout.String(), w) {
					t.Errorf("stdout missing %q:\n%s", w, stdout.String())
				}
			}
			for _, w := range tt.wantStderr {
				if !strings.Contains(stderr.String(), w) {
					t.Errorf("stderr missing %q:\n%s", w, stderr.String())
				}
			}
			if strings.Contains(stdout.String(), "\x1b[") {
				t.Error("colors must be off when stdout is not a terminal")
			}
		})
	}
}

func TestColorEnabled(t *testing.T) {
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()
	tests := []struct {
		name string
		o    options
		w    any
		env  func(string) string
		want bool
	}{
		{"no-color flag", options{noColor: true}, os.Stdout, env(), false},
		{"NO_COLOR", options{}, os.Stdout, env("NO_COLOR", "1"), false},
		{"dumb terminal", options{}, os.Stdout, env("TERM", "dumb"), false},
		{"buffer", options{}, &bytes.Buffer{}, env(), false},
		{"regular file", options{}, devnull, env(), runtime.GOOS != "windows" && isCharDevice(devnull)},
	}
	for _, tt := range tests {
		w, _ := tt.w.(interface{ Write([]byte) (int, error) })
		if got := colorEnabled(tt.o, w, tt.env); got != tt.want {
			t.Errorf("%s: colorEnabled() = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func isCharDevice(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func TestToolVersion(t *testing.T) {
	if toolVersion() == "" {
		t.Error("toolVersion() is empty")
	}
	old := version
	version = "v9.9.9"
	t.Cleanup(func() { version = old })
	if toolVersion() != "v9.9.9" {
		t.Error("ldflags version not used")
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func mustAbs(t *testing.T, p string) string {
	t.Helper()
	a, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
