package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"time"

	"github.com/kviatkovsky/tfplan-risk/config"
	"github.com/kviatkovsky/tfplan-risk/engine"
	"github.com/kviatkovsky/tfplan-risk/plan"
	"github.com/kviatkovsky/tfplan-risk/report"
	"github.com/kviatkovsky/tfplan-risk/rules"
	"github.com/kviatkovsky/tfplan-risk/rules/builtin"
)

// Exit codes.
const (
	exitOK        = 0
	exitError     = 1
	exitThreshold = 2
)

// version is set by goreleaser via -ldflags "-X main.version=...".
var version = ""

const usage = `Usage:
  tfplan-risk [flags] [plan.json|-]   analyze a plan (default: read stdin)
  tfplan-risk version                 print the version

Produce the input with:
  terraform plan -out=plan.bin && terraform show -json plan.bin > plan.json

Exit codes: 0 = below threshold, 1 = error, 2 = threshold exceeded.

Flags:
`

// errUsage marks errors caused by bad invocation; usage is printed for them.
var errUsage = errors.New("usage error")

type options struct {
	format       string
	configPath   string
	failOn       string
	maxScore     int
	noColor      bool
	logLevel     string
	terraformBin string
	input        string
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) int {
	if len(args) > 0 {
		switch args[0] {
		case "version", "--version", "-version":
			fmt.Fprintln(stdout, "tfplan-risk", toolVersion())
			return exitOK
		}
	}

	opts, fs, err := parseFlags(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		fmt.Fprintln(stderr, "error:", err)
		if errors.Is(err, errUsage) {
			fs.Usage()
		}
		return exitError
	}

	logger, err := newLogger(stderr, opts.logLevel)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitError
	}

	failed, err := analyze(ctx, opts, stdin, stdout, logger, colorEnabled(opts, stdout, getenv))
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitError
	}
	if failed {
		return exitThreshold
	}
	return exitOK
}

func parseFlags(args []string, stderr io.Writer) (options, *flag.FlagSet, error) {
	var o options
	fs := flag.NewFlagSet("tfplan-risk", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, usage)
		fs.PrintDefaults()
	}
	fs.StringVar(&o.format, "format", "table", "output format: "+strings.Join(report.Formats, "|"))
	fs.StringVar(&o.configPath, "config", "", "config file (default: "+config.DefaultFile+" if present)")
	fs.StringVar(&o.failOn, "fail-on", "", "fail when a finding is at or above: critical|high|medium|low|info|none (default: config fail_on, else critical)")
	fs.IntVar(&o.maxScore, "max-score", -1, "fail when the risk score is above this value (0-100; -1 = config max_score or disabled)")
	fs.BoolVar(&o.noColor, "no-color", false, "disable colors (also honored: NO_COLOR env var)")
	fs.StringVar(&o.logLevel, "log-level", "warn", "log level: debug|info|warn|error")
	fs.StringVar(&o.terraformBin, "terraform-bin", "", "terraform binary used to convert a binary plan file with `terraform show -json`")

	// flag stops at the first positional argument; parse again after it so
	// flags may follow the file name.
	if err := fs.Parse(args); err != nil {
		return o, fs, err
	}
	rest := fs.Args()
	if len(rest) > 0 {
		o.input = rest[0]
		if err := fs.Parse(rest[1:]); err != nil {
			return o, fs, err
		}
		if fs.NArg() > 0 {
			return o, fs, fmt.Errorf("%w: unexpected arguments %q", errUsage, fs.Args())
		}
	}
	if o.maxScore < -1 || o.maxScore > 100 {
		return o, fs, fmt.Errorf("%w: --max-score must be between 0 and 100", errUsage)
	}
	if o.terraformBin != "" && (o.input == "" || o.input == "-") {
		return o, fs, fmt.Errorf("%w: --terraform-bin needs a plan file argument", errUsage)
	}
	return o, fs, nil
}

func newLogger(w io.Writer, level string) (*slog.Logger, error) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("--log-level: %w", err)
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: l})), nil
}

// analyze runs the pipeline and reports whether the gate failed.
func analyze(ctx context.Context, o options, stdin io.Reader, stdout io.Writer, logger *slog.Logger, color bool) (bool, error) {
	start := time.Now()

	cfg, err := config.Load(ctx, o.configPath)
	if err != nil {
		return false, err
	}
	gate, err := buildGate(o, cfg)
	if err != nil {
		return false, err
	}
	renderer, err := report.New(o.format, report.Options{Color: color, ToolVersion: toolVersion()})
	if err != nil {
		return false, err
	}

	in, err := openInput(ctx, o, stdin, logger)
	if err != nil {
		return false, err
	}
	p, err := plan.Parse(ctx, in)
	if c, ok := in.(io.Closer); ok {
		_ = c.Close()
	}
	if err != nil {
		return false, fmt.Errorf("parse plan: %w", err)
	}
	logger.Debug("plan parsed", "changes", len(p.Changes), "terraform_version", p.TerraformVersion, "elapsed", time.Since(start))

	reg, err := builtin.New()
	if err != nil {
		return false, err
	}
	eng, err := engine.New(reg, cfg, gate)
	if err != nil {
		return false, err
	}
	res, err := eng.Run(ctx, p)
	if err != nil {
		return false, fmt.Errorf("evaluate rules: %w", err)
	}
	logger.Debug("rules evaluated", "findings", len(res.Findings), "score", res.Score, "elapsed", time.Since(start))

	if err := renderer.Render(ctx, stdout, res); err != nil {
		return false, fmt.Errorf("render %s: %w", o.format, err)
	}
	return res.Gate.Failed, nil
}

// buildGate merges CLI flags over config values over defaults.
func buildGate(o options, cfg config.Config) (engine.Gate, error) {
	g := engine.Gate{}
	switch {
	case o.failOn == "none":
	case o.failOn != "":
		s, err := rules.ParseSeverity(o.failOn)
		if err != nil {
			return g, fmt.Errorf("--fail-on: %w", err)
		}
		g.FailOn = &s
	case cfg.FailOnNone:
	case cfg.FailOn != nil:
		g.FailOn = cfg.FailOn
	default:
		s := rules.SeverityCritical
		g.FailOn = &s
	}
	switch {
	case o.maxScore >= 0:
		g.MaxScore = &o.maxScore
	case cfg.MaxScore != nil:
		g.MaxScore = cfg.MaxScore
	}
	return g, nil
}

func openInput(ctx context.Context, o options, stdin io.Reader, logger *slog.Logger) (io.Reader, error) {
	if o.terraformBin != "" {
		logger.Debug("converting binary plan", "terraform", o.terraformBin, "plan", o.input)
		var stdout, stderr bytes.Buffer
		cmd := exec.CommandContext(ctx, o.terraformBin, "show", "-json", o.input)
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("%s show -json %s: %w: %s", o.terraformBin, o.input, err, strings.TrimSpace(stderr.String()))
		}
		return &stdout, nil
	}
	if o.input == "" || o.input == "-" {
		return stdin, nil
	}
	f, err := os.Open(o.input)
	if err != nil {
		return nil, fmt.Errorf("open plan: %w", err)
	}
	return f, nil
}

func colorEnabled(o options, stdout io.Writer, getenv func(string) string) bool {
	if o.noColor || getenv("NO_COLOR") != "" || getenv("TERM") == "dumb" {
		return false
	}
	f, ok := stdout.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func toolVersion() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
		return bi.Main.Version
	}
	return "(devel)"
}
