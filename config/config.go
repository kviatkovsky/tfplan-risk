// Package config loads and validates .tfplan-risk.yaml.
package config

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/kviatkovsky/tfplan-risk/rules"
)

// DefaultFile is looked up in the working directory when --config is not set.
const DefaultFile = ".tfplan-risk.yaml"

// Config is the parsed configuration file.
type Config struct {
	// FailOn is the minimum severity that fails the run; nil means unset
	// (the CLI default applies). FailOnNone disables the severity gate.
	FailOn *rules.Severity `yaml:"-"`
	// FailOnNone is true for `fail_on: none`.
	FailOnNone bool `yaml:"-"`
	// MaxScore fails the run when the risk score is above it; nil = unset.
	MaxScore           *int                  `yaml:"max_score"`
	Rules              map[string]RuleConfig `yaml:"rules"`
	Ignore             []Ignore              `yaml:"ignore"`
	StatefulTypesExtra []string              `yaml:"stateful_types_extra"`
}

// RuleConfig overrides one rule.
type RuleConfig struct {
	Enabled  *bool           `yaml:"enabled"`
	Severity *rules.Severity `yaml:"severity"`
	// Options holds rule-specific keys; the rule validates them.
	Options map[string]any `yaml:",inline"`
}

// Ignore suppresses findings. Suppressed findings still appear in JSON output.
type Ignore struct {
	// Address is a glob on the resource address (`*` and `?` only).
	Address string `yaml:"address"`
	// Rules are rule IDs or globs; empty means all rules.
	Rules []string `yaml:"rules"`
	// Reason is mandatory so that every suppression is reviewable.
	Reason string `yaml:"reason"`
}

// file is the on-disk shape; fail_on needs custom handling for "none".
type file struct {
	FailOn             string                `yaml:"fail_on"`
	MaxScore           *int                  `yaml:"max_score"`
	Rules              map[string]RuleConfig `yaml:"rules"`
	Ignore             []Ignore              `yaml:"ignore"`
	StatefulTypesExtra []string              `yaml:"stateful_types_extra"`
}

// Load reads the config at path. If path is empty, DefaultFile is used when
// it exists; otherwise an empty Config is returned.
func Load(ctx context.Context, path string) (Config, error) {
	explicit := path != ""
	if !explicit {
		path = DefaultFile
	}
	if err := ctx.Err(); err != nil {
		return Config{}, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if !explicit && errors.Is(err, os.ErrNotExist) {
			return Config{}, nil
		}
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	cfg, err := Parse(bytes.NewReader(b))
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// Parse decodes and validates a config document. Unknown keys are errors.
func Parse(r io.Reader) (Config, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	var f file
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return Config{}, friendly(err)
	}
	cfg := Config{
		MaxScore:           f.MaxScore,
		Rules:              f.Rules,
		Ignore:             f.Ignore,
		StatefulTypesExtra: f.StatefulTypesExtra,
	}
	switch strings.ToLower(f.FailOn) {
	case "":
	case "none":
		cfg.FailOnNone = true
	default:
		s, err := rules.ParseSeverity(f.FailOn)
		if err != nil {
			return Config{}, fmt.Errorf("fail_on: %w (or none)", err)
		}
		cfg.FailOn = &s
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) validate() error {
	var errs []error
	if c.MaxScore != nil && (*c.MaxScore < 0 || *c.MaxScore > 100) {
		errs = append(errs, fmt.Errorf("max_score: %d is outside 0-100", *c.MaxScore))
	}
	for i, ig := range c.Ignore {
		if strings.TrimSpace(ig.Address) == "" {
			errs = append(errs, fmt.Errorf("ignore[%d]: address is required (use \"*\" for all resources)", i))
		}
		if strings.TrimSpace(ig.Reason) == "" {
			errs = append(errs, fmt.Errorf("ignore[%d] (%s): reason is required so suppressions stay reviewable", i, ig.Address))
		}
	}
	for i, t := range c.StatefulTypesExtra {
		if strings.TrimSpace(t) == "" {
			errs = append(errs, fmt.Errorf("stateful_types_extra[%d]: empty type", i))
		}
	}
	return errors.Join(errs...)
}

var unknownField = regexp.MustCompile(`line (\d+): field (\S+) not found in type config\.(\w+)`)

var allowedKeys = map[string]string{
	"file":   "fail_on, max_score, rules, ignore, stateful_types_extra",
	"Ignore": "address, rules, reason",
}

// friendly rewrites yaml's Go-type-centric messages into config terms.
func friendly(err error) error {
	msg := unknownField.ReplaceAllStringFunc(err.Error(), func(m string) string {
		sub := unknownField.FindStringSubmatch(m)
		return fmt.Sprintf("line %s: unknown key %q (allowed: %s)", sub[1], sub[2], allowedKeys[sub[3]])
	})
	return fmt.Errorf("invalid config: %s", cleanYAMLError(msg))
}

// cleanYAMLError flattens yaml's multi-line "unmarshal errors" into one line.
func cleanYAMLError(msg string) string {
	msg = strings.TrimPrefix(msg, "yaml: ")
	msg = strings.TrimPrefix(msg, "unmarshal errors:")
	lines := strings.Split(msg, "\n")
	out := lines[:0]
	for _, l := range lines {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return strings.Join(out, "; ")
}

// DecodeOptions returns a decoder that unmarshals a rule's option map into
// a typed struct and rejects unknown keys. It is what rules.Configurable
// receives.
func DecodeOptions(ruleID string, opts map[string]any) func(v any) error {
	return func(v any) error {
		if len(opts) == 0 {
			return nil
		}
		b, err := yaml.Marshal(opts)
		if err != nil {
			return fmt.Errorf("rules.%s: %w", ruleID, err)
		}
		dec := yaml.NewDecoder(bytes.NewReader(b))
		dec.KnownFields(true)
		if err := dec.Decode(v); err != nil {
			msg := regexp.MustCompile(`line \d+: field (\S+) not found in type [\w.]+`).
				ReplaceAllString(err.Error(), "unknown option $1")
			return fmt.Errorf("rules.%s: %s", ruleID, cleanYAMLError(msg))
		}
		return nil
	}
}
