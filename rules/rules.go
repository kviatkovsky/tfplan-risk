// Package rules defines the rule interfaces, findings, severities and the
// registry that the engine evaluates. Built-in rules live in sub-packages
// (rules/aws, rules/generic) and are assembled by rules/builtin.
package rules

import (
	"fmt"
	"strings"

	"github.com/kviatkovsky/tfplan-risk/plan"
)

// Severity ranks how risky a finding is. The zero value is SeverityInfo.
type Severity int

// Severities from least to most severe.
const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = [...]string{"info", "low", "medium", "high", "critical"}

// AllSeverities lists severities from most to least severe.
var AllSeverities = []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}

// String returns the lower-case name, e.g. "critical".
func (s Severity) String() string {
	if s < SeverityInfo || s > SeverityCritical {
		return fmt.Sprintf("severity(%d)", int(s))
	}
	return severityNames[s]
}

// ParseSeverity parses a case-insensitive severity name.
func ParseSeverity(name string) (Severity, error) {
	for i, n := range severityNames {
		if strings.EqualFold(name, n) {
			return Severity(i), nil
		}
	}
	return 0, fmt.Errorf("unknown severity %q (want one of: %s)", name, strings.Join(severityNames[:], ", "))
}

// MarshalText implements encoding.TextMarshaler.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (s *Severity) UnmarshalText(b []byte) error {
	v, err := ParseSeverity(string(b))
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// Category groups findings by the kind of risk.
type Category string

// Categories.
const (
	CategoryDataLoss     Category = "data-loss"
	CategorySecurity     Category = "security"
	CategoryAvailability Category = "availability"
	CategoryCost         Category = "cost"
	CategoryHygiene      Category = "hygiene"
)

// Finding is one risk detected in a plan.
type Finding struct {
	RuleID   string
	Severity Severity
	Category Category
	// Address is the resource address; empty for plan-level findings.
	Address string
	Action  plan.Action
	// Message says exactly what changed (attribute, old -> new) and why it is
	// risky. It must never contain sensitive values.
	Message string
	// Suggestion says how to make the change safe.
	Suggestion string
}

// Meta describes a rule for listings, documentation and `explain`.
type Meta struct {
	ID       string
	Title    string
	Category Category
	// Severity is the highest severity the rule emits by default; individual
	// findings may be lower (e.g. open port 8080 vs. open port 5432).
	Severity    Severity
	Description string
	// Checks lists the resource types and attributes inspected.
	Checks []string
	// Example is a short HCL snippet that triggers the rule.
	Example    string
	Suggestion string
}

// Rule evaluates one resource change at a time.
type Rule interface {
	Meta() Meta
	// Evaluate is called for every managed resource change whose action is
	// not no-op. It must not retain c and must tolerate unknown and
	// redacted values.
	Evaluate(c plan.Change) []Finding
}

// PlanRule evaluates the whole plan at once, for risks that only emerge in
// aggregate (e.g. "more than N deletes").
type PlanRule interface {
	Meta() Meta
	EvaluatePlan(p *plan.Plan) []Finding
}

// Configurable is implemented by rules that accept options from the config
// file. decode unmarshals the rule's option block into v and rejects unknown
// keys, so rules only need to declare a typed struct.
type Configurable interface {
	Configure(decode func(v any) error) error
}

// StatefulTypesExtender is implemented by rules that use the list of stateful
// resource types, so the top-level `stateful_types_extra` config can extend it.
type StatefulTypesExtender interface {
	AddStatefulTypes(patterns []string)
}

// New returns a finding pre-filled from meta and the change.
func New(m Meta, c plan.Change, sev Severity, msg string) Finding {
	return Finding{
		RuleID:     m.ID,
		Severity:   sev,
		Category:   m.Category,
		Address:    c.Address,
		Action:     c.Action,
		Message:    msg,
		Suggestion: m.Suggestion,
	}
}
