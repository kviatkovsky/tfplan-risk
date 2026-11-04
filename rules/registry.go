package rules

import (
	"fmt"
	"regexp"
	"sort"
)

var idPattern = regexp.MustCompile(`^TPR-[A-Z]+-[0-9]{3}$`)

// Registry holds rule instances by ID. A Registry is not safe for concurrent
// registration; build it once, then share it read-only.
type Registry struct {
	change []Rule
	plan   []PlanRule
	byID   map[string]any
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{byID: make(map[string]any)}
}

// Register adds change-level rules.
func (r *Registry) Register(rs ...Rule) error {
	for _, rule := range rs {
		if err := r.add(rule.Meta(), rule); err != nil {
			return err
		}
		r.change = append(r.change, rule)
	}
	return nil
}

// RegisterPlan adds plan-level rules.
func (r *Registry) RegisterPlan(rs ...PlanRule) error {
	for _, rule := range rs {
		if err := r.add(rule.Meta(), rule); err != nil {
			return err
		}
		r.plan = append(r.plan, rule)
	}
	return nil
}

func (r *Registry) add(m Meta, rule any) error {
	if !idPattern.MatchString(m.ID) {
		return fmt.Errorf("rule ID %q does not match %s", m.ID, idPattern)
	}
	if _, dup := r.byID[m.ID]; dup {
		return fmt.Errorf("duplicate rule ID %q", m.ID)
	}
	if m.Title == "" || m.Description == "" || m.Category == "" {
		return fmt.Errorf("rule %s: title, description and category are required", m.ID)
	}
	r.byID[m.ID] = rule
	return nil
}

// Rules returns change-level rules in registration order.
func (r *Registry) Rules() []Rule { return r.change }

// PlanRules returns plan-level rules in registration order.
func (r *Registry) PlanRules() []PlanRule { return r.plan }

// Get returns the rule (a Rule or PlanRule) with the given ID.
func (r *Registry) Get(id string) (any, bool) {
	v, ok := r.byID[id]
	return v, ok
}

// Metas returns metadata of all rules sorted by ID.
func (r *Registry) Metas() []Meta {
	out := make([]Meta, 0, len(r.byID))
	for _, rule := range r.change {
		out = append(out, rule.Meta())
	}
	for _, rule := range r.plan {
		out = append(out, rule.Meta())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
