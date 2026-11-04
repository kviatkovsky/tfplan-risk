// Package builtin assembles the registry of built-in rules.
package builtin

import (
	"fmt"

	"github.com/kviatkovsky/tfplan-risk/rules"
	"github.com/kviatkovsky/tfplan-risk/rules/aws"
)

// New returns a registry with fresh instances of every built-in rule. Rules
// may hold configuration, so each engine should get its own registry.
func New() (*rules.Registry, error) {
	r := rules.NewRegistry()
	err := r.Register(
		aws.NewStatefulDestroy(),
		aws.NewSGOpenIngress(),
		aws.NewIAMWildcard(),
	)
	if err != nil {
		return nil, fmt.Errorf("register built-in rules: %w", err)
	}
	return r, nil
}
