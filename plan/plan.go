// Package plan parses the JSON representation of a Terraform plan
// (`terraform show -json plan.bin`) into a small internal model that rules
// can evaluate without depending on the full Terraform JSON schema.
//
// Sensitive values are redacted during parsing: anything marked in
// before_sensitive / after_sensitive is replaced with [Redacted] so that no
// downstream code (rules, renderers) can leak it.
package plan

import (
	"fmt"
	"strconv"
	"strings"
)

// Action is the normalised action Terraform will take on a resource instance.
type Action string

// Actions as they appear in reports. Terraform encodes a replacement as two
// actions ("delete","create" or "create","delete"); both collapse to
// ActionReplace and the order is kept in [Change.ReplaceOrder].
const (
	ActionNoOp    Action = "no-op"
	ActionCreate  Action = "create"
	ActionRead    Action = "read"
	ActionUpdate  Action = "update"
	ActionDelete  Action = "delete"
	ActionReplace Action = "replace"
	// ActionForget removes an object from state without destroying it
	// (a `removed` block with `destroy = false`).
	ActionForget Action = "forget"
)

// ReplaceOrder records in which order Terraform performs a replacement.
type ReplaceOrder int

// Replacement orders.
const (
	// ReplaceNone means the change is not a replacement.
	ReplaceNone ReplaceOrder = iota
	// DeleteBeforeCreate is Terraform's default: the old object is destroyed
	// first, so there is a window where the resource does not exist.
	DeleteBeforeCreate
	// CreateBeforeDestroy is used when lifecycle.create_before_destroy is set
	// (directly or inherited from a dependent resource).
	CreateBeforeDestroy
)

// String implements fmt.Stringer.
func (o ReplaceOrder) String() string {
	switch o {
	case DeleteBeforeCreate:
		return "delete-before-create"
	case CreateBeforeDestroy:
		return "create-before-destroy"
	default:
		return "none"
	}
}

// Mode distinguishes managed resources from data sources.
const (
	ModeManaged = "managed"
	ModeData    = "data"
)

// Plan is the parsed subset of a Terraform JSON plan.
type Plan struct {
	FormatVersion    string
	TerraformVersion string
	Changes          []Change
}

// Change is one entry of resource_changes, i.e. one resource instance.
type Change struct {
	Address         string // module.app.aws_db_instance.main["blue"]
	PreviousAddress string // set when the object was moved
	ModuleAddress   string // module.app; empty for the root module
	Mode            string // managed | data
	Type            string // aws_db_instance
	Name            string // main
	Index           any    // count/for_each key; nil when absent
	ProviderName    string // registry.terraform.io/hashicorp/aws
	Deposed         string // deposed object key, if any

	Action       Action
	ReplaceOrder ReplaceOrder
	// ActionReason is Terraform's action_reason, e.g.
	// "replace_because_tainted" or "delete_because_no_resource_config".
	ActionReason string
	// ReplacePaths lists attribute paths that force the replacement.
	// Elements are strings (attribute names, map keys) or ints (list indices).
	ReplacePaths [][]any

	// Before and After are the object values; nil when the object does not
	// exist on that side (create / delete). Sensitive leaves are [Redacted].
	Before map[string]any
	After  map[string]any
	// AfterUnknown mirrors After with `true` at paths known only after apply.
	AfterUnknown map[string]any
}

// IsReplace reports whether the change destroys and recreates the object.
func (c Change) IsReplace() bool { return c.Action == ActionReplace }

// Destroys reports whether the existing object is destroyed by this change.
func (c Change) Destroys() bool {
	return c.Action == ActionDelete || c.Action == ActionReplace
}

// BeforeValue returns the value at path in Before.
func (c Change) BeforeValue(path ...any) (any, bool) { return Lookup(c.Before, path...) }

// AfterValue returns the value at path in After. The second result is false
// when the path is absent or its value is unknown until apply.
func (c Change) AfterValue(path ...any) (any, bool) {
	if c.IsUnknown(path...) {
		return nil, false
	}
	return Lookup(c.After, path...)
}

// IsUnknown reports whether the value at path (or any of its ancestors) is
// known only after apply.
func (c Change) IsUnknown(path ...any) bool {
	var cur any = c.AfterUnknown
	for i := 0; ; i++ {
		if b, ok := cur.(bool); ok {
			return b
		}
		if i == len(path) {
			return false
		}
		next, ok := step(cur, path[i])
		if !ok {
			return false
		}
		cur = next
	}
}

// Redacted replaces sensitive values. It renders as "(sensitive)" in text and
// JSON so the original value can never reach a report.
type Redacted struct{}

// String implements fmt.Stringer.
func (Redacted) String() string { return "(sensitive)" }

// MarshalJSON implements json.Marshaler.
func (Redacted) MarshalJSON() ([]byte, error) { return []byte(`"(sensitive)"`), nil }

// Lookup walks m following path. Path elements are strings (object keys) or
// ints (list indices). The second result is false when the path is absent.
func Lookup(m map[string]any, path ...any) (any, bool) {
	if m == nil {
		return nil, false
	}
	var cur any = m
	for _, p := range path {
		next, ok := step(cur, p)
		if !ok {
			return nil, false
		}
		cur = next
	}
	return cur, true
}

func step(cur any, p any) (any, bool) {
	switch v := cur.(type) {
	case map[string]any:
		var k string
		switch t := p.(type) {
		case string:
			k = t
		case int:
			k = strconv.Itoa(t)
		default:
			return nil, false
		}
		r, ok := v[k]
		return r, ok
	case []any:
		var i int
		switch t := p.(type) {
		case int:
			i = t
		case float64:
			i = int(t)
		case string:
			n, err := strconv.Atoi(t)
			if err != nil {
				return nil, false
			}
			i = n
		default:
			return nil, false
		}
		if i >= 0 && i < len(v) {
			return v[i], true
		}
	}
	return nil, false
}

// FormatPath renders an attribute path the way Terraform users write it,
// e.g. ["ebs_block_device", 0, "volume_size"] -> ebs_block_device[0].volume_size.
func FormatPath(path []any) string {
	var b strings.Builder
	for i, p := range path {
		switch v := p.(type) {
		case string:
			if i > 0 {
				b.WriteByte('.')
			}
			b.WriteString(v)
		case float64:
			fmt.Fprintf(&b, "[%d]", int(v))
		case int:
			fmt.Fprintf(&b, "[%d]", v)
		default:
			fmt.Fprintf(&b, "[%v]", v)
		}
	}
	return b.String()
}
