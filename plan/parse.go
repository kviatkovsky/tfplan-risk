package plan

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// ErrNotPlanJSON is returned when the input is valid JSON but not a Terraform
// plan, or not JSON at all.
var ErrNotPlanJSON = errors.New("input is not a Terraform JSON plan")

// rawPlan mirrors the parts of the Terraform JSON plan format we use.
// See https://developer.hashicorp.com/terraform/internals/json-format.
type rawPlan struct {
	FormatVersion    string              `json:"format_version"`
	TerraformVersion string              `json:"terraform_version"`
	ResourceChanges  []rawResourceChange `json:"resource_changes"`
	PlannedValues    json.RawMessage     `json:"planned_values"`
	Values           json.RawMessage     `json:"values"`
}

type rawResourceChange struct {
	Address         string    `json:"address"`
	PreviousAddress string    `json:"previous_address"`
	ModuleAddress   string    `json:"module_address"`
	Mode            string    `json:"mode"`
	Type            string    `json:"type"`
	Name            string    `json:"name"`
	Index           any       `json:"index"`
	ProviderName    string    `json:"provider_name"`
	Deposed         string    `json:"deposed"`
	Change          rawChange `json:"change"`
	ActionReason    string    `json:"action_reason"`
}

type rawChange struct {
	Actions         []string `json:"actions"`
	Before          any      `json:"before"`
	After           any      `json:"after"`
	AfterUnknown    any      `json:"after_unknown"`
	BeforeSensitive any      `json:"before_sensitive"`
	AfterSensitive  any      `json:"after_sensitive"`
	ReplacePaths    [][]any  `json:"replace_paths"`
}

// Parse reads a Terraform JSON plan from r.
//
// Only format_version 1.x is accepted: Terraform promises that minor version
// bumps are backwards compatible, a major bump is not.
func Parse(ctx context.Context, r io.Reader) (*Plan, error) {
	br := bufio.NewReader(r)
	if err := sniff(br); err != nil {
		return nil, err
	}

	var raw rawPlan
	dec := json.NewDecoder(br)
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("%w: decode: %w", ErrNotPlanJSON, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if raw.FormatVersion == "" {
		return nil, fmt.Errorf("%w: missing format_version", ErrNotPlanJSON)
	}
	if raw.ResourceChanges == nil && raw.PlannedValues == nil && raw.Values != nil {
		return nil, fmt.Errorf("%w: this looks like state JSON (`terraform show -json` without a plan file)", ErrNotPlanJSON)
	}
	if major, _, _ := strings.Cut(raw.FormatVersion, "."); major != "1" {
		return nil, fmt.Errorf("unsupported plan format_version %q: only 1.x is supported", raw.FormatVersion)
	}

	p := &Plan{
		FormatVersion:    raw.FormatVersion,
		TerraformVersion: raw.TerraformVersion,
		Changes:          make([]Change, 0, len(raw.ResourceChanges)),
	}
	for i, rc := range raw.ResourceChanges {
		if i%1024 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		c, err := convert(rc)
		if err != nil {
			return nil, fmt.Errorf("resource_changes[%d] (%s): %w", i, rc.Address, err)
		}
		p.Changes = append(p.Changes, c)
	}
	return p, nil
}

// sniff gives a precise error for the two most common mistakes: piping the
// binary plan file, or piping human-readable plan output.
func sniff(br *bufio.Reader) error {
	for {
		b, err := br.Peek(1)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return fmt.Errorf("%w: empty input", ErrNotPlanJSON)
			}
			return fmt.Errorf("read input: %w", err)
		}
		switch b[0] {
		case ' ', '\t', '\r', '\n':
			if _, err := br.ReadByte(); err != nil {
				return fmt.Errorf("read input: %w", err)
			}
			continue
		case '{':
			return nil
		}
		head, _ := br.Peek(2)
		if bytes.Equal(head, []byte("PK")) {
			return fmt.Errorf("%w: got a binary plan file; convert it with `terraform show -json plan.bin` or pass --terraform-bin", ErrNotPlanJSON)
		}
		return fmt.Errorf("%w: expected a JSON object (use `terraform show -json plan.bin`)", ErrNotPlanJSON)
	}
}

func convert(rc rawResourceChange) (Change, error) {
	action, order, err := normaliseActions(rc.Change.Actions)
	if err != nil {
		return Change{}, err
	}
	mode := rc.Mode
	if mode == "" {
		mode = ModeManaged
	}
	return Change{
		Address:         rc.Address,
		PreviousAddress: rc.PreviousAddress,
		ModuleAddress:   rc.ModuleAddress,
		Mode:            mode,
		Type:            rc.Type,
		Name:            rc.Name,
		Index:           rc.Index,
		ProviderName:    rc.ProviderName,
		Deposed:         rc.Deposed,
		Action:          action,
		ReplaceOrder:    order,
		ActionReason:    rc.ActionReason,
		ReplacePaths:    rc.Change.ReplacePaths,
		Before:          asObject(redact(rc.Change.Before, rc.Change.BeforeSensitive)),
		After:           asObject(redact(rc.Change.After, rc.Change.AfterSensitive)),
		AfterUnknown:    asObject(rc.Change.AfterUnknown),
	}, nil
}

func normaliseActions(actions []string) (Action, ReplaceOrder, error) {
	switch len(actions) {
	case 1:
		switch a := Action(actions[0]); a {
		case ActionNoOp, ActionCreate, ActionRead, ActionUpdate, ActionDelete, ActionForget:
			return a, ReplaceNone, nil
		}
	case 2:
		switch {
		case actions[0] == "delete" && actions[1] == "create":
			return ActionReplace, DeleteBeforeCreate, nil
		case actions[0] == "create" && actions[1] == "delete":
			return ActionReplace, CreateBeforeDestroy, nil
		}
	}
	return "", ReplaceNone, fmt.Errorf("unsupported change.actions %q", actions)
}

// redact replaces every value whose mask entry is `true` with Redacted.
// Terraform's sensitivity masks mirror the value's structure; a bare `true`
// marks the whole subtree.
func redact(v, mask any) any {
	if b, ok := mask.(bool); ok {
		if b && v != nil {
			return Redacted{}
		}
		return v
	}
	switch m := mask.(type) {
	case map[string]any:
		obj, ok := v.(map[string]any)
		if !ok {
			return v
		}
		for k, sub := range m {
			if val, present := obj[k]; present {
				obj[k] = redact(val, sub)
			}
		}
		return obj
	case []any:
		list, ok := v.([]any)
		if !ok {
			return v
		}
		for i := range list {
			if i < len(m) {
				list[i] = redact(list[i], m[i])
			}
		}
		return list
	}
	return v
}

func asObject(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}
