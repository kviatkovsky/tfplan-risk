// Package aws contains built-in rules for the hashicorp/aws provider.
package aws

import (
	"fmt"
	"slices"
	"strings"

	"github.com/kviatkovsky/tfplan-risk/internal/glob"
	"github.com/kviatkovsky/tfplan-risk/plan"
	"github.com/kviatkovsky/tfplan-risk/rules"
)

// DefaultStatefulTypes are resource types whose destruction loses data that
// Terraform cannot recreate.
var DefaultStatefulTypes = []string{
	"aws_db_instance",
	"aws_rds_cluster",
	"aws_dynamodb_table",
	"aws_s3_bucket",
	"aws_ebs_volume",
	"aws_efs_file_system",
	"aws_elasticache_cluster",
	"aws_elasticache_replication_group",
	"aws_elasticache_serverless_cache",
	"aws_kms_key",
	"aws_secretsmanager_secret",
	"aws_msk_cluster",
	"aws_msk_serverless_cluster",
	"aws_kinesis_stream",
	"aws_sqs_queue",
}

// typeNotes adds type-specific context to the data-loss message.
var typeNotes = map[string]string{
	"aws_kms_key":               "data encrypted with this key becomes unreadable once the deletion window ends",
	"aws_secretsmanager_secret": "the secret value is lost once the recovery window ends",
	"aws_s3_bucket":             "all objects are lost (the delete fails on a non-empty bucket unless force_destroy = true)",
	"aws_sqs_queue":             "in-flight messages are lost",
	"aws_kinesis_stream":        "unconsumed records are lost",
}

// StatefulDestroy flags delete or replace of resources that hold data.
type StatefulDestroy struct {
	patterns []string
}

// NewStatefulDestroy returns the rule with DefaultStatefulTypes.
func NewStatefulDestroy() *StatefulDestroy {
	return &StatefulDestroy{patterns: slices.Clone(DefaultStatefulTypes)}
}

// Meta implements rules.Rule.
func (r *StatefulDestroy) Meta() rules.Meta {
	return rules.Meta{
		ID:       "TPR-DATA-001",
		Title:    "Stateful resource deleted or replaced",
		Category: rules.CategoryDataLoss,
		Severity: rules.SeverityCritical,
		Description: "A resource that stores data is destroyed, either explicitly (delete) or as part of " +
			"a forced replacement. A replacement creates a new, empty resource: the data in the old one " +
			"is gone even if the address stays the same.",
		Checks: []string{
			"change.actions of: " + strings.Join(DefaultStatefulTypes, ", ") + " (extend with stateful_types_extra)",
			"replace_paths (which attributes force the replacement)",
			"action_reason (removed from config, tainted, -replace)",
		},
		Example: `resource "aws_db_instance" "main" {
  engine         = "postgres"
  engine_version = "16.1" # major upgrade on a resource where the change forces replacement
}`,
		Suggestion: "Snapshot or back up the data first. Add lifecycle { prevent_destroy = true } to stateful " +
			"resources. If this is a rename or refactor, use a `moved` block instead of delete+create. " +
			"For replacements, check whether the attribute can be changed in place (e.g. allow_major_version_upgrade).",
	}
}

// AddStatefulTypes implements rules.StatefulTypesExtender.
func (r *StatefulDestroy) AddStatefulTypes(patterns []string) {
	r.patterns = append(r.patterns, patterns...)
}

// Configure implements rules.Configurable.
func (r *StatefulDestroy) Configure(decode func(any) error) error {
	var opts struct {
		// ExtraTypes duplicates the top-level stateful_types_extra for
		// users who prefer to keep rule settings together.
		ExtraTypes []string `yaml:"extra_types"`
	}
	if err := decode(&opts); err != nil {
		return err
	}
	r.AddStatefulTypes(opts.ExtraTypes)
	return nil
}

// Evaluate implements rules.Rule.
func (r *StatefulDestroy) Evaluate(c plan.Change) []rules.Finding {
	if !c.Destroys() || !glob.MatchAny(r.patterns, c.Type) {
		return nil
	}

	var msg strings.Builder
	if c.IsReplace() {
		msg.WriteString("stateful resource replaced")
		if why := replaceCause(c); why != "" {
			msg.WriteString(" because " + why)
		}
		msg.WriteString(": the existing " + c.Type + " is destroyed and a new, empty one is created")
		if c.ReplaceOrder == plan.CreateBeforeDestroy {
			msg.WriteString(" (create_before_destroy does not migrate data)")
		}
	} else {
		msg.WriteString("stateful resource deleted")
		if why := deleteReason(c.ActionReason); why != "" {
			msg.WriteString(" (" + why + ")")
		}
	}
	msg.WriteString(" -> data loss")
	if note := typeNotes[c.Type]; note != "" {
		msg.WriteString("; " + note)
	}

	return []rules.Finding{rules.New(r.Meta(), c, rules.SeverityCritical, msg.String())}
}

// replaceCause explains why Terraform replaces the object.
func replaceCause(c plan.Change) string {
	switch c.ActionReason {
	case "replace_because_tainted":
		return "it is tainted"
	case "replace_by_request":
		return "of an explicit -replace request"
	case "replace_by_triggers":
		return "replace_triggered_by fired"
	}
	if len(c.ReplacePaths) == 0 {
		return ""
	}
	parts := make([]string, 0, len(c.ReplacePaths))
	for _, p := range c.ReplacePaths {
		parts = append(parts, fmt.Sprintf("%s %s -> %s", plan.FormatPath(p), rules.FormatBefore(c, p...), rules.FormatAfter(c, p...)))
	}
	const maxShown = 3
	if len(parts) > maxShown {
		parts = append(parts[:maxShown], fmt.Sprintf("and %d more", len(parts)-maxShown))
	}
	return strings.Join(parts, ", ") + " forces replacement"
}

func deleteReason(reason string) string {
	switch reason {
	case "delete_because_no_resource_config":
		return "removed from configuration"
	case "delete_because_no_module":
		return "its module was removed"
	case "delete_because_wrong_repetition":
		return "count/for_each switched"
	case "delete_because_count_index", "delete_because_each_key":
		return "count/for_each no longer includes this instance"
	case "delete_because_no_move_target":
		return "moved block target missing"
	}
	return ""
}
