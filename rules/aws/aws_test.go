package aws

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/kviatkovsky/tfplan-risk/config"
	"github.com/kviatkovsky/tfplan-risk/plan"
	"github.com/kviatkovsky/tfplan-risk/rules"
)

// got is a compact, comparable view of a finding.
type got struct {
	Sev rules.Severity
	Msg string
}

func evaluate(r rules.Rule, c plan.Change) []got {
	var out []got
	for _, f := range r.Evaluate(c) {
		if f.RuleID != r.Meta().ID || f.Address != c.Address || f.Action != c.Action || f.Suggestion == "" {
			panic("finding not populated from meta/change: " + f.RuleID)
		}
		out = append(out, got{f.Severity, f.Message})
	}
	return out
}

func loadFixture(t *testing.T, name string) *plan.Plan {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "internal", "testdata", "plans", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	p, err := plan.Parse(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// fixtureFindings runs r over every change of a fixture, keyed by address.
func fixtureFindings(t *testing.T, r rules.Rule, fixture string) map[string][]got {
	t.Helper()
	out := map[string][]got{}
	for _, c := range loadFixture(t, fixture).Changes {
		if fs := evaluate(r, c); len(fs) > 0 {
			out[c.Address] = fs
		}
	}
	return out
}

func decoder(opts map[string]any) func(any) error {
	return config.DecodeOptions("TEST", opts)
}

func TestMetaComplete(t *testing.T) {
	t.Parallel()
	for _, r := range []rules.Rule{NewStatefulDestroy(), NewSGOpenIngress(), NewIAMWildcard()} {
		m := r.Meta()
		if m.ID == "" || m.Title == "" || m.Description == "" || m.Example == "" || m.Suggestion == "" || len(m.Checks) == 0 {
			t.Errorf("%s: incomplete meta %+v", m.ID, m)
		}
	}
}

func TestStatefulDestroy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		extra []string
		c     plan.Change
		want  []got
	}{
		{
			name: "bucket removed from config",
			c:    plan.Change{Address: "aws_s3_bucket.logs", Type: "aws_s3_bucket", Action: plan.ActionDelete, ActionReason: "delete_because_no_resource_config"},
			want: []got{{rules.SeverityCritical, "stateful resource deleted (removed from configuration) -> data loss; all objects are lost (the delete fails on a non-empty bucket unless force_destroy = true)"}},
		},
		{
			name: "db replaced by attribute",
			c: plan.Change{
				Address: "aws_db_instance.main", Type: "aws_db_instance", Action: plan.ActionReplace, ReplaceOrder: plan.DeleteBeforeCreate,
				ReplacePaths: [][]any{{"identifier"}},
				Before:       map[string]any{"identifier": "old"},
				After:        map[string]any{"identifier": "new"},
			},
			want: []got{{rules.SeverityCritical, `stateful resource replaced because identifier "old" -> "new" forces replacement: the existing aws_db_instance is destroyed and a new, empty one is created -> data loss`}},
		},
		{
			name: "create before destroy with unknown and many paths",
			c: plan.Change{
				Address: "aws_ebs_volume.data", Type: "aws_ebs_volume", Action: plan.ActionReplace, ReplaceOrder: plan.CreateBeforeDestroy,
				ReplacePaths: [][]any{{"a"}, {"b"}, {"c"}, {"d"}, {"e"}},
				Before:       map[string]any{"a": "1", "b": "1", "c": "1"},
				After:        map[string]any{"a": nil, "b": "2", "c": "2"},
				AfterUnknown: map[string]any{"a": true},
			},
			want: []got{{rules.SeverityCritical, `stateful resource replaced because a "1" -> (known after apply), b "1" -> "2", c "1" -> "2", and 2 more forces replacement: the existing aws_ebs_volume is destroyed and a new, empty one is created (create_before_destroy does not migrate data) -> data loss`}},
		},
		{
			name: "tainted",
			c:    plan.Change{Address: "aws_kms_key.k", Type: "aws_kms_key", Action: plan.ActionReplace, ActionReason: "replace_because_tainted"},
			want: []got{{rules.SeverityCritical, "stateful resource replaced because it is tainted: the existing aws_kms_key is destroyed and a new, empty one is created -> data loss; data encrypted with this key becomes unreadable once the deletion window ends"}},
		},
		{
			name: "replace by request, no extra note",
			c:    plan.Change{Address: "aws_dynamodb_table.t", Type: "aws_dynamodb_table", Action: plan.ActionReplace, ActionReason: "replace_by_request"},
			want: []got{{rules.SeverityCritical, "stateful resource replaced because of an explicit -replace request: the existing aws_dynamodb_table is destroyed and a new, empty one is created -> data loss"}},
		},
		{
			name: "replace by triggers without paths",
			c:    plan.Change{Address: "aws_sqs_queue.q", Type: "aws_sqs_queue", Action: plan.ActionReplace, ActionReason: "replace_by_triggers"},
			want: []got{{rules.SeverityCritical, "stateful resource replaced because replace_triggered_by fired: the existing aws_sqs_queue is destroyed and a new, empty one is created -> data loss; in-flight messages are lost"}},
		},
		{
			name: "replace with no reason",
			c:    plan.Change{Address: "aws_efs_file_system.f", Type: "aws_efs_file_system", Action: plan.ActionReplace},
			want: []got{{rules.SeverityCritical, "stateful resource replaced: the existing aws_efs_file_system is destroyed and a new, empty one is created -> data loss"}},
		},
		{
			name: "delete reasons",
			c:    plan.Change{Address: "aws_kinesis_stream.s[1]", Type: "aws_kinesis_stream", Action: plan.ActionDelete, ActionReason: "delete_because_count_index"},
			want: []got{{rules.SeverityCritical, "stateful resource deleted (count/for_each no longer includes this instance) -> data loss; unconsumed records are lost"}},
		},
		{
			name: "module removed",
			c:    plan.Change{Address: "module.m.aws_rds_cluster.c", Type: "aws_rds_cluster", Action: plan.ActionDelete, ActionReason: "delete_because_no_module"},
			want: []got{{rules.SeverityCritical, "stateful resource deleted (its module was removed) -> data loss"}},
		},
		{
			name:  "extra type via glob",
			extra: []string{"aws_opensearch_*"},
			c:     plan.Change{Address: "aws_opensearch_domain.d", Type: "aws_opensearch_domain", Action: plan.ActionDelete, ActionReason: "delete_because_wrong_repetition"},
			want:  []got{{rules.SeverityCritical, "stateful resource deleted (count/for_each switched) -> data loss"}},
		},
		{
			name: "missing move target",
			c:    plan.Change{Address: "aws_secretsmanager_secret.s", Type: "aws_secretsmanager_secret", Action: plan.ActionDelete, ActionReason: "delete_because_no_move_target"},
			want: []got{{rules.SeverityCritical, "stateful resource deleted (moved block target missing) -> data loss; the secret value is lost once the recovery window ends"}},
		},
		{name: "stateless type deleted", c: plan.Change{Address: "aws_lb.web", Type: "aws_lb", Action: plan.ActionDelete}},
		{name: "stateful type updated", c: plan.Change{Address: "aws_s3_bucket.b", Type: "aws_s3_bucket", Action: plan.ActionUpdate}},
		{name: "stateful type forgotten", c: plan.Change{Address: "aws_s3_bucket.b", Type: "aws_s3_bucket", Action: plan.ActionForget}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := NewStatefulDestroy()
			r.AddStatefulTypes(tt.extra)
			if diff := cmp.Diff(tt.want, evaluate(r, tt.c)); diff != "" {
				t.Errorf("Evaluate() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestStatefulDestroyConfigure(t *testing.T) {
	t.Parallel()
	r := NewStatefulDestroy()
	if err := r.Configure(decoder(map[string]any{"extra_types": []string{"aws_neptune_cluster"}})); err != nil {
		t.Fatal(err)
	}
	if len(evaluate(r, plan.Change{Type: "aws_neptune_cluster", Action: plan.ActionDelete})) != 1 {
		t.Error("extra_types not applied")
	}
	if err := r.Configure(func(any) error { return errors.New("boom") }); err == nil {
		t.Error("Configure() must propagate decode errors")
	}
}

func TestStatefulDestroyFixtures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		fixture string
		want    map[string][]got
	}{
		{"s3-delete", map[string][]got{
			"aws_s3_bucket.logs": {{rules.SeverityCritical, "stateful resource deleted (removed from configuration) -> data loss; all objects are lost (the delete fails on a non-empty bucket unless force_destroy = true)"}},
		}},
		{"rds-replace", map[string][]got{
			"aws_db_instance.main": {{rules.SeverityCritical, "stateful resource replaced because storage_encrypted false -> true forces replacement: the existing aws_db_instance is destroyed and a new, empty one is created -> data loss"}},
		}},
		{"sg-open-db-port", map[string][]got{}},
	}
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			t.Parallel()
			if diff := cmp.Diff(tt.want, fixtureFindings(t, NewStatefulDestroy(), tt.fixture)); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func ingress(port float64, cidr string) map[string]any {
	return map[string]any{"from_port": port, "to_port": port, "protocol": "tcp", "cidr_blocks": []any{cidr}, "ipv6_cidr_blocks": []any{}}
}

func TestSGOpenIngress(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		opts map[string]any
		c    plan.Change
		want []got
	}{
		{
			name: "inline ingress added to existing group",
			c: plan.Change{
				Type: "aws_security_group", Action: plan.ActionUpdate,
				Before: map[string]any{"ingress": []any{ingress(5432, "10.0.0.0/16")}},
				After:  map[string]any{"ingress": []any{ingress(5432, "10.0.0.0/16"), ingress(5432, "0.0.0.0/0")}},
			},
			want: []got{{rules.SeverityCritical, "ingress from 0.0.0.0/0 on port 5432/tcp (PostgreSQL)"}},
		},
		{
			name: "already open before is not reported",
			c: plan.Change{
				Type: "aws_security_group", Action: plan.ActionUpdate,
				Before: map[string]any{"ingress": []any{ingress(22, "0.0.0.0/0")}},
				After:  map[string]any{"ingress": []any{ingress(22, "0.0.0.0/0")}, "tags": map[string]any{"a": "b"}},
			},
		},
		{
			name: "legacy rule, ipv6, port range including critical port",
			c: plan.Change{
				Type: "aws_security_group_rule", Action: plan.ActionCreate,
				After: map[string]any{"type": "ingress", "from_port": float64(3000), "to_port": float64(3400), "protocol": "6",
					"cidr_blocks": []any{"10.0.0.0/8"}, "ipv6_cidr_blocks": []any{"::/0"}},
			},
			want: []got{{rules.SeverityCritical, "ingress from ::/0 on ports 3000-3400/tcp (includes 3306 MySQL)"}},
		},
		{
			name: "legacy egress rule ignored",
			c: plan.Change{
				Type: "aws_security_group_rule", Action: plan.ActionCreate,
				After: map[string]any{"type": "egress", "from_port": float64(0), "to_port": float64(0), "protocol": "-1", "cidr_blocks": []any{"0.0.0.0/0"}},
			},
		},
		{
			name: "vpc rule all traffic",
			c: plan.Change{
				Type: "aws_vpc_security_group_ingress_rule", Action: plan.ActionCreate,
				After: map[string]any{"ip_protocol": "-1", "cidr_ipv4": "0.0.0.0/0", "from_port": nil, "to_port": nil},
			},
			want: []got{{rules.SeverityCritical, "ingress from 0.0.0.0/0 on all ports (all)"}},
		},
		{
			name: "vpc rule non-critical port is high",
			c: plan.Change{
				Type: "aws_vpc_security_group_ingress_rule", Action: plan.ActionCreate,
				After: map[string]any{"ip_protocol": "udp", "cidr_ipv4": "0.0.0.0/0", "from_port": float64(8080), "to_port": float64(8080)},
			},
			want: []got{{rules.SeverityHigh, "ingress from 0.0.0.0/0 on port 8080/udp"}},
		},
		{
			name: "tcp full range is critical",
			c: plan.Change{
				Type: "aws_vpc_security_group_ingress_rule", Action: plan.ActionReplace,
				After: map[string]any{"ip_protocol": "tcp", "cidr_ipv4": "0.0.0.0/0", "from_port": float64(0), "to_port": float64(65535)},
			},
			want: []got{{rules.SeverityCritical, "ingress from 0.0.0.0/0 on all ports (tcp)"}},
		},
		{
			name: "allowed https",
			c: plan.Change{
				Type: "aws_vpc_security_group_ingress_rule", Action: plan.ActionCreate,
				After: map[string]any{"ip_protocol": "tcp", "cidr_ipv6": "::/0", "from_port": float64(443), "to_port": float64(443)},
			},
		},
		{
			name: "range spanning allowed ports is not allowed",
			c: plan.Change{
				Type: "aws_vpc_security_group_ingress_rule", Action: plan.ActionCreate,
				After: map[string]any{"ip_protocol": "tcp", "cidr_ipv4": "0.0.0.0/0", "from_port": float64(80), "to_port": float64(81)},
			},
			want: []got{{rules.SeverityHigh, "ingress from 0.0.0.0/0 on ports 80-81/tcp"}},
		},
		{
			name: "custom options",
			opts: map[string]any{"allow_ports": []int{8080}, "critical_ports": []int{80, 9999}},
			c: plan.Change{
				Type: "aws_security_group", Action: plan.ActionCreate,
				After: map[string]any{"ingress": []any{ingress(8080, "0.0.0.0/0"), ingress(80, "0.0.0.0/0"), ingress(9999, "0.0.0.0/0")}},
			},
			want: []got{
				{rules.SeverityCritical, "ingress from 0.0.0.0/0 on port 80/tcp"},
				{rules.SeverityCritical, "ingress from 0.0.0.0/0 on port 9999/tcp"},
			},
		},
		{
			name: "icmp ignored",
			c: plan.Change{
				Type: "aws_vpc_security_group_ingress_rule", Action: plan.ActionCreate,
				After: map[string]any{"ip_protocol": "icmp", "cidr_ipv4": "0.0.0.0/0", "from_port": float64(-1), "to_port": float64(-1)},
			},
		},
		{
			name: "unknown cidr is not reported",
			c: plan.Change{
				Type: "aws_vpc_security_group_ingress_rule", Action: plan.ActionCreate,
				After:        map[string]any{"ip_protocol": "tcp", "cidr_ipv4": nil, "from_port": float64(22), "to_port": float64(22)},
				AfterUnknown: map[string]any{"cidr_ipv4": true},
			},
		},
		{
			name: "other protocol number",
			c: plan.Change{
				Type: "aws_vpc_security_group_ingress_rule", Action: plan.ActionCreate,
				After: map[string]any{"ip_protocol": "50", "cidr_ipv4": "0.0.0.0/0", "from_port": float64(0), "to_port": float64(0)},
			},
			want: []got{{rules.SeverityHigh, "ingress from 0.0.0.0/0 on port 0/50"}},
		},
		{name: "delete ignored", c: plan.Change{Type: "aws_security_group", Action: plan.ActionDelete, Before: map[string]any{"ingress": []any{ingress(22, "0.0.0.0/0")}}}},
		{name: "unrelated type", c: plan.Change{Type: "aws_instance", Action: plan.ActionCreate, After: map[string]any{"cidr_ipv4": "0.0.0.0/0"}}},
		{name: "malformed ingress entries", c: plan.Change{Type: "aws_security_group", Action: plan.ActionCreate, After: map[string]any{"ingress": []any{"x", map[string]any{"protocol": nil}}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := NewSGOpenIngress()
			if tt.opts != nil {
				if err := r.Configure(decoder(tt.opts)); err != nil {
					t.Fatal(err)
				}
			}
			if diff := cmp.Diff(tt.want, evaluate(r, tt.c)); diff != "" {
				t.Errorf("Evaluate() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSGOpenIngressConfigureErrors(t *testing.T) {
	t.Parallel()
	for _, opts := range []map[string]any{
		{"allow_ports": []int{70000}},
		{"critical_ports": []int{-1}},
	} {
		if err := NewSGOpenIngress().Configure(decoder(opts)); err == nil {
			t.Errorf("Configure(%v) want error", opts)
		}
	}
	if err := NewSGOpenIngress().Configure(func(any) error { return errors.New("boom") }); err == nil {
		t.Error("Configure() must propagate decode errors")
	}
}

func TestSGOpenIngressFixture(t *testing.T) {
	t.Parallel()
	want := map[string][]got{
		"aws_security_group.db":                   {{rules.SeverityCritical, "ingress from 0.0.0.0/0 on port 5432/tcp (PostgreSQL)"}},
		"aws_vpc_security_group_ingress_rule.ssh": {{rules.SeverityCritical, "ingress from 0.0.0.0/0 on port 22/tcp (SSH)"}},
	}
	if diff := cmp.Diff(want, fixtureFindings(t, NewSGOpenIngress(), "sg-open-db-port")); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func doc(statements string) string {
	return `{"Version":"2012-10-17","Statement":` + statements + `}`
}

func TestIAMWildcard(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		c    plan.Change
		want []got
	}{
		{
			name: "admin statement added",
			c: plan.Change{
				Type: "aws_iam_policy", Action: plan.ActionUpdate,
				Before: map[string]any{"policy": doc(`[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]`)},
				After:  map[string]any{"policy": doc(`[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"},{"Sid":"All","Effect":"Allow","Action":"*","Resource":"*"}]`)},
			},
			want: []got{{rules.SeverityCritical, `policy: statement "All": Action "*" on Resource "*" (full administrator access) (added)`}},
		},
		{
			name: "single statement object, action star on scoped resource",
			c: plan.Change{
				Type: "aws_iam_role_policy", Action: plan.ActionCreate,
				After: map[string]any{"policy": doc(`{"Effect":"Allow","Action":["*"],"Resource":["arn:aws:s3:::b","arn:aws:s3:::b/*"]}`)},
			},
			want: []got{{rules.SeverityHigh, `policy: statement 0: Action "*" grants every action on arn:aws:s3:::b, arn:aws:s3:::b/*`}},
		},
		{
			name: "not action, pass role, service wildcards, writes",
			c: plan.Change{
				Type: "aws_iam_user_policy", Action: plan.ActionCreate,
				After: map[string]any{"policy": doc(`[
					{"Effect":"Allow","NotAction":"iam:*","Resource":"*"},
					{"Effect":"Allow","Action":["iam:Pass*","s3:*","kms:*","ec2:Describe*","s3:PutObject","s3:DeleteObject","sqs:SendMessage","sns:Publish","lambda:InvokeFunction","dynamodb:PutItem"],"Resource":"*"},
					{"Effect":"Deny","Action":"*","Resource":"*"},
					{"Effect":"Allow","Action":"s3:PutObject","Resource":"arn:aws:s3:::b/*"}]`)},
			},
			want: []got{
				{rules.SeverityHigh, "policy: statement 0: Allow with NotAction grants every action except the listed ones"},
				{rules.SeverityHigh, `policy: statement 1: "iam:Pass*" on Resource "*" lets the principal pass any role to a service (privilege escalation)`},
				{rules.SeverityMedium, `policy: statement 1: Action "s3:*" on Resource "*"`},
				{rules.SeverityHigh, `policy: statement 1: Action "kms:*" on Resource "*"`},
				{rules.SeverityMedium, `policy: statement 1: write actions s3:PutObject, s3:DeleteObject, sqs:SendMessage, sns:Publish, lambda:InvokeFunction and 1 more on Resource "*"`},
			},
		},
		{
			name: "role inline policy and managed admin attachment",
			c: plan.Change{
				Type: "aws_iam_role", Action: plan.ActionUpdate,
				Before: map[string]any{"managed_policy_arns": []any{"arn:aws:iam::aws:policy/ReadOnlyAccess"}},
				After: map[string]any{
					"inline_policy":       []any{map[string]any{"name": "p", "policy": doc(`{"Effect":"Allow","Action":"iam:PassRole","Resource":"*"}`)}},
					"managed_policy_arns": []any{"arn:aws:iam::aws:policy/ReadOnlyAccess", "arn:aws:iam::aws:policy/AdministratorAccess", "arn:aws:iam::123456789012:policy/AdministratorAccess"},
				},
			},
			want: []got{
				{rules.SeverityHigh, `inline_policy[0].policy: statement 0: "iam:PassRole" on Resource "*" lets the principal pass any role to a service (privilege escalation) (added)`},
				{rules.SeverityCritical, "managed_policy_arns: attaches AWS managed policy AdministratorAccess"},
			},
		},
		{
			name: "attachment",
			c: plan.Change{
				Type: "aws_iam_group_policy_attachment", Action: plan.ActionCreate,
				After: map[string]any{"policy_arn": "arn:aws:iam::aws:policy/PowerUserAccess"},
			},
			want: []got{{rules.SeverityHigh, "policy_arn: attaches AWS managed policy PowerUserAccess"}},
		},
		{
			name: "harmless attachment",
			c: plan.Change{
				Type: "aws_iam_role_policy_attachment", Action: plan.ActionCreate,
				After: map[string]any{"policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess"},
			},
		},
		{
			name: "unknown policy",
			c: plan.Change{
				Type: "aws_iam_group_policy", Action: plan.ActionCreate,
				After: map[string]any{"policy": nil}, AfterUnknown: map[string]any{"policy": true},
			},
			want: []got{{rules.SeverityInfo, "policy is known only after apply; wildcard grants cannot be checked, review it manually"}},
		},
		{
			name: "invalid policy json",
			c: plan.Change{
				Type: "aws_iam_policy", Action: plan.ActionCreate,
				After: map[string]any{"policy": "{not json"},
			},
			want: []got{{rules.SeverityInfo, "policy is not a valid policy document (invalid character 'n' looking for beginning of object key string); review it manually"}},
		},
		{
			name: "invalid statement shape",
			c: plan.Change{
				Type: "aws_iam_policy", Action: plan.ActionCreate,
				After: map[string]any{"policy": `{"Statement":{"Effect":1}}`},
			},
			want: []got{{rules.SeverityInfo, "policy is not a valid policy document (json: cannot unmarshal number into Go struct field statement.Effect of type string); review it manually"}},
		},
		{
			name: "invalid statement list",
			c: plan.Change{
				Type: "aws_iam_policy", Action: plan.ActionCreate,
				After: map[string]any{"policy": `{"Statement":"x"}`},
			},
			want: []got{{rules.SeverityInfo, "policy is not a valid policy document (json: cannot unmarshal string into Go value of type []aws.statement); review it manually"}},
		},
		{name: "read only on star", c: plan.Change{Type: "aws_iam_policy", Action: plan.ActionCreate, After: map[string]any{"policy": doc(`{"Effect":"Allow","Action":["s3:Get*","s3:ListBucket"],"Resource":"*"}`)}}},
		{name: "empty policy", c: plan.Change{Type: "aws_iam_policy", Action: plan.ActionCreate, After: map[string]any{"policy": ""}}},
		{name: "no statements", c: plan.Change{Type: "aws_iam_policy", Action: plan.ActionCreate, After: map[string]any{"policy": `{"Version":"2012-10-17"}`}}},
		{name: "delete ignored", c: plan.Change{Type: "aws_iam_policy", Action: plan.ActionDelete, Before: map[string]any{"policy": doc(`{"Effect":"Allow","Action":"*","Resource":"*"}`)}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if diff := cmp.Diff(tt.want, evaluate(NewIAMWildcard(), tt.c)); diff != "" {
				t.Errorf("Evaluate() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIAMWildcardFixture(t *testing.T) {
	t.Parallel()
	want := map[string][]got{
		"aws_iam_policy.ci":                       {{rules.SeverityCritical, `policy: statement "Everything": Action "*" on Resource "*" (full administrator access) (added)`}},
		"aws_iam_role_policy_attachment.ci_admin": {{rules.SeverityCritical, "policy_arn: attaches AWS managed policy AdministratorAccess"}},
		"aws_iam_role_policy.launcher": {
			{rules.SeverityHigh, `policy: statement 0: "iam:PassRole" on Resource "*" lets the principal pass any role to a service (privilege escalation)`},
			{rules.SeverityMedium, `policy: statement 0: write actions ec2:RunInstances on Resource "*"`},
		},
		"aws_iam_role_policy.generated": {{rules.SeverityInfo, "policy is known only after apply; wildcard grants cannot be checked, review it manually"}},
	}
	if diff := cmp.Diff(want, fixtureFindings(t, NewIAMWildcard(), "iam-wildcard")); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func TestNoSensitiveLeak(t *testing.T) {
	t.Parallel()
	for _, fixture := range []string{"rds-replace", "s3-delete", "sg-open-db-port", "iam-wildcard"} {
		for _, r := range []rules.Rule{NewStatefulDestroy(), NewSGOpenIngress(), NewIAMWildcard()} {
			for _, fs := range fixtureFindings(t, r, fixture) {
				for _, f := range fs {
					if strings.Contains(f.Msg, "example-secret") {
						t.Errorf("%s leaked a sensitive value: %s", r.Meta().ID, f.Msg)
					}
				}
			}
		}
	}
}
