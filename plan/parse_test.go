package plan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    *Plan
		wantErr error
		errText string
	}{
		{
			name:  "empty plan without resource_changes",
			input: `{"format_version":"1.2","terraform_version":"1.17.1","planned_values":{}}`,
			want:  &Plan{FormatVersion: "1.2", TerraformVersion: "1.17.1", Changes: []Change{}},
		},
		{
			name: "delete-before-create replacement",
			input: `{"format_version":"1.2","resource_changes":[{
				"address":"module.db.aws_db_instance.main","module_address":"module.db",
				"mode":"managed","type":"aws_db_instance","name":"main",
				"provider_name":"registry.terraform.io/hashicorp/aws",
				"action_reason":"replace_because_cannot_update",
				"change":{"actions":["delete","create"],
					"before":{"engine_version":"15.4","password":"hunter2"},
					"after":{"engine_version":"16.1","password":"hunter3"},
					"after_unknown":{"id":true},
					"before_sensitive":{"password":true},
					"after_sensitive":{"password":true},
					"replace_paths":[["engine_version"]]}}]}`,
			want: &Plan{FormatVersion: "1.2", Changes: []Change{{
				Address:       "module.db.aws_db_instance.main",
				ModuleAddress: "module.db",
				Mode:          ModeManaged,
				Type:          "aws_db_instance",
				Name:          "main",
				ProviderName:  "registry.terraform.io/hashicorp/aws",
				Action:        ActionReplace,
				ReplaceOrder:  DeleteBeforeCreate,
				ActionReason:  "replace_because_cannot_update",
				ReplacePaths:  [][]any{{"engine_version"}},
				Before:        map[string]any{"engine_version": "15.4", "password": Redacted{}},
				After:         map[string]any{"engine_version": "16.1", "password": Redacted{}},
				AfterUnknown:  map[string]any{"id": true},
			}}},
		},
		{
			name: "create-before-destroy replacement and nested sensitive list",
			input: `{"format_version":"1.0","resource_changes":[{
				"address":"aws_lb.web","type":"aws_lb","name":"web",
				"change":{"actions":["create","delete"],
					"before":{"tags":{"a":"1"},"items":[{"k":"x"},{"k":"y"}]},
					"after":null,
					"before_sensitive":{"items":[false,{"k":true}]},
					"after_sensitive":false}}]}`,
			want: &Plan{FormatVersion: "1.0", Changes: []Change{{
				Address:      "aws_lb.web",
				Mode:         ModeManaged,
				Type:         "aws_lb",
				Name:         "web",
				Action:       ActionReplace,
				ReplaceOrder: CreateBeforeDestroy,
				Before: map[string]any{
					"tags":  map[string]any{"a": "1"},
					"items": []any{map[string]any{"k": "x"}, map[string]any{"k": Redacted{}}},
				},
			}}},
		},
		{
			name: "data source read and forget",
			input: `{"format_version":"1.2","resource_changes":[
				{"address":"data.aws_caller_identity.me","mode":"data","type":"aws_caller_identity","change":{"actions":["read"]}},
				{"address":"aws_s3_bucket.old","type":"aws_s3_bucket","change":{"actions":["forget"],"before":{"bucket":"old"}}}]}`,
			want: &Plan{FormatVersion: "1.2", Changes: []Change{
				{Address: "data.aws_caller_identity.me", Mode: ModeData, Type: "aws_caller_identity", Action: ActionRead},
				{Address: "aws_s3_bucket.old", Mode: ModeManaged, Type: "aws_s3_bucket", Action: ActionForget, Before: map[string]any{"bucket": "old"}},
			}},
		},
		{name: "empty input", input: "  \n", wantErr: ErrNotPlanJSON, errText: "empty input"},
		{name: "binary plan", input: "PK\x03\x04garbage", wantErr: ErrNotPlanJSON, errText: "binary plan"},
		{name: "human readable plan", input: "Terraform will perform the following actions:", wantErr: ErrNotPlanJSON, errText: "expected a JSON object"},
		{name: "truncated json", input: `{"format_version":"1.2","resource_changes":[`, wantErr: ErrNotPlanJSON, errText: "decode"},
		{name: "missing format_version", input: `{"resource_changes":[]}`, wantErr: ErrNotPlanJSON, errText: "format_version"},
		{name: "state json", input: `{"format_version":"1.0","values":{"root_module":{}}}`, wantErr: ErrNotPlanJSON, errText: "state JSON"},
		{name: "future major format", input: `{"format_version":"2.0","resource_changes":[]}`, errText: "unsupported plan format_version"},
		{
			name:    "unknown action combination",
			input:   `{"format_version":"1.2","resource_changes":[{"address":"x.y","change":{"actions":["update","delete"]}}]}`,
			errText: `resource_changes[0] (x.y): unsupported change.actions`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Parse(context.Background(), strings.NewReader(tt.input))
			if tt.errText != "" || tt.wantErr != nil {
				if err == nil {
					t.Fatalf("Parse() error = nil, want error containing %q", tt.errText)
				}
				if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
					t.Errorf("Parse() error = %v, want errors.Is %v", err, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.errText) {
					t.Errorf("Parse() error = %q, want it to contain %q", err, tt.errText)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse() unexpected error: %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Parse() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestParseCanceledContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Parse(ctx, strings.NewReader(`{"format_version":"1.2"}`))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Parse() error = %v, want context.Canceled", err)
	}
}

func TestParseFixtures(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob("../internal/testdata/plans/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no fixtures found")
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			t.Parallel()
			fh, err := os.Open(f)
			if err != nil {
				t.Fatal(err)
			}
			defer fh.Close()
			p, err := Parse(context.Background(), fh)
			if err != nil {
				t.Fatalf("Parse(%s): %v", f, err)
			}
			if len(p.Changes) == 0 {
				t.Errorf("Parse(%s): no changes", f)
			}
		})
	}
}

func TestChangeAccessors(t *testing.T) {
	t.Parallel()
	c := Change{
		Action: ActionUpdate,
		Before: map[string]any{"a": map[string]any{"b": []any{"x", nil}}},
		After:  map[string]any{"a": map[string]any{"b": []any{"y", "z"}}, "id": nil, "tags": map[string]any{}},
		AfterUnknown: map[string]any{
			"id":   true,
			"a":    map[string]any{"b": []any{false, true}},
			"tags": map[string]any{},
		},
	}

	tests := []struct {
		name        string
		path        []any
		wantBefore  any
		okBefore    bool
		wantAfter   any
		okAfter     bool
		wantUnknown bool
	}{
		{name: "known list element", path: []any{"a", "b", 0}, wantBefore: "x", okBefore: true, wantAfter: "y", okAfter: true},
		{name: "unknown list element", path: []any{"a", "b", 1}, wantBefore: nil, okBefore: true, okAfter: false, wantUnknown: true},
		{name: "unknown top-level attribute", path: []any{"id"}, okAfter: false, wantUnknown: true},
		{name: "absent attribute", path: []any{"nope"}},
		{name: "string index into list", path: []any{"a", "b", "0"}, wantBefore: "x", okBefore: true, wantAfter: "y", okAfter: true},
		{name: "bad string index", path: []any{"a", "b", "x"}},
		{name: "out of range index", path: []any{"a", "b", 5}},
		{name: "container not unknown", path: []any{"tags"}, okAfter: true, wantAfter: map[string]any{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotB, okB := c.BeforeValue(tt.path...)
			if okB != tt.okBefore || !cmp.Equal(gotB, tt.wantBefore) {
				t.Errorf("BeforeValue(%v) = %v, %v; want %v, %v", tt.path, gotB, okB, tt.wantBefore, tt.okBefore)
			}
			gotA, okA := c.AfterValue(tt.path...)
			if okA != tt.okAfter || !cmp.Equal(gotA, tt.wantAfter) {
				t.Errorf("AfterValue(%v) = %v, %v; want %v, %v", tt.path, gotA, okA, tt.wantAfter, tt.okAfter)
			}
			if got := c.IsUnknown(tt.path...); got != tt.wantUnknown {
				t.Errorf("IsUnknown(%v) = %v, want %v", tt.path, got, tt.wantUnknown)
			}
		})
	}

	if (Change{}).IsUnknown() {
		t.Error("IsUnknown() on an empty change must be false")
	}
	if c.IsReplace() || c.Destroys() {
		t.Error("update must not be reported as replace/destroy")
	}
	if !(Change{Action: ActionReplace}).Destroys() || !(Change{Action: ActionDelete}).Destroys() {
		t.Error("replace and delete must destroy")
	}
}

func TestFormatPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		path []any
		want string
	}{
		{[]any{"engine_version"}, "engine_version"},
		{[]any{"ebs_block_device", float64(0), "volume_size"}, "ebs_block_device[0].volume_size"},
		{[]any{"tags", "Name"}, "tags.Name"},
		{[]any{"list", 2}, "list[2]"},
		{[]any{"x", true}, "x[true]"},
	}
	for _, tt := range tests {
		if got := FormatPath(tt.path); got != tt.want {
			t.Errorf("FormatPath(%v) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestReplaceOrderString(t *testing.T) {
	t.Parallel()
	for o, want := range map[ReplaceOrder]string{
		ReplaceNone: "none", DeleteBeforeCreate: "delete-before-create", CreateBeforeDestroy: "create-before-destroy",
	} {
		if got := o.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", o, got, want)
		}
	}
}

func TestRedactedRendering(t *testing.T) {
	t.Parallel()
	if (Redacted{}).String() != "(sensitive)" {
		t.Error("Redacted.String()")
	}
	b, err := Redacted{}.MarshalJSON()
	if err != nil || string(b) != `"(sensitive)"` {
		t.Errorf("Redacted.MarshalJSON() = %s, %v", b, err)
	}
}
