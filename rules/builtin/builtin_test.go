package builtin

import (
	"testing"

	"github.com/kviatkovsky/tfplan-risk/plan"
	"github.com/kviatkovsky/tfplan-risk/rules"
)

func TestNew(t *testing.T) {
	t.Parallel()
	a, err := New()
	if err != nil {
		t.Fatal(err)
	}
	b, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Metas()) == 0 || len(a.Metas()) != len(b.Metas()) {
		t.Fatalf("Metas() = %d / %d", len(a.Metas()), len(b.Metas()))
	}

	// Rules hold configuration, so each registry must get fresh instances:
	// extending one must not affect the other.
	ra, _ := a.Get("TPR-DATA-001")
	ra.(rules.StatefulTypesExtender).AddStatefulTypes([]string{"aws_neptune_cluster"})
	c := plan.Change{Type: "aws_neptune_cluster", Action: plan.ActionDelete}
	rb, _ := b.Get("TPR-DATA-001")
	if got := len(ra.(rules.Rule).Evaluate(c)); got != 1 {
		t.Errorf("configured registry: %d findings, want 1", got)
	}
	if got := len(rb.(rules.Rule).Evaluate(c)); got != 0 {
		t.Errorf("fresh registry: %d findings, want 0 (state leaked between registries)", got)
	}
}
