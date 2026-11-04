package glob

import "testing"

func TestMatch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		pattern, name string
		want          bool
	}{
		{"*", "", true},
		{"*", "anything.at[\"all\"]", true},
		{"", "", true},
		{"", "x", false},
		{"module.sandbox.*", "module.sandbox.aws_s3_bucket.tmp", true},
		{"module.sandbox.*", "module.sandbox2.aws_s3_bucket.tmp", false},
		{"aws_s3_bucket.tmp", "aws_s3_bucket.tmp", true},
		{"aws_s3_bucket.tmp", "aws_s3_bucket.tmp2", false},
		{`aws_s3_bucket.x["a"]`, `aws_s3_bucket.x["a"]`, true},
		{`aws_s3_bucket.x[*]`, `aws_s3_bucket.x["a"]`, true},
		{"aws_elasticache_*", "aws_elasticache_cluster", true},
		{"TPR-DATA-00?", "TPR-DATA-001", true},
		{"TPR-DATA-00?", "TPR-DATA-0012", false},
		{"*.main", "module.a.aws_db_instance.main", true},
		{"a*b*c", "aXbYbZc", true},
		{"a*b*c", "aXbYbZ", false},
		{"**", "x", true},
		{"x*", "", false},
	}
	for _, tt := range tests {
		if got := Match(tt.pattern, tt.name); got != tt.want {
			t.Errorf("Match(%q, %q) = %v, want %v", tt.pattern, tt.name, got, tt.want)
		}
	}
	if !MatchAny([]string{"a", "b*"}, "bc") || MatchAny([]string{"a"}, "b") || MatchAny(nil, "a") {
		t.Error("MatchAny")
	}
}
