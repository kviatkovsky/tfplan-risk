package plan

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func FuzzParse(f *testing.F) {
	seeds := []string{
		``,
		`{}`,
		`{"format_version":"1.2"}`,
		`{"format_version":"1.2","resource_changes":[{"change":{"actions":["delete","create"],"before":{"a":1},"before_sensitive":{"a":true}}}]}`,
		`{"format_version":"1.2","resource_changes":[{"change":{"actions":["update"],"before":[1],"before_sensitive":{"a":[true]},"after_unknown":true}}]}`,
		`PK`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	if files, err := filepath.Glob("../internal/testdata/plans/*.json"); err == nil {
		for _, file := range files {
			if b, err := os.ReadFile(file); err == nil {
				f.Add(b)
			}
		}
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Parse(context.Background(), bytes.NewReader(data))
		if err != nil {
			return
		}
		for _, c := range p.Changes {
			// Exercise accessors on whatever shape the fuzzer produced.
			_ = c.IsUnknown("a", 0, "b")
			_, _ = c.AfterValue("a")
			_, _ = c.BeforeValue("a", 0)
			for _, rp := range c.ReplacePaths {
				_ = FormatPath(rp)
			}
		}
	})
}
