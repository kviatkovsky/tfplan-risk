package rules

import (
	"encoding/json"
	"strconv"

	"github.com/kviatkovsky/tfplan-risk/plan"
)

// UnknownValue is how values known only after apply appear in messages.
const UnknownValue = "(known after apply)"

// FormatValue renders an attribute value for a finding message. Strings are
// quoted, null is "null", redacted values stay redacted, and long composite
// values are truncated.
func FormatValue(v any) string {
	const maxLen = 80
	switch t := v.(type) {
	case nil:
		return "null"
	case plan.Redacted:
		return t.String()
	case string:
		return strconv.Quote(t)
	case bool:
		return strconv.FormatBool(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "(unprintable)"
	}
	if len(b) > maxLen {
		return string(b[:maxLen-3]) + "..."
	}
	return string(b)
}

// FormatAfter renders the planned value at path, or UnknownValue.
func FormatAfter(c plan.Change, path ...any) string {
	if c.IsUnknown(path...) {
		return UnknownValue
	}
	v, _ := plan.Lookup(c.After, path...)
	return FormatValue(v)
}

// FormatBefore renders the prior value at path.
func FormatBefore(c plan.Change, path ...any) string {
	v, _ := plan.Lookup(c.Before, path...)
	return FormatValue(v)
}
