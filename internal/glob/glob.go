// Package glob implements the small wildcard syntax used in config files:
// `*` matches any sequence of characters (including dots and brackets) and
// `?` matches one character. Nothing else is special, so resource addresses
// such as aws_s3_bucket.x["key"] can be written literally.
package glob

// Match reports whether name matches pattern.
func Match(pattern, name string) bool {
	p, n := []rune(pattern), []rune(name)
	// Iterative matcher with single-star backtracking: linear for typical
	// patterns and never exponential.
	pi, ni := 0, 0
	star, mark := -1, 0
	for ni < len(n) {
		switch {
		case pi < len(p) && (p[pi] == '?' || p[pi] == n[ni]):
			pi++
			ni++
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, ni
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			ni = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

// MatchAny reports whether name matches any of the patterns.
func MatchAny(patterns []string, name string) bool {
	for _, p := range patterns {
		if Match(p, name) {
			return true
		}
	}
	return false
}
