package vault

import "strings"

// MatchDomain reports whether domain matches pattern: exactly, "*." for one
// label in front of the suffix, or "**." for any number. The vault matches a
// credential's domains with it, and the sandboxed-app policy its rules.
func MatchDomain(pattern, domain string) bool {
	pattern = strings.ToLower(pattern)
	domain = strings.ToLower(domain)

	if pattern == domain {
		return true
	}

	if strings.HasPrefix(pattern, "**.") {
		suffix := pattern[2:]
		return strings.HasSuffix(domain, suffix)
	}

	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		if !strings.HasSuffix(domain, suffix) {
			return false
		}
		prefix := strings.TrimSuffix(domain, suffix)
		return !strings.Contains(prefix, ".")
	}

	return false
}
