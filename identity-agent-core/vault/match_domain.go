package vault

import "strings"

// MatchDomain reports whether a destination matches a pattern. It is the one
// reading of a host pattern: the vault matches a credential's domains with it,
// the sandboxed-app policy matches an app's allowed_domains and
// blocked_domains with it, and the app manifest's check of those lists
// (appmanifest.ValidOutboundHost) accepts exactly the patterns it can read.
//
// The host part of a pattern is a host, "*.host" (exactly one label in front
// of host) or "**.host" (one or more labels in front of host), compared
// without regard to case. A pattern may end in ":port". With no port the
// pattern covers every port of the host, and the destination may or may not
// carry one; with a port it covers that port only, so a destination that
// names no port, or another port, does not match it.
func MatchDomain(pattern, domain string) bool {
	pHost, pPort, pHasPort := splitHostPort(strings.ToLower(pattern))
	dHost, dPort, dHasPort := splitHostPort(strings.ToLower(domain))

	if pHasPort && (!dHasPort || pPort != dPort) {
		return false
	}

	if pHost == dHost {
		return pHost != ""
	}
	if suffix, ok := strings.CutPrefix(pHost, "**."); ok {
		suffix = "." + suffix
		prefix, found := strings.CutSuffix(dHost, suffix)
		return found && prefix != ""
	}
	if suffix, ok := strings.CutPrefix(pHost, "*."); ok {
		suffix = "." + suffix
		prefix, found := strings.CutSuffix(dHost, suffix)
		return found && prefix != "" && !strings.Contains(prefix, ".")
	}
	return false
}

// splitHostPort separates a trailing ":port" (decimal digits) from s. A string
// with more than one ':' is an IPv6 literal and carries no port here.
func splitHostPort(s string) (host, port string, hasPort bool) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 || strings.Count(s, ":") != 1 {
		return s, "", false
	}
	port = s[i+1:]
	if port == "" || strings.Trim(port, "0123456789") != "" {
		return s, "", false
	}
	return s[:i], port, true
}
