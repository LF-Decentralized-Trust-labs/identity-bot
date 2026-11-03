package vault

import "strings"

// MatchHostPort reports whether a destination, given as the host and the port
// it is actually dialled on, matches a pattern. It is the one reading of a host
// pattern: the vault matches a credential's domains with it, the
// sandboxed-app policy matches an app's allowed_domains and blocked_domains
// with it, and the app manifest's check of those lists
// (appmanifest.ValidOutboundHost) accepts exactly the patterns it can read.
//
// The host part of a pattern is a host, "*.host" (exactly one label in front
// of host) or "**.host" (one or more labels in front of host), compared
// without regard to case. A pattern may end in ":port". With no port the
// pattern covers every port of the host; with a port it covers that port only.
//
// A caller passes the port it dials, the scheme's default (80, 443) when the
// URL names none, and never strips it first: a port-qualified block entry can
// only block a port the matcher is told about. An empty port means the
// caller does not know it, and then a port-qualified pattern does not match.
// A host that still carries ":port" is not a host here: it matches only a
// pattern written the same way, so split it first (net.SplitHostPort).
func MatchHostPort(pattern, host, port string) bool {
	pHost, pPort, pHasPort := splitHostPort(strings.ToLower(pattern))
	dHost := strings.ToLower(host)

	if pHasPort && (port == "" || pPort != port) {
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
