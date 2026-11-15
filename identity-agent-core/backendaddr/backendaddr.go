// Package backendaddr is the one rule for the address of a utility app's back
// end, as a sign-in challenge names it (`api`) and as the owner records it. A
// page (packages/login-web) and a Dart front end (packages/login-dart) apply the
// same rule; the cases every one of them must agree on are in
// packages/login-verify/test-vectors/back-end-addresses.json.
//
// The rule is about the shape of the text, which is all a person's Identity
// Agent can check on reading a challenge. It keeps out what would aim a request
// at the machine it runs on or at a private network by the way it is written:
// an IP address, a name with no dot, a name under a suffix reserved for private
// networks, a port that is not one. A public name that resolves to a private
// address passes the shape, and is the guarded client's to refuse when it
// connects.
package backendaddr

import (
	"errors"
	"strings"
)

// ErrShape is returned for an address the rule does not accept.
var ErrShape = errors.New("a back-end address is an https address of a public name in lower case, with no query, fragment or trailing slash")

// MaxLength bounds an address.
const MaxLength = 2048

// reserved are the suffixes a name written for a private network ends in.
var reserved = []string{".local", ".localhost", ".internal", ".lan", ".home.arpa", ".corp", ".intranet", ".localdomain"}

// Check reports whether address is one a back end may be named by. dev allows
// http on this machine (127.0.0.1 or localhost), as a development build does;
// outside dev that is refused.
func Check(address string, dev bool) error {
	if len(address) == 0 || len(address) > MaxLength {
		return ErrShape
	}
	var rest string
	local := false
	switch {
	case strings.HasPrefix(address, "https://"):
		rest = address[len("https://"):]
	case dev && strings.HasPrefix(address, "http://"):
		rest = address[len("http://"):]
		local = true
	default:
		return ErrShape
	}
	hostport, path := rest, ""
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		hostport, path = rest[:i], rest[i:]
	}
	host, port := hostport, ""
	if i := strings.IndexByte(hostport, ':'); i >= 0 {
		host, port = hostport[:i], hostport[i+1:]
		if !aPort(port) {
			return ErrShape
		}
	}
	if local {
		if host != "127.0.0.1" && host != "localhost" {
			return ErrShape
		}
	} else if !aPublicName(host) {
		return ErrShape
	}
	return checkPath(path)
}

// CheckRelayID reports whether rid is a relay identifier as this system writes
// one: 44 characters of the URL-safe alphabet, the first a derivation code.
func CheckRelayID(rid string) error {
	if len(rid) != 44 || rid[0] < 'A' || rid[0] > 'Z' {
		return errors.New("a relay identifier is 44 characters of the URL-safe alphabet, the first a capital letter")
	}
	for i := 1; i < len(rid); i++ {
		if !urlSafe(rid[i]) {
			return errors.New("a relay identifier is 44 characters of the URL-safe alphabet, the first a capital letter")
		}
	}
	return nil
}

func urlSafe(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}

func aPort(p string) bool {
	if p == "" || len(p) > 5 || p[0] == '0' {
		return false
	}
	n := 0
	for i := 0; i < len(p); i++ {
		if p[i] < '0' || p[i] > '9' {
			return false
		}
		n = n*10 + int(p[i]-'0')
	}
	return n >= 1 && n <= 65535
}

// aPublicName is a lower-case DNS name of at least two labels whose last is not
// all digits (so not an IPv4 address) and which no private suffix ends.
func aPublicName(host string) bool {
	if host == "" || len(host) > 253 || !strings.Contains(host, ".") {
		return false
	}
	labels := strings.Split(host, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	last := labels[len(labels)-1]
	// No real top-level name starts with a digit, and a last label that does (all
	// digits, or 0x and hex digits) is read as an IPv4 address by browsers and system
	// resolvers. Punycode names start with xn--, so this refuses nothing else.
	if last[0] < 'a' || last[0] > 'z' {
		return false
	}
	for _, s := range reserved {
		if strings.HasSuffix(host, s) || host == s[1:] {
			return false
		}
	}
	return true
}

// checkPath accepts an empty path, or one that starts with a slash, does not end
// in one, has no dot segment and uses only characters a URL path may carry.
func checkPath(path string) error {
	if path == "" {
		return nil
	}
	if path == "/" || strings.HasSuffix(path, "/") {
		return ErrShape
	}
	for i := 0; i < len(path); i++ {
		c := path[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case strings.IndexByte("._~!$&'()*+,;=:@/-", c) >= 0:
		case c == '%':
			if i+2 >= len(path) || !hex(path[i+1]) || !hex(path[i+2]) {
				return ErrShape
			}
			i += 2
		default:
			return ErrShape
		}
	}
	for _, seg := range strings.Split(path[1:], "/") {
		// A percent-escaped dot is a dot to a browser, so it is judged as one.
		s := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(seg, "%2e", "."), "%2E", "."))
		if seg == "" || s == "." || s == ".." {
			return ErrShape
		}
	}
	return nil
}

func hex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}
