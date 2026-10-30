package server

import (
	"fmt"
	"regexp"
	"strings"

	"identity-agent-core/iacrypto"
)

// Whose paths a route pattern matches.
//
// Comparing route patterns as strings misses routes that differ in spelling
// and match the same requests: chi treats /controllers/{x} as
// /controllers/{aid}, tries /controllers/{aid:E.*} first, and prefers the
// static /controllers/Evictim to either. A route mounted later can take some
// or all of an earlier one's requests while the earlier one's access class
// is what the table says. So patterns are compared by the paths they can
// match, a segment at a time, and where that cannot be decided they are
// taken to overlap.

// segmentsOf is pattern's path segments, without the leading slash's empty
// one.
func segmentsOf(pattern string) []string {
	return strings.Split(strings.TrimPrefix(pattern, "/"), "/")
}

// paramIn is the regexp a segment that is wholly a {param} or {param:re}
// holds ("" for a plain one), and whether it is one.
func paramIn(seg string) (re string, isParam bool) {
	if len(seg) < 2 || seg[0] != '{' || seg[len(seg)-1] != '}' || strings.Count(seg, "{") != 1 {
		return "", false
	}
	if i := strings.Index(seg, ":"); i >= 0 {
		return seg[i+1 : len(seg)-1], true
	}
	return "", true
}

// isStatic reports whether seg names no parameter and no wildcard.
func isStatic(seg string) bool { return !strings.ContainsAny(seg, "{}*") }

// segmentsMeet reports whether some path segment matches both a and b.
// Where that cannot be decided simply, the answer is yes.
func segmentsMeet(a, b string) bool {
	if isStatic(a) && isStatic(b) {
		return a == b
	}
	if !isStatic(a) && isStatic(b) {
		a, b = b, a
	}
	// a is static or both are not.
	if isStatic(a) {
		re, isParam := paramIn(b)
		if !isParam {
			return true // a segment mixing text and a parameter: assumed to
		}
		if a == "" {
			return false // a parameter never matches an empty segment
		}
		if re == "" {
			return true
		}
		m, err := regexp.MatchString("^(?:"+re+")$", a)
		return err != nil || m
	}
	return true
}

// patternsMeet reports whether some request path matches both patterns. A
// trailing * matches whatever follows, including nothing.
func patternsMeet(a, b string) bool {
	return segmentsMeetFrom(segmentsOf(a), segmentsOf(b))
}

func segmentsMeetFrom(a, b []string) bool {
	for i := 0; ; i++ {
		switch {
		case i < len(a) && a[i] == "*", i < len(b) && b[i] == "*":
			return true
		case i == len(a) || i == len(b):
			return len(a) == len(b)
		case !segmentsMeet(a[i], b[i]):
			return false
		}
	}
}

// prefixSegments are prefix's path segments, or why it is not one an add-on
// may own: it must begin with a slash, name no parameter or wildcard, and
// have no empty segment, so "/" alone, "//x", "/x//y" and "/x/" are refused.
func prefixSegments(prefix string) ([]string, error) {
	if !strings.HasPrefix(prefix, "/") || strings.ContainsAny(prefix, "{}*") {
		return nil, fmt.Errorf("prefix %s is not a static path", prefix)
	}
	segs := segmentsOf(prefix)
	for _, seg := range segs {
		if seg == "" {
			return nil, fmt.Errorf("prefix %q has an empty segment", prefix)
		}
	}
	return segs, nil
}

// prefixAndRoute is how route pattern stands to prefix: inside, when every
// path it matches lies under the prefix (or is the prefix), and meets, when
// some path it matches does. One function decides both, from one reading of
// each, so the two can never disagree about a prefix.
func prefixAndRoute(prefix, pattern string) (inside, meets bool, err error) {
	ps, err := prefixSegments(prefix)
	if err != nil {
		return false, false, err
	}
	rs := segmentsOf(pattern)
	meets = segmentsMeetFrom(append(append([]string(nil), ps...), "*"), rs)
	inside = len(rs) >= len(ps)
	for i := 0; inside && i < len(ps); i++ {
		inside = rs[i] == ps[i]
	}
	return inside, meets, nil
}

// identifierRoutes is where the core serves an identity's own documents at
// the root, by identifier: /{aid}/did.json, /{aid}/kel, /{aid}/keri.cesr,
// /{aid}/oobi, and the OIDC routes under /{aid}/. Each answers a first
// segment that is not an identifier (iacrypto.IsIdentifierQB64: a CESR
// identifier code with the length that code carries) with a refusal and
// nothing else. So a prefix whose first segment is not an identifier, such as
// /apps, takes no request these routes would answer, though chi would hand
// the word to {aid} if nothing else claimed it. That is the only case the
// check is told about; every other parameter, and an identifier-shaped first
// segment, is taken to match.
const identifierRoutes = "/{aid}/"

// prefixMeetsTheCore reports whether some request under prefix is one a core
// route matching pattern would answer, with what identifierRoutes says.
func prefixMeetsTheCore(prefix, pattern string) (bool, error) {
	_, meets, err := prefixAndRoute(prefix, pattern)
	if err != nil || !meets {
		return meets, err
	}
	if strings.HasPrefix(pattern, identifierRoutes) && !iacrypto.IsIdentifierQB64(segmentsOf(prefix)[0]) {
		return false, nil
	}
	return true, nil
}

// theWebUI is the core's catch-all for the web app's own files. Every route
// is more specific than it and chi prefers every one, so a route of an
// add-on's or an overlay's is never counted as taking requests from it; it
// is only ever the files' fallback.
const theWebUI = "/*"
