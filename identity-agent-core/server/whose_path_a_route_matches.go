package server

import (
	"regexp"
	"strings"
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

// prefixMeets reports whether some request path under prefix (static, on a
// segment's boundary, or the prefix itself) matches pattern.
func prefixMeets(prefix, pattern string) bool {
	return segmentsMeetFrom(append(segmentsOf(strings.TrimSuffix(prefix, "/")), "*"), segmentsOf(pattern))
}

// identifierRoutes is where the core serves an identity's own documents at
// the root, by its identifier: /{aid}/did.json, /{aid}/oobi and the like.
// The segment takes an identifier, a CESR prefix, and the core answers
// nothing for one it does not hold. A prefix whose first segment is a word no
// identifier can be ("apps") therefore never takes a request these routes
// would answer, though chi would hand the word to {aid} if nothing else
// claimed it. That is the only case the check is told about, and only for
// these routes; every other parameter is taken to match anything.
const identifierRoutes = "/{aid}/"

// couldBeAnIdentifier reports whether seg could be a CESR identifier prefix:
// 44 characters of the base64url alphabet.
func couldBeAnIdentifier(seg string) bool {
	if len(seg) != 44 {
		return false
	}
	for _, c := range seg {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// prefixMeetsTheCore is prefixMeets for a route of the core's, with what
// identifierRoutes says about the core's identifier routes.
func prefixMeetsTheCore(prefix, pattern string) bool {
	if strings.HasPrefix(pattern, identifierRoutes) && !couldBeAnIdentifier(segmentsOf(prefix)[0]) {
		return false
	}
	return prefixMeets(prefix, pattern)
}

// theWebUI is the core's catch-all for the web app's own files. Every route
// is more specific than it and chi prefers every one, so a route of an
// add-on's or an overlay's is never counted as taking requests from it; it
// is only ever the files' fallback.
const theWebUI = "/*"
