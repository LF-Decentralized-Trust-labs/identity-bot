package server

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Routes that something else depends on being public must actually be public.
//
// This has happened three times, silently, and every time the symptom was a
// whole feature that did not work rather than an error anybody could see. The
// router's default is owner-only, which is the right default; the failure is
// always a route mounted with the intent of being public and never declared so.
//
//   - POST /didcomm, mounted as the public inbound endpoint for agent-to-agent
//     envelopes. Every peer was refused before the handler ran, so agent-to-agent
//     messaging had never once worked.
//   - GET /api/invites/{token} and its redeem, called by the login SDK from a
//     relying party's browser, which is nobody's owner.
//   - GET /api/employees/invites/{token} and its redeem, called by an invited
//     person's agent, which is not the org's owner either.
//
// A comment at the mount site is not enforcement, and each of these had one.

// TestTheRoutesThatWereSilentlyUnreachableAreDeclared names them individually,
// so that dropping any one fails with the feature it breaks rather than with a
// count that changed.
func TestTheRoutesThatWereSilentlyUnreachableAreDeclared(t *testing.T) {
	for route, feature := range map[string]string{
		"POST /didcomm":                              "agent-to-agent messaging",
		"GET /api/invites/{token}":                   "the login SDK's invite flow",
		"POST /api/invites/{token}/redeem":           "the login SDK's invite flow",
		"POST /api/assets/{id}/requests":             "asking an owner for access",
		"GET /api/employees/invites/{token}":         "employee onboarding",
		"POST /api/employees/invites/{token}/redeem": "employee onboarding",
	} {
		if _, ok := publicRoutes[route]; !ok {
			t.Errorf("%s is not in publicRoutes, so %s does not work — "+
				"the router refuses it with 403 before the handler runs", route, feature)
		}
	}
}

// sdkFetch matches a path the browser SDK fetches, capturing the whole template
// literal after ${base} — including any further interpolations, which are the
// path parameters and must not be dropped.
var sdkFetch = regexp.MustCompile("\\$\\{base\\}([^`]*)")

// interpolation matches a ${...} inside a captured path.
var interpolation = regexp.MustCompile(`\$\{[^}]*\}`)

// TestEveryPathTheBrowserSDKCallsIsReachable reads the SDK's own source and
// checks that everything it asks for is public.
//
// The SDK is the precise statement of what a relying party's browser needs,
// and it is the client that cannot ever be the owner — it runs on somebody
// else's website. Checking against it rather than against a comment means the
// test fails when the real contract is broken, not when a comment is worded
// differently.
func TestEveryPathTheBrowserSDKCallsIsReachable(t *testing.T) {
	sdk := filepath.Join("..", "..", "packages", "login-web", "src", "index.ts")
	source, err := os.ReadFile(sdk)
	if err != nil {
		t.Skipf("the browser SDK is not in this checkout: %v", err)
	}

	// Declared paths, with their chi parameter names stripped, so a literal
	// path in the SDK can be matched against the pattern that serves it.
	declared := map[string]bool{}
	for key := range publicRoutes {
		method, path, found := strings.Cut(key, " ")
		if found {
			declared[method+" "+shape(path)] = true
		}
	}

	matches := sdkFetch.FindAllStringSubmatch(string(source), -1)
	// A test that finds nothing to check and reports success is worse than no
	// test: it reads as coverage. If the SDK stops building its URLs this way,
	// this fails and gets updated rather than quietly protecting nothing.
	if len(matches) < 2 {
		t.Fatalf("found %d paths in the browser SDK — the pattern it builds URLs "+
			"with has changed, and this test is no longer checking anything", len(matches))
	}

	for _, match := range matches {
		path := shape(match[1])
		if path == "" {
			continue
		}
		// The SDK uses GET and POST only; accept either, since the source does
		// not always put the method somewhere a regex can reach.
		if declared["GET "+path] || declared["POST "+path] {
			continue
		}
		t.Errorf("the browser SDK calls %q, which is not public — a relying "+
			"party's browser is nobody's owner, so this is refused with 403",
			match[1])
	}
}

// shape reduces a path to its structure, so a chi pattern and a concrete URL
// compare equal: every parameter or interpolated value becomes a single
// placeholder.
func shape(p string) string {
	// Every interpolated value is a path parameter; reduce it before splitting
	// so it survives as a segment rather than vanishing.
	p = interpolation.ReplaceAllString(p, "*")
	p = strings.SplitN(p, "?", 2)[0]
	segments := strings.Split(strings.Trim(p, "/"), "/")
	for i, s := range segments {
		if s == "" || strings.HasPrefix(s, "{") || strings.Contains(s, "$") {
			segments[i] = "*"
		}
	}
	return "/" + strings.Join(segments, "/")
}
