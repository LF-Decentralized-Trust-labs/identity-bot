package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func withHeaders(h map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	for k, v := range h {
		r.Header.Set(k, v)
	}
	return r
}

// The address a person actually reached, assembled from what the proxy said.
func TestTheAddressIsBuiltFromWhatTheProxySaid(t *testing.T) {
	got := observedPublicBase(withHeaders(map[string]string{
		"X-Forwarded-Proto":  "https",
		"X-Forwarded-Host":   "agent.example.net",
		"X-Forwarded-Prefix": "/C5jXvXsJsjOWWwEKP2c4mw",
	}))
	want := "https://agent.example.net/C5jXvXsJsjOWWwEKP2c4mw"
	if got != want {
		t.Fatalf("built %q, want %q", got, want)
	}
}

// No prefix is a real answer, not a missing one: an agent served at the root of
// a name has no prefix to report.
func TestNoPrefixIsStillAnAddress(t *testing.T) {
	got := observedPublicBase(withHeaders(map[string]string{
		"X-Forwarded-Proto": "https",
		"X-Forwarded-Host":  "agent.example.net",
	}))
	if got != "https://agent.example.net" {
		t.Fatalf("built %q", got)
	}
}

// Half an answer is refused rather than completed by guessing.
//
// An address assembled from a missing host, or a scheme this agent chose for
// itself, is one it would publish in an OOBI and nobody could reach. Publishing
// nothing is recoverable; publishing a wrong address is what sends
// counterparties somewhere else.
func TestAPartialAnswerIsRefused(t *testing.T) {
	cases := []struct {
		name string
		h    map[string]string
	}{
		{"no host at all", map[string]string{"X-Forwarded-Proto": "https"}},
		{"host but no scheme", map[string]string{"X-Forwarded-Host": "agent.example.net"}},
		{"a scheme we do not speak", map[string]string{
			"X-Forwarded-Proto": "gopher", "X-Forwarded-Host": "agent.example.net"}},
	}
	for _, tc := range cases {
		if got := observedPublicBase(withHeaders(tc.h)); got != "" {
			t.Errorf("%s: built %q from an incomplete answer", tc.name, got)
		}
	}
}

// Forwarding headers accumulate through a chain of proxies, outermost first.
// The first is the address the person actually reached.
func TestAChainOfProxiesReportsTheOutermost(t *testing.T) {
	got := observedPublicBase(withHeaders(map[string]string{
		"X-Forwarded-Proto": "https, http",
		"X-Forwarded-Host":  "agent.example.net, internal.local",
	}))
	if got != "https://agent.example.net" {
		t.Fatalf("built %q — that is an inner hop, not where the person went", got)
	}
}

// The headers are ignored unless the deployment says to believe them.
//
// This is the whole safety property. Headers are set by whoever sends the
// request, so an agent that believed any caller could be told by a stranger
// that it lives at the stranger's address — and would publish that in its OOBI,
// sending anybody who resolved it there instead.
func TestHeadersAreIgnoredUnlessTheDeploymentSaysOtherwise(t *testing.T) {
	t.Setenv("TRUST_FORWARDED_HEADERS", "")
	if trustForwardedHeaders() {
		t.Fatal("forwarding headers are trusted by default, so any caller can move this agent's address")
	}
	for _, on := range []string{"1", "true", "TRUE", " true "} {
		t.Setenv("TRUST_FORWARDED_HEADERS", on)
		if !trustForwardedHeaders() {
			t.Errorf("TRUST_FORWARDED_HEADERS=%q did not turn it on", on)
		}
	}
	t.Setenv("TRUST_FORWARDED_HEADERS", "no")
	if trustForwardedHeaders() {
		t.Error("an unrecognised value turned trust on")
	}
}
