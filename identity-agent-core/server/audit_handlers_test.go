package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"identity-agent-core/sandbox"
)

// The audit log is the one endpoint where "who is asking" matters more than what they
// hold, so the gate gets its own tests. The failure it guards against is specific and
// easy to reintroduce: isOwner treats any loopback request without forwarding headers
// as the owner, and every AI agent on this machine calls from loopback too. Gating on
// isOwner alone hands every agent the record of every other caller.

func auditTestServer(t *testing.T) *CoreServer {
	t.Helper()
	return &CoreServer{DataDir: t.TempDir()}
}

func auditRequest(target string, remoteAddr string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.RemoteAddr = remoteAddr
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestAuditRefusesTokenBearingLoopbackCaller(t *testing.T) {
	// The regression that matters. An AI agent invoking capabilities on this machine
	// is a loopback caller with a bearer token; it must not be able to read the log.
	s := auditTestServer(t)
	for _, header := range []string{"Authorization", "X-IA-Token"} {
		t.Run(header, func(t *testing.T) {
			h := map[string]string{}
			if header == "Authorization" {
				h[header] = "Bearer some-agent-token"
			} else {
				h[header] = "some-agent-token"
			}
			w := httptest.NewRecorder()
			if s.requireOwner(w, auditRequest("/api/activity/invocations", "127.0.0.1:54321", h)) {
				t.Fatal("a token-bearing loopback caller was treated as the owner")
			}
			if w.Code != http.StatusForbidden {
				t.Fatalf("want 403, got %d", w.Code)
			}
		})
	}
}

func TestAuditAllowsOwnerOnLoopbackWithoutToken(t *testing.T) {
	s := auditTestServer(t)
	w := httptest.NewRecorder()
	if !s.requireOwner(w, auditRequest("/api/activity/invocations", "127.0.0.1:54321", nil)) {
		t.Fatalf("the local owner should be allowed, got %d", w.Code)
	}
}

func TestAuditRefusesRemoteCaller(t *testing.T) {
	s := auditTestServer(t)
	for _, remote := range []string{"203.0.113.7:443", "10.0.0.5:8080"} {
		w := httptest.NewRecorder()
		if s.requireOwner(w, auditRequest("/api/activity/invocations", remote, nil)) {
			t.Fatalf("remote caller %s was treated as the owner", remote)
		}
		if w.Code != http.StatusForbidden {
			t.Fatalf("want 403 for %s, got %d", remote, w.Code)
		}
	}
}

func TestAuditRefusesForwardedLoopbackCaller(t *testing.T) {
	// A proxied request arrives from loopback but did not originate there. The owner
	// check already accounts for this; the audit gate must inherit it rather than
	// re-deriving a weaker version.
	s := auditTestServer(t)
	for _, h := range []map[string]string{
		{"X-Forwarded-For": "203.0.113.7"},
		{"X-Real-IP": "203.0.113.7"},
	} {
		w := httptest.NewRecorder()
		if s.requireOwner(w, auditRequest("/api/activity/invocations", "127.0.0.1:54321", h)) {
			t.Fatalf("a forwarded request was treated as the owner (headers %v)", h)
		}
	}
}

func TestAuditEndpointsAllGuarded(t *testing.T) {
	// Every audit route must refuse a token-bearing loopback caller. This catches a
	// new endpoint being added without the gate — the likeliest future mistake.
	s := auditTestServer(t)
	s.SandboxManager = nil // the gate must run before anything touches the store
	targets := []string{
		"/api/activity/invocations",
		"/api/activity/invocations/1",
		"/api/activity/summary",
		"/api/activity/chain",
	}
	handlers := []func(http.ResponseWriter, *http.Request){
		s.handleListInvocations, s.handleGetInvocation,
		s.handleAuditSummary, s.handleVerifyAuditChain,
	}
	for i, target := range targets {
		w := httptest.NewRecorder()
		r := auditRequest(target, "127.0.0.1:54321", map[string]string{"Authorization": "Bearer agent-token"})
		handlers[i](w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s: want 403 for a delegated caller, got %d", target, w.Code)
		}
	}
}

func TestNormaliseStatusRejectsUnknownValues(t *testing.T) {
	// An unrecognised status must become empty rather than being passed through: a
	// typo should return everything-unfiltered visibly, not match nothing silently
	// while looking like a legitimate query.
	for _, in := range []string{"ok", "OK", " denied ", "error"} {
		if normaliseStatus(in) == "" {
			t.Errorf("%q is a real status and should survive", in)
		}
	}
	for _, in := range []string{"okay", "success", "failed", "'; DROP TABLE", ""} {
		if got := normaliseStatus(in); got != "" {
			t.Errorf("%q should not pass as a status, got %q", in, got)
		}
	}
}

func TestDescribeAuthorityLabelsTheChain(t *testing.T) {
	s := auditTestServer(t)
	steps := s.describeAuthority(sandbox.InvocationEvent{
		CallerAID:       "AID-agent",
		DelegationChain: []string{"AID-agent", "AID-team", "AID-root"},
	})
	if len(steps) != 3 {
		t.Fatalf("want 3 steps, got %d", len(steps))
	}
	if steps[0].Role != "caller" || steps[1].Role != "delegator" || steps[2].Role != "root" {
		t.Fatalf("roles wrong: %+v", steps)
	}
	if steps[0].AID != "AID-agent" || steps[2].AID != "AID-root" {
		t.Fatalf("chain order lost: %+v", steps)
	}
}

func TestDescribeAuthorityFallsBackToTheCaller(t *testing.T) {
	// A bare token caller has no delegation chain. It still has an identity, and
	// showing nothing at all would read as "no authority" rather than "no lineage".
	s := auditTestServer(t)
	steps := s.describeAuthority(sandbox.InvocationEvent{CallerAID: "AID-solo"})
	if len(steps) != 1 || steps[0].AID != "AID-solo" {
		t.Fatalf("want the caller alone, got %+v", steps)
	}
	// One step is both the start and the end of its own chain; caller is the more
	// useful label.
	if steps[0].Role != "caller" {
		t.Fatalf("want role caller, got %q", steps[0].Role)
	}
	if len(s.describeAuthority(sandbox.InvocationEvent{})) != 0 {
		t.Fatal("an event with no identity at all should produce no steps")
	}
}
