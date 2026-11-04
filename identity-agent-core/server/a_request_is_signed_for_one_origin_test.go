package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"identity-agent-core/authorisation"
	"identity-agent-core/authprovider"
	"identity-agent-core/endpoint"
	"identity-agent-core/login"
)

const ownOrigin = "https://agent.example.com:443"

// A machine's request is signed for the origin it meant to reach. A plain
// reverse proxy is another origin, so a request relayed through one is refused.
func aServerReachedAt(t *testing.T) (*CoreServer, string, []byte) {
	t.Helper()
	resetSeenSignatures(t)
	s := newAuthTestServer(t)
	s.EndpointService = endpoint.New(nil, 8080)
	s.EndpointService.SetOverrideURL("https://agent.example.com")
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)
	return s, aid, seed
}

// resignedForOrigin re-signs req over the V3 form for origin, and sends the origin
// header only when sendHeader is set.
func resignedForOrigin(t *testing.T, req *http.Request, aid string, seed []byte, origin string, sendHeader bool) *http.Request {
	t.Helper()
	stamp := req.Header.Get(headerControllerTimestamp)
	sig, err := login.SignString(canonicalControllerRequestAt(aid, "", origin, req.Method, req.URL.Path, stamp,
		authprovider.Unmeasured(""), nil), seed)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(headerControllerSig, sig)
	if sendHeader {
		req.Header.Set(headerControllerOrigin, origin)
	}
	return req
}

func send(s *CoreServer, req *http.Request) int {
	w := httptest.NewRecorder()
	s.buildRouter().ServeHTTP(w, req)
	return w.Code
}

func TestARequestRelayedThroughAnotherAddressIsRefused(t *testing.T) {
	s, aid, seed := aServerReachedAt(t)
	get := func() *http.Request { return asThatMachine(t, aid, "GET", "/api/profile", "", seed, "", time.Time{}) }

	baseline := send(s, get())
	if baseline == http.StatusForbidden {
		t.Fatalf("the unsigned-origin form, which older clients send, was refused: %d", baseline)
	}
	resetSeenSignatures(t)

	if got := send(s, resignedForOrigin(t, get(), aid, seed, ownOrigin, true)); got != baseline {
		t.Fatalf("a request signed for this agent's own origin was answered %d, want %d", got, baseline)
	}
	resetSeenSignatures(t)

	// The forwarder cannot change what was signed, and cannot make its own
	// address one of ours.
	proxied := resignedForOrigin(t, get(), aid, seed, "https://proxy.example.net:443", true)
	if got := send(s, proxied); got != http.StatusForbidden {
		t.Fatalf("a request signed for a proxy's origin was accepted: %d", got)
	}
	resetSeenSignatures(t)

	// Signed for the proxy, relabelled as ours: the signature no longer matches.
	relabelled := resignedForOrigin(t, get(), aid, seed, "https://proxy.example.net:443", false)
	relabelled.Header.Set(headerControllerOrigin, ownOrigin)
	if got := send(s, relabelled); got != http.StatusForbidden {
		t.Fatalf("a request relabelled with this agent's origin was accepted: %d", got)
	}
	resetSeenSignatures(t)

	// Signed for our origin, with the header removed: read as the older form,
	// whose string it was not signed over.
	stripped := resignedForOrigin(t, get(), aid, seed, ownOrigin, false)
	if got := send(s, stripped); got != http.StatusForbidden {
		t.Fatalf("a request with its origin stripped was accepted: %d", got)
	}
}

func TestAnOriginNotInItsOneSpellingIsRefused(t *testing.T) {
	s, aid, seed := aServerReachedAt(t)
	for _, origin := range []string{"https://agent.example.com", "https://Agent.example.com:443", "https://agent.example.com:443/", " "} {
		resetSeenSignatures(t)
		req := asThatMachine(t, aid, "GET", "/api/profile", "", seed, "", time.Time{})
		req = resignedForOrigin(t, req, aid, seed, origin, true)
		if got := send(s, req); got != http.StatusForbidden {
			t.Errorf("origin %q was accepted: %d", origin, got)
		}
	}
	// Twice is not once.
	resetSeenSignatures(t)
	req := resignedForOrigin(t, asThatMachine(t, aid, "GET", "/api/profile", "", seed, "", time.Time{}), aid, seed, ownOrigin, true)
	req.Header.Add(headerControllerOrigin, ownOrigin)
	if got := send(s, req); got != http.StatusForbidden {
		t.Errorf("a doubled origin header was accepted: %d", got)
	}
}

// The older form is read for one version; switched off, it is refused.
func TestTheOlderFormIsRefusedOnceTheOriginIsRequired(t *testing.T) {
	s, aid, seed := aServerReachedAt(t)
	requireControllerOrigin = true
	defer func() { requireControllerOrigin = false }()
	if got := send(s, asThatMachine(t, aid, "GET", "/api/profile", "", seed, "", time.Time{})); got != http.StatusForbidden {
		t.Fatalf("a request naming no origin was accepted once one is required: %d", got)
	}
}

// The origin is signed in a form of its own, and every reader of what a machine
// signed reads it.
func TestTheOriginIsAFormOfItsOwn(t *testing.T) {
	v3 := canonicalControllerRequestAt("BMachine", "EAgent", ownOrigin, "POST", "/api/x", "2026-01-01T00:00:00Z",
		authprovider.Unmeasured(""), []byte(`{}`))
	v2 := canonicalControllerRequest("BMachine", "EAgent", "POST", "/api/x", "2026-01-01T00:00:00Z",
		authprovider.Unmeasured(""), []byte(`{}`))
	if !strings.HasPrefix(v3, "IA-CONTROLLER-REQ-V3\n") || !strings.HasPrefix(v2, "IA-CONTROLLER-REQ-V2\n") {
		t.Fatalf("forms: %q / %q", v3, v2)
	}
	cr, err := authorisation.ReadControllerRequest(v3)
	if err != nil || cr.Origin != ownOrigin || cr.Controller != "BMachine" || cr.IdentityAgent != "EAgent" ||
		cr.Method != "POST" || cr.Path != "/api/x" || !cr.NamesIdentityAgent {
		t.Fatalf("the third form was read as %+v, %v", cr, err)
	}
	if old, err := authorisation.ReadControllerRequest(v2); err != nil || old.Origin != "" {
		t.Fatalf("the second form was read as %+v, %v", old, err)
	}
}

// What a controller's own core signs for is checked before it signs.
func TestTheCoreRefusesToSignForAnOriginNotInItsOneSpelling(t *testing.T) {
	s := newAuthTestServer(t)
	w, _ := signAs(t, s, `{"method":"GET","path":"/api/profile","origin":"https://agent.example.com"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("an origin without its port was not refused: %d %s", w.Code, w.Body.String())
	}
}
