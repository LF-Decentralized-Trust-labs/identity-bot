package sandbox

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A credential is only ever handed to a caller that proved who it is AND was
// granted that credential. These pin both halves, and the three ways the old
// behaviour could hand a secret to the wrong caller.

func provenProxy(inject CredentialInjectFunc, routes ...ProxyRoute) *ProxyManager {
	pm := &ProxyManager{injectCreds: inject, routes: map[string]*ProxyRoute{}}
	for i := range routes {
		r := routes[i]
		pm.routes[r.InstanceID] = &r
	}
	return pm
}

func TestAnInferredCallerGetsNoCredential(t *testing.T) {
	// The heart of it. Source-address matching is an inference, and behind
	// user-mode networking every guest shares one egress address — so the
	// inference is not merely weak, it is identical for every caller.
	calls := 0
	pm := provenProxy(injector("api.example.com", "Authorization", "Bearer secret", &calls),
		ProxyRoute{InstanceID: "inst-1", TargetHost: "10.0.0.5",
			CredentialServices: []string{"svc"}})

	r := httptest.NewRequest(http.MethodGet, "https://api.example.com/x", nil)
	r.RemoteAddr = "10.0.0.5:5555" // matches by address, presents no token
	route, how := pm.identifyCaller(r)
	if how != callerInferred || route == nil {
		t.Fatalf("expected an address match to be inferred, got %v", how)
	}

	out := httptest.NewRequest(http.MethodGet, "https://api.example.com/x", nil)
	pm.applyCredentialsFor(out, "app", "inst-1", route, how)
	if out.Header.Get("Authorization") != "" {
		t.Fatal("an inferred caller must not receive a credential")
	}
	if calls != 0 {
		t.Fatalf("the vault should not even be consulted, called %d times", calls)
	}
}

func TestTheSingleRouteFallbackCannotMoveASecret(t *testing.T) {
	// With exactly one route registered, ANY request was attributed to it — so
	// traffic from anything at all on the host was handed that instance's
	// credentials. The fallback survives for logging; it can no longer inject.
	calls := 0
	pm := provenProxy(injector("api.example.com", "Authorization", "Bearer secret", &calls),
		ProxyRoute{InstanceID: "only-one", CredentialServices: []string{"svc"}})

	r := httptest.NewRequest(http.MethodGet, "https://api.example.com/x", nil)
	r.RemoteAddr = "203.0.113.99:1234" // matches nothing
	route, how := pm.identifyCaller(r)
	if route == nil || how != callerInferred {
		t.Fatalf("the fallback should still attribute for logging, got %v", how)
	}
	out := httptest.NewRequest(http.MethodGet, "https://api.example.com/x", nil)
	pm.applyCredentialsFor(out, "app", "only-one", route, how)
	if out.Header.Get("Authorization") != "" || calls != 0 {
		t.Fatal("the single-route fallback must never produce a credential")
	}
}

func TestAProvenCallerGetsOnlyWhatItWasGranted(t *testing.T) {
	pm := provenProxy(injector("api.example.com", "Authorization", "Bearer secret", nil),
		ProxyRoute{InstanceID: "inst-1", ProxyToken: "tok-1", CredentialServices: []string{"svc"}},
		ProxyRoute{InstanceID: "inst-2", ProxyToken: "tok-2"}) // granted nothing

	for _, tc := range []struct {
		name, token string
		wantCred    bool
	}{
		{"granted", "tok-1", true},
		{"proven but granted nothing", "tok-2", false},
		{"wrong token", "not-a-token", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "https://api.example.com/x", nil)
			r.Header.Set("Proxy-Authorization", "Bearer "+tc.token)
			route, how := pm.identifyCaller(r)

			out := httptest.NewRequest(http.MethodGet, "https://api.example.com/x", nil)
			pm.applyCredentialsFor(out, "app", "inst", route, how)
			got := out.Header.Get("Authorization") != ""
			if got != tc.wantCred {
				t.Fatalf("credential injected = %v, want %v", got, tc.wantCred)
			}
		})
	}
}

func TestAWrongTokenDoesNotFallBackToGuessing(t *testing.T) {
	// A caller that tried to identify itself and failed must not then be
	// misidentified by address. Falling through would mean presenting a bad
	// token is a way to be treated as somebody else.
	pm := provenProxy(nil,
		ProxyRoute{InstanceID: "inst-1", ProxyToken: "tok-1", TargetHost: "10.0.0.5"})
	r := httptest.NewRequest(http.MethodGet, "https://api.example.com/x", nil)
	r.RemoteAddr = "10.0.0.5:5555" // would match by address
	r.Header.Set("Proxy-Authorization", "Bearer wrong")

	route, how := pm.identifyCaller(r)
	if route != nil || how != callerUnknown {
		t.Fatalf("a bad token must not fall back to address matching, got route=%v how=%v", route, how)
	}
}

func TestProxyTokensAreDistinctAndLongEnough(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		tok, err := NewProxyToken()
		if err != nil {
			t.Fatal(err)
		}
		if len(tok) < 32 {
			t.Fatalf("token is too short to be unguessable: %d chars", len(tok))
		}
		if seen[tok] {
			t.Fatal("minted a duplicate token")
		}
		seen[tok] = true
	}
}

func TestEmptyServiceListInjectsNothing(t *testing.T) {
	// Empty must not mean "unrestricted": that would hand a caller every stored
	// secret exactly when nobody remembered to restrict it.
	cv := &CredentialVault{}
	r := httptest.NewRequest(http.MethodGet, "https://api.example.com/x", nil)
	if cv.InjectCredentialsScoped(r, nil) {
		t.Fatal("an empty service list must inject nothing")
	}
	if cv.InjectCredentialsScoped(r, []string{}) {
		t.Fatal("an empty service list must inject nothing")
	}
}

func TestTheTokenIsAHandleAndTheAIDIsTheIdentity(t *testing.T) {
	// The token recognises a connection; it is not who the caller is. A route
	// carries the same delegated AID and grant the capability path records, so a
	// reader can follow one caller across both transports rather than seeing an
	// opaque value on one side and an identity on the other.
	pm := provenProxy(injector("api.example.com", "Authorization", "Bearer secret", nil),
		ProxyRoute{
			InstanceID: "inst-1", ProxyToken: "tok-1",
			CallerAID: "EAgentDelegatedAID", GrantSAID: "EGrantSAID",
			CredentialServices: []string{"svc"},
		})

	r := httptest.NewRequest(http.MethodGet, "https://api.example.com/x", nil)
	r.Header.Set("Proxy-Authorization", "Bearer tok-1")
	route, how := pm.identifyCaller(r)
	if how != callerProven {
		t.Fatalf("a matching token should prove the connection, got %v", how)
	}
	if route.CallerAID != "EAgentDelegatedAID" || route.GrantSAID != "EGrantSAID" {
		t.Fatalf("the route must carry the delegated identity, got %+v", route)
	}
}

func TestATokenAloneGrantsNothing(t *testing.T) {
	// Presenting a valid token is recognition, not authority. Without a grant the
	// caller gets nothing — which is what stops the token being mistaken for a
	// credential in its own right.
	calls := 0
	pm := provenProxy(injector("api.example.com", "Authorization", "Bearer secret", &calls),
		ProxyRoute{InstanceID: "inst-1", ProxyToken: "tok-1",
			CallerAID: "EAgentDelegatedAID"}) // recognised, granted nothing

	r := httptest.NewRequest(http.MethodGet, "https://api.example.com/x", nil)
	r.Header.Set("Proxy-Authorization", "Bearer tok-1")
	route, how := pm.identifyCaller(r)

	out := httptest.NewRequest(http.MethodGet, "https://api.example.com/x", nil)
	pm.applyCredentialsFor(out, "app", "inst-1", route, how)
	if out.Header.Get("Authorization") != "" || calls != 0 {
		t.Fatal("a token with no grant must yield no credential")
	}
}

func TestAcceptsTheHeaderCurlAndGitActuallySend(t *testing.T) {
	// Captured from a real curl run against a listening socket, with the proxy
	// URL http://mytoken:@127.0.0.1:PORT — which is exactly how a workspace is
	// pointed at the gateway:
	//
	//	Proxy-Authorization: Basic bXl0b2tlbjo=      ("mytoken:")
	//
	// Not Bearer. An earlier version accepted Bearer only, so the callers this
	// transport exists for could not authenticate — and the failure was silent,
	// because an unidentified caller simply gets no credential.
	const captured = "Basic bXl0b2tlbjo="

	pm := provenProxy(injector("api.example.com", "Authorization", "Bearer secret", nil),
		ProxyRoute{InstanceID: "inst-1", ProxyToken: "mytoken",
			CallerAID: "EAgent", CredentialServices: []string{"svc"}})

	r := httptest.NewRequest(http.MethodGet, "https://api.example.com/x", nil)
	r.Header.Set("Proxy-Authorization", captured)
	route, how := pm.identifyCaller(r)
	if how != callerProven || route == nil {
		t.Fatalf("the header curl actually sends must authenticate; got %v", how)
	}

	out := httptest.NewRequest(http.MethodGet, "https://api.example.com/x", nil)
	pm.applyCredentialsFor(out, "app", "inst-1", route, how)
	if out.Header.Get("Authorization") == "" {
		t.Fatal("a proven, granted caller should have received its credential")
	}
}

func TestTheTokenMayBeInEitherHalfOfABasicPair(t *testing.T) {
	// Which half carries the token depends on how the proxy URL was written: a
	// token as username leaves the password empty, and some tooling insists on a
	// non-empty username. Both are compared in constant time, so accepting either
	// costs nothing and removes a configuration foot-gun.
	pm := provenProxy(nil, ProxyRoute{InstanceID: "i", ProxyToken: "tok"})
	for _, pair := range []string{"tok:", "x:tok", "tok:ignored"} {
		enc := base64.StdEncoding.EncodeToString([]byte(pair))
		r := httptest.NewRequest(http.MethodGet, "https://x/", nil)
		r.Header.Set("Proxy-Authorization", "Basic "+enc)
		if _, how := pm.identifyCaller(r); how != callerProven {
			t.Errorf("%q should authenticate, got %v", pair, how)
		}
	}
}

func TestMalformedProxyAuthIsRefusedNotGuessedAt(t *testing.T) {
	pm := provenProxy(nil, ProxyRoute{InstanceID: "i", ProxyToken: "tok", TargetHost: "10.0.0.5"})
	for _, h := range []string{
		"Basic !!!not-base64!!!",
		"Basic " + base64.StdEncoding.EncodeToString([]byte("wrong:")),
		"Bearer wrong",
		"Negotiate something",
	} {
		r := httptest.NewRequest(http.MethodGet, "https://x/", nil)
		r.RemoteAddr = "10.0.0.5:1234" // would otherwise match by address
		r.Header.Set("Proxy-Authorization", h)
		route, how := pm.identifyCaller(r)
		if how == callerProven {
			t.Errorf("%q must not authenticate", h)
		}
		// A malformed or unknown scheme carries no claim at all, so falling back
		// to address matching is right. A well-formed but WRONG token is a failed
		// claim, and must not be quietly re-identified as somebody else.
		if strings.HasPrefix(h, "Basic "+base64.StdEncoding.EncodeToString([]byte("wrong:"))) ||
			h == "Bearer wrong" {
			if route != nil {
				t.Errorf("%q presented a claim and failed it; must not fall back", h)
			}
		}
	}
}
