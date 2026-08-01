package sandbox

import (
	"net/http"
	"net/http/httptest"
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
