package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"identity-agent-core/permission"
)

// A credential no add-on recognises is refused.
//
// The core detects that a caller presented a bearer token or a body's
// signature, and asks the add-ons who that is. Where none says, the caller is
// what an unknown token or body always made it: remote, holding no scopes,
// and never the owner, even when the request also carries what would make it
// the owner on its own. Leaving the AI-agent add-on out of a build must not
// turn a request it would have refused into the owner's.

// fromThisComputerAsTheOwner is a request from this computer carrying the
// secret the core was started with, which on its own makes it the owner's.
func fromThisComputerAsTheOwner(header, value string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/identity", nil)
	r.RemoteAddr = "127.0.0.1:51000"
	r.Header.Set(LocalOwnerSecretHeader, testOwnerSecret)
	if header != "" {
		r.Header.Set(header, value)
	}
	return r
}

// refused reports why cc is not what a presented credential nobody
// recognises makes a caller, or "" when it is.
func refused(cc permission.CallerContext) string {
	switch {
	case cc.Owner || cc.CallerAID == "local-owner":
		return "the caller was taken for the owner"
	case cc.CallerAID != "":
		return "the caller was named " + cc.CallerAID
	case !cc.Remote:
		return "the caller was taken for a local one"
	case len(cc.Scopes) > 0:
		return "the caller was given scopes"
	}
	return ""
}

func TestATokenNoAddOnRecognisesIsNotTheOwner(t *testing.T) {
	for name, addons := range map[string][]Addon{
		"with no add-on":    nil,
		"with every add-on": registeredAddons(),
	} {
		t.Run(name, func(t *testing.T) {
			onlyAddons(t, addons...)
			s := &CoreServer{localOwnerSecret: testOwnerSecret, DataDir: t.TempDir()}
			if cc := s.resolveCaller(fromThisComputerAsTheOwner("", "")); cc.CallerAID != "local-owner" {
				t.Fatalf("without a token the request is not the owner's, so this proves nothing: %+v", cc)
			}
			cc := s.resolveCaller(fromThisComputerAsTheOwner("Authorization", "Bearer a-token-nobody-issued"))
			if why := refused(cc); why != "" {
				t.Fatalf("a token nobody recognises was not refused: %s (%+v)", why, cc)
			}
			if cc.AuthLevel != "bearer" {
				t.Fatalf("the caller should be recorded as having presented a token, got %q", cc.AuthLevel)
			}
		})
	}
}

func TestABodySignatureNoAddOnRecognisesIsRefused(t *testing.T) {
	for name, addons := range map[string][]Addon{
		"with no add-on":    nil,
		"with every add-on": registeredAddons(),
	} {
		t.Run(name, func(t *testing.T) {
			onlyAddons(t, addons...)
			s := &CoreServer{localOwnerSecret: testOwnerSecret, DataDir: t.TempDir()}
			cc := s.resolveCaller(fromThisComputerAsTheOwner(permission.HeaderBodyHost, "Bmachine-nobody-enrolled"))
			if why := refused(cc); why != "" {
				t.Fatalf("a body nobody recognises was not refused: %s (%+v)", why, cc)
			}
			if cc.AuthLevel != "" {
				t.Fatalf("a body nobody recognises was given standing %q", cc.AuthLevel)
			}
		})
	}
}

// Where an add-on recognises a token, the caller is whoever it says; another
// token is still refused, and the add-on is not asked about a request that
// presents none.
func TestAnAddOnSaysWhoPresentedItsToken(t *testing.T) {
	asked := 0
	onlyAddons(t, Addon{Name: "issues tokens",
		ResolveBearerToken: func(s *CoreServer, r *http.Request, token string, cc permission.CallerContext) (permission.CallerContext, bool) {
			asked++
			if token != "issued-here" {
				return cc, false
			}
			cc.CallerAID, cc.Scopes = "Eissued", []string{"demo.read"}
			return cc, true
		}})
	s := &CoreServer{localOwnerSecret: testOwnerSecret, DataDir: t.TempDir()}
	cc := s.resolveCaller(fromThisComputerAsTheOwner("Authorization", "Bearer issued-here"))
	if cc.CallerAID != "Eissued" || len(cc.Scopes) != 1 || !cc.Remote || cc.Owner {
		t.Fatalf("the add-on's token did not resolve to its caller: %+v", cc)
	}
	if why := refused(s.resolveCaller(fromThisComputerAsTheOwner("Authorization", "Bearer something-else"))); why != "" {
		t.Fatalf("a token the add-on does not recognise was not refused: %s", why)
	}
	before := asked
	s.resolveCaller(fromThisComputerAsTheOwner("", ""))
	if asked != before {
		t.Fatal("the add-on was asked about a request that presented no token")
	}
}
