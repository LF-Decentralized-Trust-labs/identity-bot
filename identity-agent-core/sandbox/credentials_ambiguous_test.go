package sandbox

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Two accounts on one service is an ordinary thing to want. Choosing between
// them by iteration order is not: the request goes out authenticated as
// whichever entry happened to be first, the log says a credential was injected,
// and the only symptom is a 404 on something the other account could see.
//
// This actually happened. Two GitHub credentials were stored, one for each
// organisation; a read of a private repository returned "Not Found" while the
// log cheerfully reported an injection. Acting silently as the wrong identity is
// worse than not acting at all.

func vaultWith(entries ...CredentialEntry) *CredentialVault {
	cv := &CredentialVault{}
	cv.entries = entries
	cv.loaded = true
	return cv
}

func req(url string) *http.Request { return httptest.NewRequest(http.MethodGet, url, nil) }

func TestTwoCredentialsForOneHostInjectNothing(t *testing.T) {
	cv := vaultWith(
		CredentialEntry{Service: "github-org-a", MatchDomains: []string{"api.github.com"},
			Headers: map[string]string{"Authorization": "Bearer aaa"}},
		CredentialEntry{Service: "github-org-b", MatchDomains: []string{"api.github.com"},
			Headers: map[string]string{"Authorization": "Bearer bbb"}},
	)
	r := req("https://api.github.com/user")
	if cv.InjectCredentials(r) {
		t.Fatal("an ambiguous match must inject nothing")
	}
	if r.Header.Get("Authorization") != "" {
		t.Fatalf("nothing should have been sent, got %q", r.Header.Get("Authorization"))
	}
}

func TestNarrowingToOneServiceResolvesIt(t *testing.T) {
	// The caller says which account it means, and gets exactly that one. This is
	// the escape hatch that makes refusing safe rather than merely strict.
	cv := vaultWith(
		CredentialEntry{Service: "github-org-a", MatchDomains: []string{"api.github.com"},
			Headers: map[string]string{"Authorization": "Bearer aaa"}},
		CredentialEntry{Service: "github-org-b", MatchDomains: []string{"api.github.com"},
			Headers: map[string]string{"Authorization": "Bearer bbb"}},
	)
	r := req("https://api.github.com/user")
	if !cv.InjectCredentialsScoped(r, []string{"github-org-b"}) {
		t.Fatal("naming one service should resolve the ambiguity")
	}
	if got := r.Header.Get("Authorization"); got != "Bearer bbb" {
		t.Fatalf("wrong account injected: %q", got)
	}
}

func TestTheUnambiguousCaseStillWorks(t *testing.T) {
	// Nearly every real case. Refusing ambiguity must not cost anything here.
	cv := vaultWith(
		CredentialEntry{Service: "cloudflare", MatchDomains: []string{"api.cloudflare.com"},
			Headers: map[string]string{"Authorization": "Bearer cf"}},
		CredentialEntry{Service: "github-org-a", MatchDomains: []string{"api.github.com"},
			Headers: map[string]string{"Authorization": "Bearer aaa"}},
	)
	r := req("https://api.cloudflare.com/zones")
	if !cv.InjectCredentials(r) {
		t.Fatal("a single match must still inject")
	}
	if r.Header.Get("Authorization") != "Bearer cf" {
		t.Fatal("wrong credential")
	}
}

func TestAmbiguityIsPerHostNotGlobal(t *testing.T) {
	// Two credentials that both exist but serve different hosts are not
	// ambiguous. Refusing those would make having more than one account anywhere
	// impossible.
	cv := vaultWith(
		CredentialEntry{Service: "github-org-a", MatchDomains: []string{"api.github.com"},
			Headers: map[string]string{"Authorization": "Bearer aaa"}},
		CredentialEntry{Service: "gitlab", MatchDomains: []string{"gitlab.com"},
			Headers: map[string]string{"Authorization": "Bearer gl"}},
	)
	r := req("https://gitlab.com/api/v4/user")
	if !cv.InjectCredentials(r) {
		t.Fatal("different hosts are not ambiguous")
	}
	if r.Header.Get("Authorization") != "Bearer gl" {
		t.Fatal("wrong credential")
	}
}

func TestACallerHeaderIsNeverOverwritten(t *testing.T) {
	// Unchanged behaviour, pinned because the rewrite touched this path: an app
	// carrying its own end-user token must not have it replaced by the org's.
	cv := vaultWith(CredentialEntry{Service: "github-org-a",
		MatchDomains: []string{"api.github.com"},
		Headers:      map[string]string{"Authorization": "Bearer aaa"}})
	r := req("https://api.github.com/user")
	r.Header.Set("Authorization", "Bearer the-callers-own")
	cv.InjectCredentials(r)
	if got := r.Header.Get("Authorization"); got != "Bearer the-callers-own" {
		t.Fatalf("the caller's own header was replaced: %q", got)
	}
}
