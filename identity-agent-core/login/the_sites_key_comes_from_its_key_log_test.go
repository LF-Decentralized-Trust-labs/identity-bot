package login

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// aSiteIntroducing serves an introduction for `named`, carrying the signed key
// log of the identity behind keyLog, and fails the test if anybody reads a
// did.json instead.
func aSiteIntroducing(t *testing.T, named, keyLog string) *httptest.Server {
	t.Helper()
	kl, err := DecodeKeyLog(keyLog)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/did.json") {
			t.Errorf("the site's key was read from %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"aid": named, "raw_events_b64": kl.RawEventsB64, "cesr_signatures": kl.CesrSignatures,
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The key a site's challenge is checked against comes from the site's own key
// log, which proves itself, never from a did.json beside it.
func TestASitesKeyComesFromItsOwnKeyLog(t *testing.T) {
	aid, seed, keyLog := aRealIdentity(t)
	site := aSiteIntroducing(t, aid, keyLog)
	h := &Handler{HTTPClient: site.Client()}

	got, err := h.resolveSiteKey(site.URL+"/oobi/"+aid, aid)
	if err != nil {
		t.Fatalf("a site's own log did not establish its key: %v", err)
	}
	if string(got) != string(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)) {
		t.Fatal("the key established is not the site's")
	}
}

// A page claiming to be a site cannot borrow another identity's log for it.
func TestAPageCannotIntroduceItselfAsAnotherSite(t *testing.T) {
	victim, _, _ := aRealIdentity(t)
	_, _, liarLog := aRealIdentity(t)
	site := aSiteIntroducing(t, victim, liarLog)
	h := &Handler{HTTPClient: site.Client()}

	if _, err := h.resolveSiteKey(site.URL+"/oobi/"+victim, victim); err == nil {
		t.Fatal("another identity's log established a key for the site it named")
	}
}
