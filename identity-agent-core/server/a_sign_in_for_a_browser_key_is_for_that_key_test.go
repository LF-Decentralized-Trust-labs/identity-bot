package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"identity-agent-core/asset"
	"identity-agent-core/login"
)

const aBrowserKey = "vuOv03KUq8o-Rp-QnU3J1Wqz6-gi2PhHdaCvNLP7bJk"
const anotherBrowserKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func aBrowserKeyChallenge(t *testing.T, w *aWebsiteWorld, key string) login.StartLoginRequest {
	t.Helper()
	token, _, code, msg := w.org.createSignedAssetChallenge("the-website", "https://portal.example", []string{"display_name"}, key, w.srv.URL)
	if code != 0 {
		t.Fatalf("no challenge for browser key %q: %d %s", key, code, msg)
	}
	return login.StartLoginRequest{SessionToken: token, RPSessionURL: w.srv.URL}
}

func theStatus(w *aWebsiteWorld, token string) interface{} {
	w.org.challengeMu.Lock()
	defer w.org.challengeMu.Unlock()
	return w.org.challengeStatus[token]["status"]
}

// The person's Identity Agent approves a challenge that names a browser key,
// repeats the thumbprint in its signed assertion, and the callback admits it.
func TestASignInForABrowserKeyIsAdmittedWhenTheAssertionRepeatsIt(t *testing.T) {
	w := anOrganisationWithAWebsite(t, asset.EnrollmentPolicy{Mode: asset.EnrollmentOpen})
	h := aPersonsIdentityAgent(t)
	req := aBrowserKeyChallenge(t, w, aBrowserKey)
	if _, err := h.Approve(req); err != nil {
		t.Fatalf("an approved sign-in for a browser key was refused: %v", err)
	}
	if got := theStatus(w, req.SessionToken); got != "complete" {
		t.Fatalf("the session is %v, not complete", got)
	}
	if got := w.org.challenges[req.SessionToken].BrowserKey; got != aBrowserKey {
		t.Fatalf("the challenge names %q", got)
	}
	// The result says which browser key the verified assertion repeated.
	w.org.challengeMu.Lock()
	got := w.org.challengeStatus[req.SessionToken]["browser_key"]
	w.org.challengeMu.Unlock()
	if got != aBrowserKey {
		t.Fatalf("the result carries browser key %v", got)
	}
}

// An assertion approved for another key, or for none, is refused by the
// callback, and the session is denied.
func TestAnAssertionForAnotherBrowserKeyIsRefusedAtTheCallback(t *testing.T) {
	for name, wrong := range map[string]string{"another key": anotherBrowserKey, "no key": ""} {
		t.Run(name, func(t *testing.T) {
			w := anOrganisationWithAWebsite(t, asset.EnrollmentPolicy{Mode: asset.EnrollmentOpen})
			h := aPersonsIdentityAgent(t)
			req := aBrowserKeyChallenge(t, w, aBrowserKey)
			bundle := w.org.challenges[req.SessionToken]

			// The person's agent signs a sign-in for the wrong key.
			forged := bundle
			forged.BrowserKey = wrong
			rel, err := h.GetOrCreateRelationship(bundle.SiteAID, &bundle)
			if err != nil {
				t.Fatal(err)
			}
			a, err := h.BuildAssertion(rel, &forged, nil)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(a)
			resp, err := http.Post(w.srv.URL+"/api/login/callback?session="+req.SessionToken, "application/json", bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("the callback answered %d, not 401", resp.StatusCode)
			}
			w.org.challengeMu.Lock()
			reason := w.org.challengeStatus[req.SessionToken]["reason"]
			w.org.challengeMu.Unlock()
			if r, _ := reason.(string); !strings.Contains(r, "browser key mismatch") || theStatus(w, req.SessionToken) != "denied" {
				t.Fatalf("session %v, reason %v", theStatus(w, req.SessionToken), reason)
			}
		})
	}
}

// A site does not sign a challenge naming something that is not a thumbprint.
func TestAChallengeNamingAMalformedBrowserKeyIsNotIssued(t *testing.T) {
	w := anOrganisationWithAWebsite(t, asset.EnrollmentPolicy{Mode: asset.EnrollmentOpen})
	_, _, code, _ := w.org.createSignedAssetChallenge("the-website", "https://portal.example", nil, "not-a-thumbprint", w.srv.URL)
	if code != http.StatusBadRequest {
		t.Fatalf("code %d, want 400", code)
	}
}
