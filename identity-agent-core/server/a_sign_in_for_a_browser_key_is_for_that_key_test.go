package server

import (
	"bytes"
	"encoding/json"
	"errors"
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

// An add-on starts a sign-in for an asset's browser key and reads its result
// with the secret it was given, and with nothing else.
func TestAnAddOnStartsASignInForABrowserKeyAndReadsItsResultWithTheSecret(t *testing.T) {
	w := anOrganisationWithAWebsite(t, asset.EnrollmentPolicy{Mode: asset.EnrollmentOpen})
	h := aPersonsIdentityAgent(t)
	in, err := w.org.startBrowserKeySignIn("the-website", "https://portal.example", aBrowserKey, w.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	var c login.ChallengeBundle
	if err := json.Unmarshal([]byte(in.CanonicalBody), &c); err != nil || c.BrowserKey != aBrowserKey || in.Sig == "" || in.Collector == "" {
		t.Fatalf("the challenge handed over does not name the key, or is unsigned: %+v %v", in, err)
	}
	if in.Pointer != w.srv.URL+"/i/"+in.Session {
		t.Fatalf("the pointer is %q", in.Pointer)
	}
	if res, err := w.org.browserKeySignInResult(in.Session, in.Collector); err != nil || res.State != "pending" {
		t.Fatalf("before the person answers: %+v %v", res, err)
	}
	for _, wrong := range []string{"", "not-the-secret"} {
		if _, err := w.org.browserKeySignInResult(in.Session, wrong); err == nil {
			t.Fatalf("the result was given for the secret %q", wrong)
		}
	}
	if _, err := h.Approve(login.StartLoginRequest{SessionToken: in.Session, RPSessionURL: w.srv.URL}); err != nil {
		t.Fatal(err)
	}
	res, err := w.org.browserKeySignInResult(in.Session, in.Collector)
	if err != nil || res.State != "verified" || res.BrowserKey != aBrowserKey || res.Pairwise == "" {
		t.Fatalf("after the person approved: %+v %v", res, err)
	}
	// A sign-in that was not for a browser's key is not read this way, even with its secret.
	token, _, code, msg := w.org.createSignedAssetChallenge("the-website", "https://portal.example", nil, "", w.srv.URL)
	if code != 0 {
		t.Fatal(msg)
	}
	secret, _ := w.org.mintCollectorSecret(token)
	if _, err := w.org.browserKeySignInResult(token, secret); err == nil {
		t.Fatal("a sign-in with no browser key was read as one")
	}
	// An unknown asset and a malformed key are refused as the core's route refuses them.
	var refused *SignInRefused
	if _, err := w.org.startBrowserKeySignIn("no-such-asset", "x", aBrowserKey, w.srv.URL); !errors.As(err, &refused) || refused.Code != http.StatusNotFound {
		t.Fatalf("an unknown asset: %v", err)
	}
	if _, err := w.org.startBrowserKeySignIn("the-website", "x", "bad", w.srv.URL); !errors.As(err, &refused) || refused.Code != http.StatusBadRequest {
		t.Fatalf("a malformed key: %v", err)
	}
}
