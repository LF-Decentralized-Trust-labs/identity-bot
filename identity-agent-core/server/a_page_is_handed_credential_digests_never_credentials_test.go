package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/asset"
	"identity-agent-core/login"
)

// ADR-071. A page's collector is any script in the page. Whatever form the
// assertion arrives in, what reaches that collector never holds a credential's
// body, and the credentials posted beside the assertion are kept nowhere.
func TestAPageIsHandedTheDigestsOfTheCredentialsNeverTheCredentials(t *testing.T) {
	const body = "SECRET-CREDENTIAL-BODY"
	const said = "ECredentialSAIDforthepagetest0123456789ABC"
	held := login.PresentedCredential{SAID: said, SchemaSAID: "ESchema", IssuerAID: "EIssuer", AcdcJsonB64: body}

	for _, tc := range []struct {
		name          string
		oldForm       bool
		wantAssertion bool
	}{
		{"digests in the assertion, credentials beside it", false, true},
		// The older Identity Agent's form still signs a person in, and is
		// never handed to a page: it would carry the credential with it.
		{"credentials inside the assertion (the form before ADR-071)", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := anOrganisationWithAWebsite(t, asset.EnrollmentPolicy{Mode: asset.EnrollmentOpen})
			ia := anOrganisationsAgentOnTheOpenInternet(t, w)
			req, _ := http.NewRequest("POST", ia.URL+"/api/login/session/the-website",
				strings.NewReader(`{"requestDisclosures":["display_name"],"audience":"https://portal.example"}`))
			req.Header.Set("Origin", aPagesOrigin)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			var started struct {
				Token  string `json:"session_token"`
				Secret string `json:"collector_secret"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&started)
			resp.Body.Close()
			if started.Token == "" {
				t.Fatalf("no sign-in was started (%d)", resp.StatusCode)
			}

			const idx = 1000701
			h, rel, _ := theirAgent(t, idx)
			rel.RelayOOBI = ia.URL + "/oobi/" + rel.PairwiseAID
			h.HeldCredentials = func() []login.PresentedCredential { return []login.PresentedCredential{held} }
			w.org.challengeMu.Lock()
			bundle := w.org.challenges[started.Token]
			w.org.challengeMu.Unlock()
			bundle.RequestedCredentials = []login.RequestedCredential{{SchemaSAID: "ESchema"}}

			a, creds, err := h.BuildAssertionWithCredentials(rel, &bundle, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(a.PresentedACDCs) != 1 || a.PresentedACDCs[0] != said {
				t.Fatalf("the assertion does not name the credential by its digest: %v", a.PresentedACDCs)
			}
			var post []byte
			if tc.oldForm {
				// As an older Identity Agent signs it and a site reads it: the
				// credential an object whose keys the canonical body sorts.
				var whole []interface{}
				raw, _ := json.Marshal([]login.PresentedCredential{held})
				_ = json.Unmarshal(raw, &whole)
				a.PresentedACDCs = whole
				if err := login.SignAssertion(a, theirSeed(t, idx)); err != nil {
					t.Fatal(err)
				}
				post, _ = json.Marshal(a)
			} else {
				post, err = login.SignInPostBody(a, creds)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(post), body) {
					t.Fatal("the credential did not travel beside the assertion")
				}
			}
			rr := httptest.NewRecorder()
			w.org.handleLoginCallback(rr, httptest.NewRequest(http.MethodPost,
				"/api/login/callback?session="+started.Token, strings.NewReader(string(post))))
			if rr.Code != http.StatusOK {
				t.Fatalf("the sign-in was not accepted (%d): %s", rr.Code, rr.Body.String())
			}

			// Nothing kept holds the credential, whichever way it came.
			w.org.challengeMu.Lock()
			kept, _ := json.Marshal(w.org.challengeStatus[started.Token])
			w.org.challengeMu.Unlock()
			if strings.Contains(string(kept), body) {
				t.Errorf("a credential's body was kept with the sign-in: %s", kept)
			}

			r, _ := http.NewRequest("GET", ia.URL+"/api/login/session/the-website/"+started.Token, nil)
			r.Header.Set("X-Collector-Secret", started.Secret)
			got, err := http.DefaultClient.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			defer got.Body.Close()
			var out map[string]any
			_ = json.NewDecoder(got.Body).Decode(&out)
			if out["state"] != "verified" {
				t.Fatalf("the collector was not handed the identity: %v", out)
			}
			handed, _ := json.Marshal(out)
			if strings.Contains(string(handed), body) {
				t.Errorf("the collector was handed a credential's body: %s", handed)
			}
			if has := out["assertion"] != nil; has != tc.wantAssertion {
				t.Fatalf("assertion handed over = %v, want %v: %v", has, tc.wantAssertion, out)
			}
			if tc.wantAssertion && !strings.Contains(out["assertion"].(string), said) {
				t.Errorf("the assertion the page was handed does not name the credential: %v", out["assertion"])
			}
		})
	}
}

// ADR-071. A credential posted beside the assertion counts only if the
// assertion's signature names it and its body has the digest named.
func TestACredentialPostedBesideTheAssertionCountsOnlyIfTheAssertionNamesIt(t *testing.T) {
	w := aGateWorldIssuingTo(t, true, true)
	held := w.s.loginHandler.HeldCredentials()
	if len(held) != 1 {
		t.Fatalf("expected the one held credential, got %d", len(held))
	}
	c := held[0]
	gate := func(presented []interface{}, posted []login.PresentedCredential) bool {
		ok, _ := w.s.credentialGateSatisfied(context.Background(),
			login.BoundCredentials(presented, posted), w.holder, w.schema, w.issuer)
		return ok
	}

	if !gate([]interface{}{c.SAID}, []login.PresentedCredential{c}) {
		t.Fatal("a credential named by digest and posted beside the assertion was refused")
	}
	if gate([]interface{}{c.SAID}, nil) {
		t.Error("a digest with no credential posted passed the gate")
	}
	if gate(nil, []login.PresentedCredential{c}) {
		t.Error("a credential the assertion does not name passed the gate")
	}
	if gate([]interface{}{"ESomeOtherDigest"}, []login.PresentedCredential{c}) {
		t.Error("a credential passed under a digest that is not its own")
	}
	other := c
	other.SAID = "ESomeOtherDigest"
	if gate([]interface{}{other.SAID}, []login.PresentedCredential{other}) {
		t.Error("a credential passed under a SAID its body does not have")
	}

	// The window: the older form carries the credentials whole and is still read.
	raw, _ := json.Marshal([]login.PresentedCredential{c})
	var whole []interface{}
	_ = json.Unmarshal(raw, &whole)
	if !gate(whole, nil) {
		t.Error("an assertion in the form before ADR-071 was no longer read")
	}
}
