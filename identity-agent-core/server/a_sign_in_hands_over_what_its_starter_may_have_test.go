package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"identity-agent-core/asset"
	"identity-agent-core/login"
)

// Who started a sign-in decides what the collector is handed with the identity.
// A website's server (no Origin) is handed the disclosures it asked for and not
// the assertion, which carries the credentials the person showed; a page is
// handed both, since it has no server to check the assertion for it.
func TestWhatTheCollectorIsHandedDependsOnWhoStartedTheSignIn(t *testing.T) {
	for _, tc := range []struct {
		name          string
		origin        string
		wantAssertion bool
	}{
		{"a website with a back end", "", false},
		{"a page with no back end", aPagesOrigin, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := anOrganisationWithAWebsite(t, asset.EnrollmentPolicy{Mode: asset.EnrollmentOpen})
			ia := anOrganisationsAgentOnTheOpenInternet(t, w)
			req, _ := http.NewRequest("POST", ia.URL+"/api/login/session/the-website",
				strings.NewReader(`{"requestDisclosures":["display_name"],"audience":"https://portal.example"}`))
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
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

			h := aPersonsIdentityAgent(t)
			sr := login.StartLoginRequest{SessionToken: started.Token, RPSessionURL: ia.URL}
			if _, err := h.Preview(sr); err != nil {
				t.Fatal(err)
			}
			if _, err := h.Approve(sr); err != nil {
				t.Fatal(err)
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

			if out["state"] != "verified" || out["app_session_token"] == nil {
				t.Fatalf("the collector was not handed the identity: %v", out)
			}
			// confirmLoginSession (packages/login-web/src/confirmSession.ts)
			// reads these for every site with a server.
			if _, ok := out["disclosures"]; !ok {
				t.Errorf("the collector was not handed the disclosures: %v", out)
			}
			if has := out["assertion"] != nil; has != tc.wantAssertion {
				t.Errorf("assertion handed over = %v, want %v: %v", has, tc.wantAssertion, out)
			}
			if has := out["nonce"] != nil || out["site_aid"] != nil; has != tc.wantAssertion {
				t.Errorf("nonce/site handed over = %v, want %v: %v", has, tc.wantAssertion, out)
			}
			if !tc.wantAssertion {
				// Not kept at all, so nothing can release it later.
				w.org.challengeMu.Lock()
				st := w.org.challengeStatus[started.Token]
				w.org.challengeMu.Unlock()
				if st["assertion"] != nil {
					t.Errorf("an assertion nobody may be handed was kept: %v", st)
				}
			}
		})
	}
}
