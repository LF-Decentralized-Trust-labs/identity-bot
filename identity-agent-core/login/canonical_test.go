package login

import "testing"

// The Ask (challenge) is signed by the site in TypeScript (login-verify) and
// verified here in Go. The two canonical serializations MUST be byte-identical
// or the IA rejects every login. This pins the exact bytes both sides produce
// for a fixed Ask so a divergence is caught in CI, not on a user's phone.
//
// Field order + encoding mirror login-verify/src/canonical.ts canonicalChallengeBody.
func TestCanonicalAskBodyWire(t *testing.T) {
	bundle := ChallengeBundle{
		V:                    "ASK1",
		T:                    1,
		SiteAID:              "ESITEAID",
		SiteOOBI:             "https://rp.example/auth/ia/site/oobi/ESITEAID",
		Audience:             "https://rp.example",
		Nonce:                "nonce-abc",
		Dt:                   "2026-06-18T00:00:00Z",
		Expiry:               "2026-06-18T00:05:00Z",
		RequestedDisclosures: []string{"display_name", "email"},
		RequestedCredentials: []RequestedCredential{},
		CallbackURL:          "https://rp.example/auth/ia/callback",
		SessionToken:         "tok123",
	}

	want := `{"v":"ASK1","t":1,"site_aid":"ESITEAID","site_oobi":"https://rp.example/auth/ia/site/oobi/ESITEAID","audience":"https://rp.example","nonce":"nonce-abc","dt":"2026-06-18T00:00:00Z","expiry":"2026-06-18T00:05:00Z","requested_disclosures":["display_name","email"],"requested_credentials":[],"callback_url":"https://rp.example/auth/ia/callback","session_token":"tok123"}`

	if got := canonicalChallengeBody(bundle); got != want {
		t.Fatalf("Ask canonical mismatch:\n got=%s\nwant=%s", got, want)
	}
}

// relayBaseFromOOBI must preserve the path prefix (RP-hosted serves under
// /auth/ia/site) — collapsing to scheme://host pointed the relationship OOBI +
// registration at the wrong routes (the approve-time 401 "key resolve failed").
func TestRelayBaseFromOOBI(t *testing.T) {
	h := &Handler{}
	cases := map[string]string{
		"https://content.antispamguy.org/auth/ia/site/oobi/EUSER": "https://content.antispamguy.org/auth/ia/site",
		"http://127.0.0.1:8765/oobi/EUSER":                        "http://127.0.0.1:8765",
		"https://relay.grapeid.org/oobi/EUSER":                    "https://relay.grapeid.org",
	}
	for oobi, want := range cases {
		if got := h.relayBaseFromOOBI(oobi); got != want {
			t.Errorf("relayBaseFromOOBI(%q) = %q, want %q", oobi, got, want)
		}
	}
}
