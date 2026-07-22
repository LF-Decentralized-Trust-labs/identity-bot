package login

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The relationship anchor (org-owned membership-gated assets) must be part of
// the SIGNED canonical body — an unsigned anchor would let a tampering page
// rewrite which relationship the scanner presents. Also pins that anchor-less
// bundles keep their pre-anchor canonical form (old signatures stay valid).
func TestCanonicalAskBodyRelationshipAnchor(t *testing.T) {
	base := ChallengeBundle{
		V: "ASK1", T: 1,
		SiteAID: "ESITE", SiteOOBI: "https://org.example/public/oobi/ESITE",
		Audience: "https://rp.example", Nonce: "n", Dt: "2026-06-18T00:00:00Z",
		Expiry:               "2026-06-18T00:05:00Z",
		RequestedDisclosures: []string{},
		RequestedCredentials: []RequestedCredential{},
		CallbackURL:          "https://org.example/api/login/callback",
		SessionToken:         "tok",
	}

	plain := canonicalChallengeBody(base)
	if strings.Contains(plain, "relationship_anchor") {
		t.Fatalf("anchor-less bundle must not contain anchor fields: %s", plain)
	}

	base.RelationshipAnchorAID = "EORG"
	base.RelationshipAnchorOOBI = "https://org.example/public/oobi/EORG"
	anchored := canonicalChallengeBody(base)
	if !strings.Contains(anchored, `"relationship_anchor_aid":"EORG"`) ||
		!strings.Contains(anchored, `"relationship_anchor_oobi":"https://org.example/public/oobi/EORG"`) {
		t.Fatalf("anchored bundle must sign the anchor fields: %s", anchored)
	}
}

// verifyDelegationAnchor must only honor an org anchor when the site's served
// KEL opens with a delegated inception (dip) for the site AID naming the anchor
// as delegator — and fail closed on every mismatch.
func TestVerifyDelegationAnchor(t *testing.T) {
	serve := func(body map[string]interface{}) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(body)
		}))
	}
	h := &Handler{HTTPClient: &http.Client{Timeout: 5 * time.Second}}
	bundle := func(oobiURL string) *ChallengeBundle {
		return &ChallengeBundle{SiteAID: "ESITE", SiteOOBI: oobiURL, RelationshipAnchorAID: "EORG"}
	}

	// Happy path: dip for ESITE delegated by EORG.
	ok := serve(map[string]interface{}{
		"aid": "ESITE",
		"kel": []map[string]interface{}{{"t": "dip", "i": "ESITE", "di": "EORG"}},
	})
	defer ok.Close()
	if err := h.verifyDelegationAnchor(bundle(ok.URL)); err != nil {
		t.Fatalf("valid delegation rejected: %v", err)
	}

	// Wrong delegator → reject.
	wrongDi := serve(map[string]interface{}{
		"aid": "ESITE",
		"kel": []map[string]interface{}{{"t": "dip", "i": "ESITE", "di": "EEVIL"}},
	})
	defer wrongDi.Close()
	if err := h.verifyDelegationAnchor(bundle(wrongDi.URL)); err == nil {
		t.Fatal("wrong delegator must be rejected")
	}

	// Non-delegated inception → reject.
	icp := serve(map[string]interface{}{
		"aid": "ESITE",
		"kel": []map[string]interface{}{{"t": "icp", "i": "ESITE"}},
	})
	defer icp.Close()
	if err := h.verifyDelegationAnchor(bundle(icp.URL)); err == nil {
		t.Fatal("non-delegated site must be rejected")
	}

	// OOBI serving a different AID → reject.
	otherAID := serve(map[string]interface{}{
		"aid": "EOTHER",
		"kel": []map[string]interface{}{{"t": "dip", "i": "EOTHER", "di": "EORG"}},
	})
	defer otherAID.Close()
	if err := h.verifyDelegationAnchor(bundle(otherAID.URL)); err == nil {
		t.Fatal("mismatched OOBI AID must be rejected")
	}
}
