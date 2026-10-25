package login

import (
	"strings"
	"testing"
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
