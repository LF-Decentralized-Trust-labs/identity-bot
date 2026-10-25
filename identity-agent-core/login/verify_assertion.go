package login

import (
	"time"
)

// AssertionVerifyResult is the relying-party-side outcome of checking a login assertion.
type AssertionVerifyResult struct {
	Valid       bool
	Reason      string
	PairwiseAID string
	Disclosures map[string]string
}

// VerifyAssertion verifies a login assertion on the relying-party side: it binds the
// assertion to the original challenge (nonce, audience, freshness), takes the
// asserter's current signing key from the key log the assertion carries (p_kel),
// and verifies the Ed25519 signature over the canonical assertion body.
//
// The key log is inside the signed body and proves itself: its inception must
// derive the identifier the assertion names, and every event must be signed by
// the key it declares (KeyFromKeyLog). Nothing is fetched, so nothing about
// where the assertion says its key lives is trusted. An assertion without a
// key log is refused, because nothing else ties a key to an identifier.
//
// expectedSiteAID is the site whose challenge this answers. The assertion must
// name it: an assertion naming another site was approved for that site's
// challenge, carrying this one's nonce and audience copied into it.
func VerifyAssertion(a Assertion, expectedNonce, expectedAudience, expectedSiteAID string, maxSkewSeconds int) AssertionVerifyResult {
	if maxSkewSeconds <= 0 {
		maxSkewSeconds = 300
	}

	dt, err := time.Parse(time.RFC3339, a.Dt)
	if err != nil {
		return AssertionVerifyResult{Reason: "bad dt"}
	}
	if d := time.Since(dt); d > time.Duration(maxSkewSeconds)*time.Second || d < -time.Duration(maxSkewSeconds)*time.Second {
		return AssertionVerifyResult{Reason: "dt outside freshness window"}
	}
	if a.Nonce != expectedNonce {
		return AssertionVerifyResult{Reason: "nonce mismatch"}
	}
	if a.Audience != expectedAudience {
		return AssertionVerifyResult{Reason: "audience mismatch"}
	}
	if expectedSiteAID == "" || a.SiteAID != expectedSiteAID {
		return AssertionVerifyResult{Reason: "site mismatch: the assertion answers another site's challenge"}
	}
	if a.Sig == "" {
		return AssertionVerifyResult{Reason: "missing sig"}
	}

	pub, err := KeyFromKeyLog(a.I, a.PKEL)
	if err != nil {
		return AssertionVerifyResult{Reason: "key resolve failed: " + err.Error()}
	}
	ok, err := verifyUTF8(canonicalAssertionBody(a), a.Sig, pub)
	if err != nil || !ok {
		return AssertionVerifyResult{Reason: "invalid signature"}
	}
	return AssertionVerifyResult{Valid: true, PairwiseAID: a.I, Disclosures: a.Disclosures}
}
