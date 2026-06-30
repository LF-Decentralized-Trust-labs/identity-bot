package login

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
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
// assertion to the original challenge (nonce, audience, freshness), resolves the
// asserter's current signing key from its KERI AID/OOBI (did.json), and verifies the
// Ed25519 signature over the canonical assertion body. This is the inverse of the
// per-user flow's challenge verification — the same KERI primitives, RP side.
//
// The resolved key comes from the asserter's KEL (published at its OOBI), so a valid
// result traces back to the KERI identity, not a self-asserted key.
func VerifyAssertion(a Assertion, expectedNonce, expectedAudience string, maxSkewSeconds int, client *http.Client) AssertionVerifyResult {
	if client == nil {
		client = http.DefaultClient
	}
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
	if a.Sig == "" {
		return AssertionVerifyResult{Reason: "missing sig"}
	}

	pub, err := resolveAIDKey(client, a.RelationshipAIDOOBI, a.I)
	if err != nil {
		return AssertionVerifyResult{Reason: "key resolve failed: " + err.Error()}
	}
	ok, err := verifyUTF8(canonicalAssertionBody(a), a.Sig, pub)
	if err != nil || !ok {
		return AssertionVerifyResult{Reason: "invalid signature"}
	}
	return AssertionVerifyResult{Valid: true, PairwiseAID: a.I, Disclosures: a.Disclosures}
}

// resolveAIDKey fetches an AID's current Ed25519 signing key from its KERI did.json
// (resolved from the AID's OOBI). Mirrors resolveSiteKey; works for any AID.
func resolveAIDKey(client *http.Client, oobi, aid string) ([]byte, error) {
	relayBase := oobi
	if i := strings.Index(relayBase, "/oobi/"); i >= 0 {
		relayBase = relayBase[:i]
	}
	url := fmt.Sprintf("%s/%s/did.json", trimSlash(relayBase), aid)
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var doc struct {
		VerificationMethod []struct {
			PublicKeyJwk struct {
				X string `json:"x"`
			} `json:"publicKeyJwk"`
		} `json:"verificationMethod"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}
	if len(doc.VerificationMethod) == 0 || doc.VerificationMethod[0].PublicKeyJwk.X == "" {
		return nil, fmt.Errorf("did.json missing key")
	}
	return base64.RawURLEncoding.DecodeString(doc.VerificationMethod[0].PublicKeyJwk.X)
}
