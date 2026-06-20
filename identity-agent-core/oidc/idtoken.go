package oidc

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"identity-agent-core/didwebs"
	"identity-agent-core/login"
)

const (
	ClaimSeam8Assertion       = ClaimNamespace + "/seam8_assertion"
	ClaimSeam8AssertionDigest = ClaimNamespace + "/seam8_assertion_digest"
)

// BuildIDToken wraps a signed login assertion as a self-issued OIDC ID token (JWT-primary).
func BuildIDToken(host string, assertion *login.Assertion, seed []byte, ttl time.Duration) (string, error) {
	if assertion == nil || assertion.Sig == "" {
		return "", fmt.Errorf("assertion must be signed")
	}
	if len(seed) != ed25519.SeedSize {
		return "", fmt.Errorf("invalid signing seed")
	}
	did := fmt.Sprintf("did:webs:%s:%s", didwebs.ColonHost(host), assertion.I)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	kid := fmt.Sprintf("%s#%s", did, didwebs.KeyIDFromPub(pub))

	iat, err := time.Parse(time.RFC3339, assertion.Dt)
	if err != nil {
		return "", fmt.Errorf("invalid assertion dt: %w", err)
	}
	exp := iat.Add(ttl)

	claims := map[string]interface{}{
		"iss": did,
		"sub": did,
		"aud": assertion.Audience,
		"nonce": assertion.Nonce,
		"iat": iat.Unix(),
		"exp": exp.Unix(),
		ClaimSeam8AssertionDigest: assertion.D,
		ClaimSeam8Assertion:       assertion,
	}
	for k, v := range ClaimsFromDisclosures(assertion.Disclosures) {
		claims[k] = v
	}
	if band, score := grapeScoreFromAssertion(assertion); band != "" {
		claims[ClaimNamespace+"/grape_score_band"] = band
		if score > 0 {
			claims[ClaimNamespace+"/grape_score"] = score
		}
	}

	return signJWT(claims, seed, kid)
}

func signJWT(claims map[string]interface{}, seed []byte, kid string) (string, error) {
	header := map[string]string{
		"alg": "EdDSA",
		"typ": "JWT",
		"kid": kid,
	}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	seg := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	priv := ed25519.NewKeyFromSeed(seed)
	sig := ed25519.Sign(priv, []byte(seg))
	return seg + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}