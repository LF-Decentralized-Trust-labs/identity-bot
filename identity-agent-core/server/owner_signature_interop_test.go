package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The client and the agent are two implementations of one construction, in two
// languages, released separately. This pins them together from the agent's
// side: the signature below was produced by the Dart client's golden-vector
// test, and this agent must accept it.
//
// If either side changes the canonical string, one of these two tests fails —
// which is the whole point. Without them a mismatch shows up as every request
// being refused in production, with nothing saying why.
func TestAcceptsASignatureProducedByTheDartClient(t *testing.T) {
	resetSeenSignatures(t)

	// The same fixed seed the client's test uses: bytes 1..32.
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)

	s := &CoreServer{DataDir: t.TempDir()}
	if err := s.SealOwnerAuthority(OwnerAuthority{
		AID:       "EDARTCLIENT",
		PublicKey: base64.RawURLEncoding.EncodeToString(pub),
	}); err != nil {
		t.Fatalf("seal: %v", err)
	}

	const (
		dartSignature = "0BDLE6J20nXw-Cf5q6cM0PPIJnCqtlSZYjoUMwfsVX8P2UrFxponlBjrXO68JBTLshkqPpiHW3oIYBJX-UJS32IH"
		dartTimestamp = "2026-07-27T12:00:00Z"
	)

	req := httptest.NewRequest(http.MethodGet, "/api/profile", nil)
	req.RemoteAddr = "203.0.113.9:51000" // remote: only the signature can admit it
	req.Header.Set(headerOwnerSig, dartSignature)
	req.Header.Set(headerOwnerTimestamp, dartTimestamp)

	// The timestamp is outside the freshness window by the time this test runs,
	// so verify the construction directly rather than the window.
	signed, err := time.Parse(time.RFC3339, dartTimestamp)
	if err != nil {
		t.Fatalf("timestamp: %v", err)
	}
	body := canonicalRequestString(http.MethodGet, "/api/profile", dartTimestamp, nil)

	authority, err := s.ownerAuthority()
	if err != nil {
		t.Fatalf("authority: %v", err)
	}
	pubRaw, err := decodeOwnerKey(authority.PublicKey)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	ok, err := verifyOwnerString(body, dartSignature, pubRaw)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatalf("the agent rejected a signature the Dart client produced.\n"+
			"canonical string the agent built:\n%q\n"+
			"If this changed deliberately, the client's owner_signature.dart must "+
			"change identically and in the same release.", body)
	}
	_ = signed
}
