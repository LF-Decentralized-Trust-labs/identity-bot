package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

	s := &CoreServer{localOwnerSecret: testOwnerSecret, DataDir: t.TempDir()}
	if err := s.SealOwnerAuthority(OwnerAuthority{
		AID:       "EDARTCLIENT",
		PublicKey: base64.RawURLEncoding.EncodeToString(pub),
	}); err != nil {
		t.Fatalf("seal: %v", err)
	}

	const (
		dartSignature = "0BDuezD3LBmx9DEFugOkyMZtZOfPETxsToamKGnFoF2Z8y7d8bVsrmsLpsrvRKPLgSpvIeMwaDQFGtfEkwauEUsK"
		dartTimestamp = "2026-07-27T12:00:00Z"
		// The Identity Agent the Dart client's vector names.
		dartTarget = "EGOLDENIDENTITYAGENT"
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
	body := canonicalOwnerRequest(dartTarget, http.MethodGet, "/api/profile", dartTimestamp, nil)

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

// The vectors for X-IA-Body-Digest, pinned from both sides: packages/agent_client
// /test/owner_signature_test.dart holds the same constants. The signed string is
// the one it always was; the header carries the digest it already contains, so
// the agent can check the signature before it reads the body.
func TestTheBodyDigestVectors(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)

	const (
		target    = "EGOLDENIDENTITYAGENT"
		stamp     = "2026-07-27T12:00:00Z"
		path      = "/api/recovery/start"
		body      = `{"archive_b64":"AAAA"}`
		digest    = "EGYyOU4vRQiXR9KODcp7bLmX2fzoFVAbS9ozYvstod3d"
		signature = "0BCg90nECbDmFqAN13nETR9MK5po24EF5FSlM22NAXpbaag1xsPIPZAOXOA85y2RGF2-UNyC3q7atuiLjxmI5tgD"
		// A body that is not the one signed.
		otherBody = `{"archive_b64":"BBBB"}`
	)

	// Vector 1: a request with its digest header. The digest is Blake3 of the
	// body in qb64, and the signature covers the string built from it.
	if got := digestOf(body); got != digest {
		t.Fatalf("digest of the body is %s, want %s", got, digest)
	}
	signed := canonicalOwnerRequestOver(target, http.MethodPost, path, stamp, digest)
	if want := "IA-REQ-V2\n" + target + "\nPOST\n" + path + "\n" + stamp + "\n" + digest; signed != want {
		t.Fatalf("signed string is %q, want %q", signed, want)
	}
	if signed != canonicalOwnerRequest(target, http.MethodPost, path, stamp, []byte(body)) {
		t.Fatal("the string built from the digest differs from the one built from the body")
	}
	ok, err := verifyOwnerString(signed, signature, pub)
	if err != nil || !ok {
		t.Fatalf("the vector's signature does not verify over its digest (ok %v, err %v)", ok, err)
	}

	// The body that matches its header is read; the one that does not is refused.
	good := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if err := readTheBodyAgainst(good, digest); err != nil {
		t.Fatalf("the body that was signed was refused: %v", err)
	}
	// Vector 2: the same header and signature, a body that is not the signed one.
	bad := httptest.NewRequest(http.MethodPost, path, strings.NewReader(otherBody))
	if err := readTheBodyAgainst(bad, digest); !errors.As(err, new(bodyDoesNotMatchItsDigest)) {
		t.Fatalf("a body that is not the signed one was not refused as a mismatch: %v", err)
	}
}
