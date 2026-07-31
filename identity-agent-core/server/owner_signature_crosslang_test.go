package server

import (
	"encoding/base64"
	"testing"

	"identity-agent-core/login"
)

// A signature made by the client must verify here.
//
// This is one construction implemented twice, in two languages, released
// separately. The two halves agree on nothing except this test: the client
// builds a string of method, path, timestamp and body digest, signs it, and
// this side rebuilds the same string and checks it. A difference of one
// newline, one case, one encoding, and every signed request is refused — with
// nothing in the error saying which side is wrong, because neither side is
// wrong on its own.
//
// It is a pinned vector rather than a live round trip on purpose. A test that
// needed both runtimes would be skipped in most places it matters, and this
// needs to fail loudly in the build that changes it.
//
// PRODUCED BY THE DART CLIENT on 2026-07-31, by OwnerSignature.headers over an
// all-sevens seed. To regenerate after a deliberate change: sign the same
// method, path, timestamp and body in the client and replace the values below —
// and understand that doing so is a wire change which invalidates every
// deployed signer, not a test fixup.
const (
	dartPublicKeyRawB64 = "6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw="
	dartMethod          = "POST"
	dartPath            = "/api/endpoint/publish"
	dartTimestamp       = "2026-07-31T12:00:00Z"
	dartBody            = `{"aid":"EOrg","url":"https://relay-b.test"}`
	dartSignature       = "0BA-A00AKZw0FQqB7FN9l1QrnA083xlqtswsJ6ixZ5c5rwbaRzizIj6QOInQgS6TIuKjWWT9JVtg8m-U-_CDjWgI"
)

func TestASignatureFromTheClientVerifiesHere(t *testing.T) {
	pub, err := base64.StdEncoding.DecodeString(dartPublicKeyRawB64)
	if err != nil {
		t.Fatal(err)
	}

	msg := canonicalRequestString(dartMethod, dartPath, dartTimestamp, []byte(dartBody))
	ok, err := login.VerifyString(msg, dartSignature, pub)
	if err != nil {
		t.Fatalf("verifying a client signature errored: %v", err)
	}
	if !ok {
		t.Fatalf("a signature produced by the client does not verify here.\n\n"+
			"The two canonical strings have diverged, so every signed request from "+
			"every client would be refused — and the error a person sees would say "+
			"only that the signature is invalid.\n\nThis side builds:\n%s", msg)
	}
}

// The digest is over the body, so a changed body must not still verify.
// Without this the test above would pass even if the body were dropped from
// the construction entirely.
func TestATamperedBodyDoesNotVerify(t *testing.T) {
	pub, _ := base64.StdEncoding.DecodeString(dartPublicKeyRawB64)

	msg := canonicalRequestString(dartMethod, dartPath, dartTimestamp,
		[]byte(`{"aid":"EOrg","url":"https://attacker.test"}`))
	ok, _ := login.VerifyString(msg, dartSignature, pub)
	if ok {
		t.Fatal("a signature verified over a body it was not made for — " +
			"the body is not actually covered")
	}
}

// Likewise the path, or a captured signature could be pointed at another
// endpoint.
func TestADifferentPathDoesNotVerify(t *testing.T) {
	pub, _ := base64.StdEncoding.DecodeString(dartPublicKeyRawB64)

	msg := canonicalRequestString(dartMethod, "/api/reset", dartTimestamp, []byte(dartBody))
	ok, _ := login.VerifyString(msg, dartSignature, pub)
	if ok {
		t.Fatal("a signature verified for a path it was not made for — " +
			"a captured signature could be aimed at any endpoint")
	}
}
