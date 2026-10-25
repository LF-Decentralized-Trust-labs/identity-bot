package login

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"identity-agent-core/iacrypto"
)

// aRealIdentity mints a genuine identity: an inception built from a key and a
// pre-rotated next key, whose identifier is the digest of that inception. Its
// key log is the inception, signed with the key it declares.
func aRealIdentity(t *testing.T) (aid string, seed []byte, keyLog string) {
	t.Helper()
	seed = make([]byte, ed25519.SeedSize)
	next := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(next); err != nil {
		t.Fatal(err)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	nextPub := ed25519.NewKeyFromSeed(next).Public().(ed25519.PublicKey)
	icp, err := iacrypto.BuildEd25519Inception(pub, nextPub)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(icp.RawBytesB64)
	sig, err := SignString(string(raw), seed)
	if err != nil {
		t.Fatal(err)
	}
	keyLog, err = EncodeKeyLog([][]byte{raw}, []string{sig})
	if err != nil {
		t.Fatal(err)
	}
	return icp.AID, seed, keyLog
}

// testSite is the site whose challenge the test assertions answer.
const testSite = "ESiteWhoseChallengeThisAnswers"

func anAssertion(t *testing.T, aid, keyLog string, seed []byte, nonce, aud string) Assertion {
	t.Helper()
	a := Assertion{
		V:                   "IALOGIN10JSON",
		T:                   "login-assertion",
		I:                   aid,
		RelationshipAIDOOBI: "https://wherever.example/oobi/" + aid,
		Audience:            aud,
		Nonce:               nonce,
		Dt:                  time.Now().UTC().Format(time.RFC3339),
		Disclosures:         map[string]string{"display_name": "Test User"},
		PresentedACDCs:      []interface{}{},
		PKEL:                keyLog,
		SiteAID:             testSite,
	}
	if err := SignAssertion(&a, seed); err != nil {
		t.Fatal(err)
	}
	return a
}

// TestVerifyAssertionRoundTrip proves the RP-side assertion verification: an
// assertion signed by the key its own key log establishes verifies, with
// nothing fetched, and is rejected on nonce, audience or tampering.
func TestVerifyAssertionRoundTrip(t *testing.T) {
	aid, seed, keyLog := aRealIdentity(t)
	const nonce = "challenge-nonce-xyz"
	const aud = "Example RP"
	a := anAssertion(t, aid, keyLog, seed, nonce, aud)

	if res := VerifyAssertion(a, nonce, aud, testSite, 300); !res.Valid {
		t.Fatalf("expected valid, got reason=%q", res.Reason)
	} else if res.PairwiseAID != aid {
		t.Fatalf("pairwiseAID = %q, want %q", res.PairwiseAID, aid)
	}

	if VerifyAssertion(a, "wrong-nonce", aud, testSite, 300).Valid {
		t.Fatal("nonce mismatch must fail")
	}
	if VerifyAssertion(a, nonce, "Evil RP", testSite, 300).Valid {
		t.Fatal("audience mismatch must fail")
	}
	tampered := a
	tampered.Disclosures = map[string]string{"display_name": "Hacker"}
	if VerifyAssertion(tampered, nonce, aud, testSite, 300).Valid {
		t.Fatal("tampered body must fail")
	}
}

// Naming somebody else's identifier gets nothing. The assertion is signed with
// the attacker's key and carries the attacker's own valid key log, but that log
// derives the attacker's identifier, not the one named.
func TestAnAssertionNamingSomebodyElsesIdentifierIsRefused(t *testing.T) {
	victim, _, _ := aRealIdentity(t)
	_, attackerSeed, attackerLog := aRealIdentity(t)

	a := anAssertion(t, victim, attackerLog, attackerSeed, "n", "aud")
	res := VerifyAssertion(a, "n", "aud", testSite, 300)
	if res.Valid {
		t.Fatal("an assertion naming another identity was accepted")
	}
	if !strings.Contains(res.Reason, "not "+victim) {
		t.Errorf("refused for the wrong reason: %q", res.Reason)
	}
}

// An assertion with no key log has nothing to tie a key to its identifier, and
// is refused rather than resolved from wherever it says its key lives.
func TestAnAssertionWithNoKeyLogIsRefused(t *testing.T) {
	aid, seed, _ := aRealIdentity(t)
	a := anAssertion(t, aid, "", seed, "n", "aud")
	if res := VerifyAssertion(a, "n", "aud", testSite, 300); res.Valid {
		t.Fatal("an assertion with no key log was accepted")
	}
}

// The victim's own log, but signed by somebody else: the log names the
// victim's key, and the signature is not by it.
func TestTheRightLogWithTheWrongKeyIsRefused(t *testing.T) {
	victim, _, victimLog := aRealIdentity(t)
	_, attackerSeed, _ := aRealIdentity(t)
	a := anAssertion(t, victim, victimLog, attackerSeed, "n", "aud")
	if res := VerifyAssertion(a, "n", "aud", testSite, 300); res.Valid || res.Reason != "invalid signature" {
		t.Fatalf("expected invalid signature, got valid=%v reason=%q", res.Valid, res.Reason)
	}
}

// An unsigned log proves nothing about who authorised it, even when it
// derives the identifier.
func TestAnUnsignedKeyLogEstablishesNoKey(t *testing.T) {
	aid, _, keyLog := aRealIdentity(t)
	kl, err := DecodeKeyLog(keyLog)
	if err != nil {
		t.Fatal(err)
	}
	raws := [][]byte{}
	for _, r := range kl.RawEventsB64 {
		b, _ := base64.StdEncoding.DecodeString(r)
		raws = append(raws, b)
	}
	unsigned, err := EncodeKeyLog(raws, []string{""})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := KeyFromKeyLog(aid, unsigned); err == nil {
		t.Fatal("an unsigned key log established a key")
	}
}
