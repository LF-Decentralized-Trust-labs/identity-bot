package login

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ADR-066: a challenge may name the thumbprint of a key a browser holds, the
// signed assertion repeats it, and a verifier accepts only the one it asked
// for. The vectors are pinned beside the TypeScript package's.
type browserKeyVectors struct {
	Jwk                    map[string]string `json:"jwk"`
	ThumbprintInput        string            `json:"thumbprint_jwk_input"`
	Thumbprint             string            `json:"thumbprint"`
	Assertion              Assertion         `json:"assertion"`
	AssertionCanonicalBody string            `json:"assertion_canonical_body"`
	Challenge              ChallengeBundle   `json:"challenge"`
	ChallengeCanonicalBody string            `json:"challenge_canonical_body"`
	SigningVerkey          string            `json:"signing_verkey_qb64"`
	Negative               struct {
		OtherBrowserKey string `json:"other_browser_key"`
	} `json:"negative_vectors"`
}

func loadBrowserKeyVectors(t *testing.T) browserKeyVectors {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "packages", "login-verify", "test-vectors", "browser-key-thumbprint.json"))
	if err != nil {
		t.Skipf("the TypeScript package is not beside this module here: %v", err)
	}
	var v browserKeyVectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestTheBrowserKeyVectorsAreTheSameInGoAndTypeScript(t *testing.T) {
	v := loadBrowserKeyVectors(t)
	if got, err := ThumbprintP256(v.Jwk["x"], v.Jwk["y"]); err != nil || got != v.Thumbprint {
		t.Fatalf("thumbprint: go %q (%v), vector %q", got, err, v.Thumbprint)
	}
	if v.Assertion.BrowserKey != v.Thumbprint || v.Challenge.BrowserKey != v.Thumbprint {
		t.Fatal("the vectors do not carry the thumbprint")
	}
	if got := canonicalAssertionBody(v.Assertion); got != v.AssertionCanonicalBody {
		t.Fatalf("assertion body differs:\n go: %s\n ts: %s", got, v.AssertionCanonicalBody)
	}
	if got := canonicalChallengeBody(v.Challenge); got != v.ChallengeCanonicalBody {
		t.Fatalf("challenge body differs:\n go: %s\n ts: %s", got, v.ChallengeCanonicalBody)
	}
	if !strings.Contains(v.AssertionCanonicalBody, `"browser_key":"`+v.Thumbprint+`"}`) {
		t.Fatal("the browser key is not the last field of the assertion body")
	}
	if d, err := assertionDigest(v.Assertion); err != nil || d != v.Assertion.D {
		t.Fatalf("digest: go %q (%v), vector %q", d, err, v.Assertion.D)
	}
	key, err := KeyFromKeyLog(v.Assertion.I, v.Assertion.PKEL)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := VerifyString(v.AssertionCanonicalBody, v.Assertion.Sig, key); err != nil || !ok {
		t.Fatalf("the assertion signature does not verify: %v", err)
	}
	if ok, err := VerifyString(v.ChallengeCanonicalBody, v.Challenge.Sig, key); err != nil || !ok {
		t.Fatalf("the challenge signature does not verify: %v", err)
	}
	// Strictly read, the way a verifier reads what it receives.
	raw, _ := json.Marshal(v.Challenge)
	if c, err := ReadChallengeBundle(raw); err != nil || c.BrowserKey != v.Thumbprint {
		t.Fatalf("the challenge is not read with its browser key: %v", err)
	}
}

// Nothing is verified against a fixed time here, so the vectors' own dt is
// moved to now and the assertion signed again by a fresh identity.
func TestAnAssertionIsAcceptedOnlyForTheBrowserKeyTheChallengeNamed(t *testing.T) {
	v := loadBrowserKeyVectors(t)
	aid, seed, keyLog := aRealIdentity(t)
	const nonce, aud = "n-browser", "https://app.example.com"
	mk := func(browserKey string) Assertion {
		a := anAssertion(t, aid, keyLog, seed, nonce, aud)
		a.D, a.Sig, a.BrowserKey, a.Dt = "", "", browserKey, time.Now().UTC().Format(time.RFC3339)
		if err := SignAssertion(&a, seed); err != nil {
			t.Fatal(err)
		}
		return a
	}
	good := mk(v.Thumbprint)
	if res := VerifyAssertionForBrowserKey(good, nonce, aud, testSite, v.Thumbprint, 300); !res.Valid {
		t.Fatalf("the right browser key was refused: %s", res.Reason)
	}
	for name, c := range map[string]struct {
		a        Assertion
		expected string
	}{
		"a different thumbprint expected":       {good, v.Negative.OtherBrowserKey},
		"the assertion names another key":       {mk(v.Negative.OtherBrowserKey), v.Thumbprint},
		"the assertion names no key":            {mk(""), v.Thumbprint},
		"the challenge named no key":            {good, ""},
		"a malformed thumbprint, both agreeing": {mk("short"), "short"},
	} {
		res := VerifyAssertionForBrowserKey(c.a, nonce, aud, testSite, c.expected, 300)
		if res.Valid || !strings.Contains(res.Reason, "browser key mismatch") {
			t.Errorf("%s: want a browser key refusal, got valid=%v reason=%q", name, res.Valid, res.Reason)
		}
	}
	// An assertion with the thumbprint rewritten after signing fails its signature.
	forged := good
	forged.BrowserKey = v.Negative.OtherBrowserKey
	if VerifyAssertionForBrowserKey(forged, nonce, aud, testSite, v.Negative.OtherBrowserKey, 300).Valid {
		t.Fatal("a thumbprint changed after signing was accepted")
	}
	// The plain verifier, which expects no browser key, refuses one that names a key.
	if VerifyAssertion(good, nonce, aud, testSite, 300).Valid {
		t.Fatal("VerifyAssertion accepted an assertion made for a browser key")
	}
}

func TestAThumbprintHasOneSpelling(t *testing.T) {
	v := loadBrowserKeyVectors(t)
	if err := CheckBrowserKeyThumbprint(v.Thumbprint); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", v.Thumbprint + "=", v.Thumbprint[:42], v.Thumbprint + "A", strings.Repeat("A", 42) + "B", strings.Repeat("+", 43)} {
		if CheckBrowserKeyThumbprint(bad) == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}
