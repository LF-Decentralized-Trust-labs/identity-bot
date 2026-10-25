package login

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"identity-agent-core/iacrypto"
)

// The login assertion's golden vectors are pinned by the TypeScript package
// (packages/login-verify/golden_vectors.json). The Go side builds and checks
// the same assertion, so the two must agree byte for byte: the canonical body,
// its digest, the signature, and the key the carried key log puts in force.
// A field added on one side and not the other (as p_kel and site_aid were)
// fails here, not at the first sign-in between the two.
func TestTheGoldenAssertionIsTheSameInGoAndTypeScript(t *testing.T) {
	path := filepath.Join("..", "..", "packages", "login-verify", "golden_vectors.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("the TypeScript package is not beside this module here: %v", err)
	}
	var file struct {
		LoginAssertion struct {
			Assertion      Assertion `json:"assertion"`
			CanonicalBody  string    `json:"canonical_body"`
			Said           string    `json:"said"`
			SigningVerkey  string    `json:"signing_verkey_qb64"`
			ExpectedVerify struct {
				SiteAID string `json:"site_aid"`
			} `json:"expected_verify"`
		} `json:"login_assertion"`
	}
	if err := json.Unmarshal(b, &file); err != nil {
		t.Fatal(err)
	}
	g := file.LoginAssertion
	a := g.Assertion
	if a.PKEL == "" || a.SiteAID == "" || a.SiteAID != g.ExpectedVerify.SiteAID {
		t.Fatalf("the golden assertion does not carry a key log and the site it answers: %+v", a)
	}
	if got := canonicalAssertionBody(a); got != g.CanonicalBody {
		t.Fatalf("the Go canonical body differs from TypeScript's:\n go: %s\n ts: %s", got, g.CanonicalBody)
	}
	if d, err := assertionDigest(a); err != nil || d != g.Said || a.D != g.Said {
		t.Fatalf("the digest differs: go %s, ts %s (%v)", d, g.Said, err)
	}
	key, err := KeyFromKeyLog(a.I, a.PKEL)
	if err != nil {
		t.Fatalf("the golden key log does not establish the golden identity's key: %v", err)
	}
	if iacrypto.VerkeyQB64(key) != g.SigningVerkey {
		t.Fatalf("the key log puts %s in force, not the golden key %s", iacrypto.VerkeyQB64(key), g.SigningVerkey)
	}
	ok, err := VerifyString(canonicalAssertionBody(a), a.Sig, key)
	if err != nil || !ok {
		t.Fatalf("the golden signature does not verify in Go: %v", err)
	}
}
