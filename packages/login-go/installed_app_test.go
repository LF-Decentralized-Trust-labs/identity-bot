package login

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"
)

// The same file login-dart runs: the statement an installed front end's key signs,
// the thumbprint that names the key, and what a sign-in start may say.
type installedVectors struct {
	Statement  []map[string]string `json:"statement"`
	Thumbprint []map[string]string `json:"thumbprint"`
	Starts     []struct {
		Name   string `json:"name"`
		Body   string `json:"body"`
		Expect string `json:"expect"`
		Refuse string `json:"refuse"`
	} `json:"starts"`
}

func readInstalledVectors(t *testing.T) installedVectors {
	t.Helper()
	raw, err := os.ReadFile("../login-web/test-vectors/installed-app.json")
	if err != nil {
		t.Fatal(err)
	}
	var v installedVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestTheStatementAnInstalledKeySignsIsTheSharedOne(t *testing.T) {
	for _, c := range readInstalledVectors(t).Statement {
		ch, err := b64uDecodeForTest(c["challenge_b64u"])
		if err != nil {
			t.Fatal(err)
		}
		got := InstalledAppStatement(c["asset_id"], ch, c["thumbprint"])
		if string(got) != c["text"] {
			t.Fatalf("%s: statement %q, want %q", c["name"], got, c["text"])
		}
		d := InstalledAppStatementDigest(c["asset_id"], ch, c["thumbprint"])
		if hex.EncodeToString(d[:]) != c["sha256_hex"] || d != sha256.Sum256([]byte(c["text"])) {
			t.Fatalf("%s: digest differs", c["name"])
		}
	}
}

func TestAKeyIsNamedByItsThumbprint(t *testing.T) {
	for _, c := range readInstalledVectors(t).Thumbprint {
		if got := KeyThumbprint(c["x"], c["y"]); got != c["thumbprint"] {
			t.Fatalf("thumbprint %s, want %s", got, c["thumbprint"])
		}
	}
}

func TestASignInStartIsReadAsTheSharedCasesRead(t *testing.T) {
	for _, c := range readInstalledVectors(t).Starts {
		s, err := ReadFrontEndStart([]byte(c.Body))
		if c.Refuse != "" {
			if err == nil || !strings.Contains(err.Error(), c.Refuse) {
				t.Fatalf("%s: err %v, want one containing %q", c.Name, err, c.Refuse)
			}
			continue
		}
		if err != nil || s.FrontEnd != c.Expect {
			t.Fatalf("%s: %v %+v", c.Name, err, s)
		}
	}
}

func TestASitesPublicRoutesNeverDropAnInstalledAppsProofSilently(t *testing.T) {
	_, err := HTTPAgent{}.Start(t.Context(), StartRequest{FrontEnd: FrontEndInstalledApp, InstalledAppKey: &InstalledKeyProof{}})
	if err == nil || !strings.Contains(err.Error(), "public routes") {
		t.Fatalf("err %v", err)
	}
}

func b64uDecodeForTest(s string) ([]byte, error) { return base64RawURL.DecodeString(s) }

var base64RawURL = base64.RawURLEncoding

func TestAnAppleAssertionIsCheckedAsTheIdentityAgentChecksIt(t *testing.T) {
	var v struct {
		A struct {
			AppID     string `json:"app_id"`
			XHex      string `json:"key_x_hex"`
			YHex      string `json:"key_y_hex"`
			ProofText string `json:"proof_text"`
			Assertion string `json:"assertion_hex"`
			Counter   uint32 `json:"counter"`
			Refusals  []struct {
				Name      string `json:"name"`
				AppID     string `json:"app_id"`
				ProofText string `json:"proof_text"`
				Refuse    string `json:"refuse"`
			} `json:"refusals"`
		} `json:"apple_assertion"`
	}
	raw, err := os.ReadFile("../login-web/test-vectors/installed-app.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	a := v.A
	x, _ := hex.DecodeString(a.XHex)
	y, _ := hex.DecodeString(a.YHex)
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	as, _ := hex.DecodeString(a.Assertion)
	if !IsAssertionProof(as) || IsAssertionProof(make([]byte, 64)) {
		t.Fatal("an assertion is told from a plain 64-byte proof by its length")
	}
	h := sha256.Sum256([]byte(a.ProofText))
	n, err := VerifyAppleAssertion(as, h[:], pub, a.AppID)
	if err != nil || n != a.Counter {
		t.Fatalf("a good assertion: %d %v", n, err)
	}
	for _, c := range a.Refusals {
		app, text := a.AppID, a.ProofText
		if c.AppID != "" {
			app = c.AppID
		}
		if c.ProofText != "" {
			text = c.ProofText
		}
		hh := sha256.Sum256([]byte(text))
		if _, err := VerifyAppleAssertion(as, hh[:], pub, app); err == nil || !strings.Contains(err.Error(), c.Refuse) {
			t.Fatalf("%s: %v", c.Name, err)
		}
	}
	for _, bad := range [][]byte{nil, {0xa1}, as[:len(as)-1], append(append([]byte{}, as...), 0)} {
		if _, err := VerifyAppleAssertion(bad, h[:], pub, a.AppID); err == nil {
			t.Fatalf("a malformed assertion was taken: %x", bad)
		}
	}
}

func TestACredentialRequestIsReadStrictly(t *testing.T) {
	ok := `{"ask":"a","ek_public":"AAEB","ek_cert":"MAA=","ek_chain":["MAE="],"ak_public":"AAEC"}`
	q, err := ReadInstalledCredentialRequest([]byte(ok))
	if err != nil || q.Ask != "a" || len(q.EKChain) != 1 || len(q.AKPublic) != 3 {
		t.Fatalf("a whole request was refused or misread: %+v, %v", q, err)
	}
	for name, body := range map[string]string{
		"no ask":       `{"ek_public":"AAEB","ek_cert":"MAA=","ak_public":"AAEC"}`,
		"no cert":      `{"ask":"a","ek_public":"AAEB","ak_public":"AAEC"}`,
		"no AK":        `{"ask":"a","ek_public":"AAEB","ek_cert":"MAA="}`,
		"unknown part": `{"ask":"a","ek_public":"AAEB","ek_cert":"MAA=","ak_public":"AAEC","extra":1}`,
		"two docs":     ok + ok,
		"empty issuer": `{"ask":"a","ek_public":"AAEB","ek_cert":"MAA=","ek_chain":[""],"ak_public":"AAEC"}`,
		"huge":         `{"ask":"a","ek_public":"AAEB","ek_cert":"` + strings.Repeat("QQ", 9000) + `","ak_public":"AAEC"}`,
	} {
		if _, err := ReadInstalledCredentialRequest([]byte(body)); err == nil {
			t.Errorf("%s: was read", name)
		}
	}
}
