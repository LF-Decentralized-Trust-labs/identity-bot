package login

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
