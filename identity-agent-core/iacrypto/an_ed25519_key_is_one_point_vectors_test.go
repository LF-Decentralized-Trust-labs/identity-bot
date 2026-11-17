package iacrypto

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The keys the page readers (login-verify's, login-dart's) are held to, read
// through the core's own decoders: a key is a witness key (code B) or a
// verification key (code D), and either is refused where it names no single
// signer.
func TestTheKeysAPageRefusesAreTheCores(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "packages", "login-web", "test-vectors", "ed25519-keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Cases []struct {
			Name string `json:"name"`
			B    string `json:"b"`
			D    string `json:"d"`
			OK   bool   `json:"ok"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Cases) < 10 {
		t.Fatalf("the shared cases are missing: %d", len(v.Cases))
	}
	for _, c := range v.Cases {
		_, errB := KeyFromNonTransferableAID(c.B)
		_, errD := KeyFromVerkeyQB64(c.D)
		if (errB == nil) != c.OK || (errD == nil) != c.OK {
			t.Errorf("%s: read as a witness key: %v, as a verification key: %v; want taken=%v", c.Name, errB, errD, c.OK)
		}
	}
}
