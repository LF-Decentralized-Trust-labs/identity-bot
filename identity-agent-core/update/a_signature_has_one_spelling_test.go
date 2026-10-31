package update

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
)

// A manifest's signature is read in its one canonical string: unpadded
// base64url with its 4 spare bits zero. The update package's own decoder took
// padding, ignored spare bits and skipped line breaks, so each signature had
// many strings that verified.
func TestARespelledManifestSignatureIsRefused(t *testing.T) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	pub, priv, _ := ed25519.GenerateKey(nil)
	ta, err := NewTrustAnchor(map[string][]byte{"spelling-test": pub})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignManifestForTest([]byte(`{"manifest_version":1,"published_at":"2026-06-15T00:00:00Z","signing_key_id":"spelling-test","channels":{},"components":{},"signature":""}`), priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyManifest(signed, ta); err != nil {
		t.Fatalf("the canonical manifest did not verify: %v", err)
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(signed, &obj); err != nil {
		t.Fatal(err)
	}
	sig := obj["signature"].(string)
	last := len(sig) - 1
	v := strings.IndexByte(alphabet, sig[last])
	for name, other := range map[string]string{
		"spare bits": sig[:last] + string(alphabet[v|1]),
		"padded":     sig + "==",
		"line break": sig[:20] + "\n" + sig[20:],
	} {
		obj["signature"] = other
		raw, _ := json.Marshal(obj)
		if _, err := VerifyManifest(raw, ta); err == nil {
			t.Errorf("%s: a manifest whose signature is %q verified", name, other)
		}
	}
}
