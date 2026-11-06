package mobilecore

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// The phone reaches keymath through KeyMath, and a signature that is not on a
// key event comes back unindexed (0B), not the indexed form of an event's.
func TestAPhoneWritesASignatureOffAKeyEventUnindexed(t *testing.T) {
	sig := base64.StdEncoding.EncodeToString(make([]byte, 64))
	out, err := KeyMath("ed25519_sig", `{"sig_b64":"`+sig+`"}`)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Sig string `json:"sig_qb64"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil || !strings.HasPrefix(got.Sig, "0B") {
		t.Fatalf("got %q: %v", out, err)
	}
}
