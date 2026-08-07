package iacrypto

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

// The keys an identifier commits to must come back out exactly as they went in.
// If they do not, the anchor is decoration and every caller is back to asking
// the network which keys belong to an identifier.
func TestTheKeysAnIdentifierCommitsToComeBackOut(t *testing.T) {
	m := SyntheticHybridKeyMaterial(7)
	built, err := BuildHybridInception(m)
	if err != nil {
		t.Fatal(err)
	}

	// Through JSON, because that is how an event reaches a verifier — never as
	// the Go map the builder happened to return.
	raw, err := json.Marshal(built.InceptionEvent)
	if err != nil {
		t.Fatal(err)
	}
	var event map[string]interface{}
	if err := json.Unmarshal(raw, &event); err != nil {
		t.Fatal(err)
	}

	x, kem, err := AnchoredAgreementKeys(event)
	if err != nil {
		t.Fatalf("an anchored inception did not yield its keys: %v", err)
	}
	if !bytes.Equal(x, m.X25519AgreementRaw) {
		t.Error("the agreement key that came out is not the one that went in")
	}
	if !bytes.Equal(kem, m.MLKEM768EncapRaw) {
		t.Error("the encapsulation key that came out is not the one that went in")
	}
}

// An identifier created before anchoring existed says so distinguishably, so a
// log reader can tell "predates this" from "being tampered with". Both refuse.
func TestAnIdentifierWithNoAnchorSaysSo(t *testing.T) {
	for _, event := range []map[string]interface{}{
		{"t": "icp"},
		{"t": "icp", "a": []interface{}{}},
		{"t": "icp", "a": []interface{}{map[string]interface{}{"other": "seal"}}},
	} {
		if _, _, err := AnchoredAgreementKeys(event); !errors.Is(err, ErrNotAnchored) {
			t.Errorf("expected ErrNotAnchored, got %v", err)
		}
	}
}

// The two keys are the same shape once their prefix is removed, so a reader
// that trusts position over label will happily read one as the other.
func TestAKeyCannotBePassedOffAsTheOtherKind(t *testing.T) {
	m := SyntheticHybridKeyMaterial(3)
	built, _ := BuildHybridInception(m)
	raw, _ := json.Marshal(built.InceptionEvent)
	var event map[string]interface{}
	_ = json.Unmarshal(raw, &event)

	seal := event["a"].([]interface{})[0].(map[string]interface{})
	ka := seal["ka"].([]interface{})
	// Swap them. Both are real keys, correctly encoded — only in the wrong order.
	ka[0], ka[1] = ka[1], ka[0]

	if _, _, err := AnchoredAgreementKeys(event); err == nil {
		t.Fatal("the encapsulation key was accepted as the agreement key")
	}
}

// A truncated or lengthened key must be refused rather than used at whatever
// size it arrived.
func TestAKeyOfTheWrongLengthIsRefused(t *testing.T) {
	m := SyntheticHybridKeyMaterial(11)
	built, _ := BuildHybridInception(m)
	raw, _ := json.Marshal(built.InceptionEvent)
	var event map[string]interface{}
	_ = json.Unmarshal(raw, &event)

	seal := event["a"].([]interface{})[0].(map[string]interface{})
	ka := seal["ka"].([]interface{})
	full := ka[0].(string)
	ka[0] = full[:len(full)-4] // still valid base64url, wrong length

	if _, _, err := AnchoredAgreementKeys(event); err == nil {
		t.Fatal("a short agreement key was accepted")
	}
}

func TestDecodeRejectsTheWrongCode(t *testing.T) {
	m := SyntheticHybridKeyMaterial(2)
	good, err := EncodeLargeFixed(CESRX25519Pubkey, m.X25519AgreementRaw, X25519PubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeLargeFixed(CESRMLKEM768Encap, good, MLKEM768EncapBytes); err == nil {
		t.Error("a value was decoded under a code it does not carry")
	}
	back, err := DecodeLargeFixed(CESRX25519Pubkey, good, X25519PubkeyBytes)
	if err != nil {
		t.Fatalf("round trip failed: %v", err)
	}
	if !bytes.Equal(back, m.X25519AgreementRaw) {
		t.Error("round trip changed the bytes")
	}
}
