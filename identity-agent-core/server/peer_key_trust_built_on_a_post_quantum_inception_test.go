//go:build kerigo_pqtest

package server

import (
	"encoding/json"
	"testing"

	"identity-agent-core/didcomm"
	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
)

// Anchored is the strong path: the identifier commits to the keys in its own
// inception, so nothing else has to be trusted.
func TestKeysCommittedInTheIdentifierAreAcceptedWithoutASignature(t *testing.T) {
	m := iacrypto.SyntheticHybridKeyMaterial(5)
	built, err := iacrypto.BuildHybridInception(m)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(built.InceptionEvent)
	var event map[string]interface{}
	_ = json.Unmarshal(raw, &event)

	did := &didcomm.DID{
		AID:    built.AID,
		X25519: b64urlOf(m.X25519AgreementRaw),
		MlKem:  b64urlOf(m.MLKEM768EncapRaw),
		Suite:  didcomm.CipherSuite,
	}

	trust, cerr := checkPeerKeys(did, []map[string]interface{}{event}, "")
	if cerr != nil {
		t.Fatalf("keys the identifier commits to were refused: %v", cerr)
	}
	if trust != peerKeysAnchored {
		t.Errorf("trust reported as %q, want %q", trust, peerKeysAnchored)
	}
}

// And an anchored identifier must refuse keys other than the ones it committed
// to, whoever signed for them.
func TestAnAnchoredIdentifierRefusesOtherKeys(t *testing.T) {
	m := iacrypto.SyntheticHybridKeyMaterial(5)
	built, _ := iacrypto.BuildHybridInception(m)
	raw, _ := json.Marshal(built.InceptionEvent)
	var event map[string]interface{}
	_ = json.Unmarshal(raw, &event)

	other := aDID(t, built.AID)
	seed, verkey := signingPair(t, 21)
	other.KelSig, _ = login.SignString(string(other.SigningInput()), seed)

	if _, err := checkPeerKeys(other, []map[string]interface{}{event}, verkey); err == nil {
		t.Fatal("an anchored identifier accepted keys it never committed to, because they were signed")
	}
}
