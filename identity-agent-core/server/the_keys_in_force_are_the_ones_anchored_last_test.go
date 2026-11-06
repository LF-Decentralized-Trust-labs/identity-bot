package server

import (
	"strings"
	"testing"

	"identity-agent-core/didcomm"
	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
)

// anchoringKeys is an event at sn anchoring ks's keyset, the founding (icp at
// 0) or one that replaces it (ixn), as a move to a new recovery phrase does
// (ADR-061 section 8).
func anchoringKeys(t *testing.T, aid string, ks *didcomm.KeySet, ilk, sn string) map[string]interface{} {
	t.Helper()
	kem, err := ks.KemPub.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	dsa, err := ks.DsaPub.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := iacrypto.KeySetAnchor(ks.XPub[:], kem, ks.EdPub, dsa)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]interface{}{"t": ilk, "s": sn, "i": aid, "d": "E" + sn + "-" + aid,
		"a": []interface{}{anchor}}
}

func didOf(t *testing.T, ks *didcomm.KeySet) *didcomm.DID {
	t.Helper()
	d, err := ks.DID()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// After the keyset is replaced, the identity is reached on the new keys and
// not on the founding's, which derive from a phrase that may have leaked.
// Fails when the check reads the founding event alone.
func TestTheKeysInForceAreTheOnesTheLogAnchoredLast(t *testing.T) {
	const aid = "EMOVED"
	founding, err := didcomm.GenerateKeySet(aid)
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := didcomm.GenerateKeySet(aid)
	if err != nil {
		t.Fatal(err)
	}
	log := []map[string]interface{}{anchoringKeys(t, aid, founding, "icp", "0"),
		{"t": "ixn", "s": "1", "d": "E1", "a": []interface{}{}},
		anchoringKeys(t, aid, replacement, "ixn", "2"),
		{"t": "ixn", "s": "3", "d": "E3", "a": []interface{}{}}}

	trust, err := checkPeerKeys(didOf(t, replacement), log, "")
	if err != nil || trust != peerKeysAnchored {
		t.Fatalf("the replacement keyset was not taken as the keys in force: %q %v", trust, err)
	}
	if _, err := checkPeerKeys(didOf(t, founding), log, ""); err == nil {
		t.Fatal("the founding keyset was still accepted after the log replaced it")
	}
	// Before the replacement, the founding's are the keys in force.
	if _, err := checkPeerKeys(didOf(t, founding), log[:2], ""); err != nil {
		t.Fatalf("the founding keyset was refused before anything replaced it: %v", err)
	}
	if _, err := checkPeerKeys(didOf(t, replacement), log[:2], ""); err == nil {
		t.Fatal("a keyset the log had not yet anchored was accepted")
	}
}

// An anchor that commits to encryption keys and no signing keys is not one
// this software makes, so signing keys served beside it are tied to nothing.
// Fails when a missing signing-key anchor is let through.
func TestAnAnchorWithNoSigningKeysTiesNoSigningKeys(t *testing.T) {
	const aid = "ENOSA"
	ks, err := didcomm.GenerateKeySet(aid)
	if err != nil {
		t.Fatal(err)
	}
	log := []map[string]interface{}{anchoringKeys(t, aid, ks, "icp", "0")}
	anchor := log[0]["a"].([]interface{})[0].(map[string]interface{})
	delete(anchor, "sa")

	_, err = checkPeerKeys(didOf(t, ks), log, "")
	if err == nil || !strings.Contains(err.Error(), "no signing keys") {
		t.Fatalf("signing keys tied to nothing were accepted: %v", err)
	}
	// Signed by the identity's current key, they are tied after all.
	seed, verkey := signingPair(t, 31)
	vouched := didOf(t, ks)
	vouched.KelSig, _ = login.SignString(string(vouched.SigningInput()), seed)
	if _, err := checkPeerKeys(vouched, log, verkey); err != nil {
		t.Fatalf("signing keys the identity signed for were refused: %v", err)
	}
	// And offering no signing keys takes nothing untied.
	encryptionOnly := didOf(t, ks)
	encryptionOnly.Ed, encryptionOnly.Dsa = "", ""
	if _, err := checkPeerKeys(encryptionOnly, log, ""); err != nil {
		t.Fatalf("the committed encryption keys alone were refused: %v", err)
	}
}

// The one walk, as both the key check and the core's own messaging keyset
// read it: the last event anchoring a keyset, or none.
func TestTheKeysetInForceIsTheLastAnchored(t *testing.T) {
	ks, err := didcomm.GenerateKeySet("EWALK")
	if err != nil {
		t.Fatal(err)
	}
	log := []map[string]interface{}{anchoringKeys(t, "EWALK", ks, "icp", "0"),
		anchoringKeys(t, "EWALK", ks, "ixn", "1"), {"t": "ixn", "s": "2", "d": "E2"}}
	got, err := iacrypto.KeySetInForce(log)
	if err != nil || got["s"] != "1" {
		t.Fatalf("the keyset in force is read from %v (%v), want the event at 1", got["s"], err)
	}
	if _, err := iacrypto.KeySetInForce(log[2:]); err != iacrypto.ErrNotAnchored {
		t.Fatalf("a log anchoring no keyset answered %v", err)
	}
	// A rotation can anchor the replacement as well as an interaction can.
	other, err := didcomm.GenerateKeySet("EWALK")
	if err != nil {
		t.Fatal(err)
	}
	rotated := append(log, anchoringKeys(t, "EWALK", other, "rot", "3"))
	if _, err := checkPeerKeys(didOf(t, other), rotated, ""); err != nil {
		t.Fatalf("a keyset a rotation anchored was refused: %v", err)
	}
	if _, err := checkPeerKeys(didOf(t, ks), rotated, ""); err == nil {
		t.Fatal("the keyset a rotation replaced was still accepted")
	}
}
