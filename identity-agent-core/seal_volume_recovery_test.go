package main

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"identity-agent-core/backup"
)

// The property the whole recovery slot exists for: the instance creates a way
// back in that it cannot itself use, and the owner can.
//
// Tested at the sealing layer rather than against a real volume, because
// cryptsetup needs a device and root. What is checked here is the part that
// would silently destroy recoverability if it were wrong — whether the secret
// this machine writes down can actually be recovered by the owner it was
// written for.

func ownerKeypair(t *testing.T) (priv, pub []byte) {
	t.Helper()
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i * 7)
	}
	priv, pub, err := backup.DeriveSealKeypair(seed)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func TestTheOwnerCanRecoverWhatTheInstanceSealedForThem(t *testing.T) {
	priv, pub := ownerKeypair(t)

	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(255 - i)
	}

	epk, wrapped, nonce, err := backup.SealBEK(pub, secret)
	if err != nil {
		t.Fatal(err)
	}

	got, err := backup.UnsealBEK(priv, epk, wrapped, nonce)
	if err != nil {
		t.Fatalf("the owner could not open what was sealed for them, so a volume "+
			"sealed this way would be unrecoverable: %v", err)
	}
	if string(got) != string(secret) {
		t.Fatal("the owner recovered a different secret than was sealed")
	}
}

// A different owner must not recover it. Without this the seal is decoration.
func TestSomebodyElsesKeyDoesNotRecoverIt(t *testing.T) {
	_, pub := ownerKeypair(t)

	otherSeed := make([]byte, 64)
	for i := range otherSeed {
		otherSeed[i] = byte(i*13 + 1)
	}
	otherPriv, _, err := backup.DeriveSealKeypair(otherSeed)
	if err != nil {
		t.Fatal(err)
	}

	secret := make([]byte, 32)
	epk, wrapped, nonce, _ := backup.SealBEK(pub, secret)

	if _, err := backup.UnsealBEK(otherPriv, epk, wrapped, nonce); err == nil {
		t.Fatal("a different owner's key opened the recovery secret")
	}
}

// One sealed copy per owner, any of which recovers alone. An organisation has
// an owner per signer, and needing several to agree means losing the data when
// one is unreachable.
func TestEveryOwnerCanRecoverAlone(t *testing.T) {
	seeds := [][]byte{make([]byte, 64), make([]byte, 64)}
	for i := range seeds {
		for j := range seeds[i] {
			seeds[i][j] = byte(j + i*100)
		}
	}
	var privs, pubs [][]byte
	for _, s := range seeds {
		priv, pub, err := backup.DeriveSealKeypair(s)
		if err != nil {
			t.Fatal(err)
		}
		privs = append(privs, priv)
		pubs = append(pubs, pub)
	}

	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}

	var slot ownerRecoverySlot
	for _, pub := range pubs {
		epk, wrapped, nonce, err := backup.SealBEK(pub, secret)
		if err != nil {
			t.Fatal(err)
		}
		slot.Owners = append(slot.Owners, sealedForOwner{
			EphemeralPublicKeyB64: base64.StdEncoding.EncodeToString(epk),
			WrappedSecretB64:      base64.StdEncoding.EncodeToString(wrapped),
			NonceB64:              base64.StdEncoding.EncodeToString(nonce),
		})
	}

	// Each owner tries every slot, because none is labelled — publishing which
	// slot belongs to whom would put an organisation's ownership on every copy
	// of its volume.
	for i, priv := range privs {
		recovered := false
		for _, o := range slot.Owners {
			epk, _ := base64.StdEncoding.DecodeString(o.EphemeralPublicKeyB64)
			wrapped, _ := base64.StdEncoding.DecodeString(o.WrappedSecretB64)
			nonce, _ := base64.StdEncoding.DecodeString(o.NonceB64)
			if got, err := backup.UnsealBEK(priv, epk, wrapped, nonce); err == nil && string(got) == string(secret) {
				recovered = true
				break
			}
		}
		if !recovered {
			t.Fatalf("owner %d could not recover alone", i)
		}
	}
}

// The record written into the volume header names no owner.
func TestTheHeaderRecordNamesNobody(t *testing.T) {
	_, pub := ownerKeypair(t)
	secret := make([]byte, 32)
	epk, wrapped, nonce, _ := backup.SealBEK(pub, secret)

	slot := ownerRecoverySlot{
		Type:     recoveryTokenType,
		Keyslots: []string{"1"},
		Owners: []sealedForOwner{{
			EphemeralPublicKeyB64: base64.StdEncoding.EncodeToString(epk),
			WrappedSecretB64:      base64.StdEncoding.EncodeToString(wrapped),
			NonceB64:              base64.StdEncoding.EncodeToString(nonce),
		}},
	}
	body, err := json.Marshal(slot)
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]interface{}
	if err := json.Unmarshal(body, &generic); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"aid", "owner_aid", "name", "email"} {
		if _, present := generic[forbidden]; present {
			t.Errorf("the header record carries %q, which publishes ownership on every copy "+
				"of the volume", forbidden)
		}
	}
	// LUKS requires the type and keyslots fields to accept the token at all.
	if generic["type"] != recoveryTokenType {
		t.Error("the record does not identify itself, so nothing could find it later")
	}
	if _, ok := generic["keyslots"]; !ok {
		t.Error("the record does not say which slot it opens")
	}
}

// No owner keys means no way back in, and that must be an error rather than a
// volume that silently has none.
func TestNoOwnerKeysIsRefused(t *testing.T) {
	if err := addOwnerRecovery("/dev/null", nil, make([]byte, 32)); err == nil {
		t.Fatal("a volume was given a recovery slot with nobody to recover it")
	}
}
