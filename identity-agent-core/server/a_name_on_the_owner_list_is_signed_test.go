package server

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"identity-agent-core/asset"
	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
)

func vouchRow(t *testing.T, seed []byte, aid, org, signedName, shownName string) asset.Employee {
	t.Helper()
	payload, _ := json.Marshal(map[string]string{
		"v": "VOUCH1", "action": "sign_org", "signer_aid": aid, "org_aid": org, "name": signedName})
	sig, err := login.SignAsk(payload, seed)
	if err != nil {
		t.Fatal(err)
	}
	return asset.Employee{PairwiseAID: aid, Name: shownName, IsSigner: true, Status: "active",
		VouchSig: sig, VouchPayload: string(payload)}
}

func TestAnOwnerIsNamedOnlyByAName(t *testing.T) {
	seed := make([]byte, 32)
	seed[0] = 7
	key := iacrypto.VerkeyQB64(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	otherSeed := make([]byte, 32)
	otherSeed[0] = 9

	// Signed by the owner: named.
	good := []asset.Employee{vouchRow(t, seed, "EOWNER", "EORG", "Ada Lovelace", "Ada Lovelace")}
	if got := signedNameOf("EOWNER", "EORG", key, good); got != "Ada Lovelace" {
		t.Fatalf("a name the owner signed was not shown: %q", got)
	}

	// The roster name edited after signing: the case that would have shown a
	// forged name before this change.
	edited := []asset.Employee{vouchRow(t, seed, "EOWNER", "EORG", "Ada Lovelace", "Mallory")}
	if got := signedNameOf("EOWNER", "EORG", key, edited); got != "" {
		t.Errorf("an unsigned roster name was shown: %q", got)
	}

	// Signed by some other key.
	forged := []asset.Employee{vouchRow(t, otherSeed, "EOWNER", "EORG", "Mallory", "Mallory")}
	if got := signedNameOf("EOWNER", "EORG", key, forged); got != "" {
		t.Errorf("a name signed by another key was shown: %q", got)
	}

	// A vouch for a different organisation does not name this one's owner.
	elsewhere := []asset.Employee{vouchRow(t, seed, "EOWNER", "EOTHER", "Ada Lovelace", "Ada Lovelace")}
	if got := signedNameOf("EOWNER", "EORG", key, elsewhere); got != "" {
		t.Errorf("a vouch for another organisation named this owner: %q", got)
	}

	// An old row with a name and no signed payload.
	old := []asset.Employee{{PairwiseAID: "EOWNER", Name: "Ada Lovelace", IsSigner: true, Status: "active", VouchSig: "x"}}
	if got := signedNameOf("EOWNER", "EORG", key, old); got != "" {
		t.Errorf("a roster name with no signed payload was shown: %q", got)
	}
}
