package lockgate

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"

	"identity-agent-core/authprovider"
	"identity-agent-core/login"
)

// The exact text a person's root device signs to let ONE desktop log-in happen
// (ADR-074, "The unlock voucher"), with a signature over it from a fixed seed.
// Published so another implementation of the root device, or of an Identity
// Agent, can check itself against it. If this fails, the wire format changed:
// that is a new statement name (IA-UNLOCK-VOUCHER-V2), never an edit.
func TestAnUnlockVoucherStatementHasOneFixedForm(t *testing.T) {
	at := time.Date(2026, 11, 11, 9, 30, 0, 0, time.UTC)
	got := authprovider.CanonicalUnlockVoucherStatement("EAgent", "BController", authprovider.LevelAuthenticated, at, 80, "0123456789abcdef0123")
	want := "IA-UNLOCK-VOUCHER-V1\nEAgent\nBController\nauthenticated\n2026-11-11T09:30:00Z\n80\n0123456789abcdef0123"
	if got != want {
		t.Fatalf("statement = %q, want %q", got, want)
	}

	// A statement made to vouch for a request is never a log-in voucher.
	request := authprovider.CanonicalAuthLevelStatement("EAgent", "BController", authprovider.LevelAuthenticated, at, 80)
	if request == got[:len(request)] {
		t.Fatal("the request statement and the voucher share a first line")
	}

	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	sig, err := login.SignString(got, seed)
	if err != nil {
		t.Fatal(err)
	}
	const wantSig = "0BB4IoJbFHyiLBuHxVETVS81OvwMc_7FNxSmsraaYotvenZaI16UUzzMiiskhd114Qb5-R3auaTWSfy0A-zAUl0F"
	if sig != wantSig {
		t.Fatalf("signature = %q, want %q", sig, wantSig)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if ok, err := login.VerifyString(got, sig, pub); err != nil || !ok {
		t.Fatalf("the pinned signature does not verify: %v", err)
	}
	t.Log("public key", base64.StdEncoding.EncodeToString(pub))
}
