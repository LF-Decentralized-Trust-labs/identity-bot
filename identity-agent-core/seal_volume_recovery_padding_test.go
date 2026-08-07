package main

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/curve25519"

	"identity-agent-core/backup"
)

// What the padding is for: somebody holding a copy of the volume can read its
// header, and before this they could count the entries and learn how many
// signers the organisation has.

func ownerKeys(t *testing.T, n int) []string {
	t.Helper()
	keys := make([]string, n)
	for i := range keys {
		priv := make([]byte, 32)
		if _, err := rand.Read(priv); err != nil {
			t.Fatal(err)
		}
		pub, err := curve25519.X25519(priv, curve25519.Basepoint)
		if err != nil {
			t.Fatal(err)
		}
		keys[i] = base64.StdEncoding.EncodeToString(pub)
	}
	return keys
}

func sealTo(t *testing.T, keys []string) ownerRecoverySlot {
	t.Helper()
	secret := make([]byte, backup.BEKLen)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	slot := ownerRecoverySlot{Type: recoveryTokenType, Keyslots: []string{"1"}}
	for _, k := range keys {
		pub, _ := base64.StdEncoding.DecodeString(k)
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
	return slot
}

// The number of entries must not be the number of owners, for any number of
// owners. This is the whole point.
func TestTheEntryCountDoesNotRevealTheNumberOfOwners(t *testing.T) {
	seen := map[int][]int{}
	for owners := 1; owners <= 20; owners++ {
		slot := sealTo(t, ownerKeys(t, owners))
		if err := padOwners(&slot); err != nil {
			t.Fatalf("%d owners: %v", owners, err)
		}
		got := len(slot.Owners)
		if got%recoveryPadTo != 0 {
			t.Errorf("%d owners produced %d entries, which is not a multiple of %d",
				owners, got, recoveryPadTo)
		}
		if got < owners {
			t.Fatalf("%d owners produced only %d entries — an owner was dropped, so "+
				"somebody who could have recovered the volume now cannot", owners, got)
		}
		seen[got] = append(seen[got], owners)
	}
	// Every count must be ambiguous: more than one number of owners produces it.
	for count, owners := range seen {
		if len(owners) < 2 {
			t.Errorf("%d entries is produced by exactly one owner count (%v), so it "+
				"reveals that count", count, owners)
		}
	}
}

// A padding entry that is distinguishable from a real one is not padding. The
// fields are the only thing an observer has, so their shapes must match.
func TestPaddingEntriesAreShapedLikeRealOnes(t *testing.T) {
	slot := sealTo(t, ownerKeys(t, 1))
	realEntry := slot.Owners[0]
	if err := padOwners(&slot); err != nil {
		t.Fatal(err)
	}
	if len(slot.Owners) != recoveryPadTo {
		t.Fatalf("expected %d entries, got %d", recoveryPadTo, len(slot.Owners))
	}
	for i, e := range slot.Owners {
		for _, f := range []struct{ name, got, want string }{
			{"epk_b64", e.EphemeralPublicKeyB64, realEntry.EphemeralPublicKeyB64},
			{"wrapped_b64", e.WrappedSecretB64, realEntry.WrappedSecretB64},
			{"nonce_b64", e.NonceB64, realEntry.NonceB64},
		} {
			if len(f.got) != len(f.want) {
				t.Errorf("entry %d %s is %d chars and the real one is %d — the lengths "+
					"alone say which is which", i, f.name, len(f.got), len(f.want))
			}
			if f.got == "" {
				t.Errorf("entry %d has an empty %s", i, f.name)
			}
		}
	}
	// Every entry distinct: a repeated one would mark itself as filler.
	seen := map[string]bool{}
	for i, e := range slot.Owners {
		if seen[e.WrappedSecretB64] {
			t.Errorf("entry %d repeats an earlier sealed secret", i)
		}
		seen[e.WrappedSecretB64] = true
	}
}

// Padding appended after the real entries would be identifiable by position,
// which makes the count readable again. Over many runs the real entry must
// land in every position.
func TestTheRealEntryIsNotAlwaysFirst(t *testing.T) {
	positions := map[int]bool{}
	for run := 0; run < 60; run++ {
		slot := sealTo(t, ownerKeys(t, 1))
		mark := slot.Owners[0].WrappedSecretB64
		if err := padOwners(&slot); err != nil {
			t.Fatal(err)
		}
		for i, e := range slot.Owners {
			if e.WrappedSecretB64 == mark {
				positions[i] = true
			}
		}
	}
	if len(positions) < recoveryPadTo {
		t.Errorf("across 60 runs the real entry appeared in only %d of %d positions (%v) — "+
			"its position is predictable", len(positions), recoveryPadTo, positions)
	}
}
