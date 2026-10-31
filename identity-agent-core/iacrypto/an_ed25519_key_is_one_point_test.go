package iacrypto

import (
	"crypto/ed25519"
	"encoding/hex"
	"math/big"
	"testing"

	"filippo.io/edwards25519"
)

// The encodings of the eight points of small order, each of which Go's
// cofactorless verifier accepts some signature under for every message.
var smallOrderKeys = []string{
	"0100000000000000000000000000000000000000000000000000000000000000", // the identity
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // order 2
	"0000000000000000000000000000000000000000000000000000000000000000", // order 4
	"0000000000000000000000000000000000000000000000000000000000000080", // order 4
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", // order 8
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", // order 8
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", // order 8
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", // order 8
}

// nonCanonicalEd25519Key is a second encoding of a point of large order: y
// written as y + p, which an encoding reader that does not insist on y < p
// reads as the same key.
func nonCanonicalEd25519Key(t *testing.T) []byte {
	t.Helper()
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	for y := int64(2); y < 19; y++ {
		le := new(big.Int).Add(p, big.NewInt(y)).FillBytes(make([]byte, 32))
		for i, j := 0, 31; i < j; i, j = i+1, j-1 {
			le[i], le[j] = le[j], le[i]
		}
		pt, err := new(edwards25519.Point).SetBytes(le)
		if err != nil || new(edwards25519.Point).MultByCofactor(pt).Equal(edwards25519.NewIdentityPoint()) == 1 {
			continue
		}
		return le
	}
	t.Fatal("no y below 19 is a point of large order")
	return nil
}

func TestAnEd25519KeyIsOnePoint(t *testing.T) {
	good := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	if err := CheckEd25519PublicKey(good); err != nil {
		t.Fatalf("a real key was refused: %v", err)
	}
	for _, h := range smallOrderKeys {
		raw, _ := hex.DecodeString(h)
		if err := CheckEd25519PublicKey(raw); err == nil {
			t.Errorf("the small-order key %s was accepted", h)
		}
		if _, err := KeyFromVerkeyQB64(VerkeyQB64(raw)); err == nil {
			t.Errorf("the small-order key %s was read in qb64", h)
		}
	}
	nc := nonCanonicalEd25519Key(t)
	if err := CheckEd25519PublicKey(nc); err == nil {
		t.Errorf("the non-canonical encoding %x was accepted", nc)
	}
	if _, err := KeyFromNonTransferableAID(NonTransferableAIDQB64(nc)); err == nil {
		t.Errorf("the non-canonical encoding %x was read as an identifier", nc)
	}
	notAPoint, _ := hex.DecodeString("0200000000000000000000000000000000000000000000000000000000000000")
	if err := CheckEd25519PublicKey(notAPoint); err == nil {
		t.Error("an encoding of no point was accepted")
	}
	if _, _, err := DecodeEd25519Key(hex.EncodeToString(smallOrderKeysRaw(t)[0]), true); err == nil {
		t.Error("a small-order key in hex was read")
	}
}

func smallOrderKeysRaw(t *testing.T) [][]byte {
	t.Helper()
	out := make([][]byte, len(smallOrderKeys))
	for i, h := range smallOrderKeys {
		out[i], _ = hex.DecodeString(h)
	}
	return out
}
