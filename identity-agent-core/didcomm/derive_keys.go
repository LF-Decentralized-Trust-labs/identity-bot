package didcomm

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Messaging keys that come back after a restore.
//
// GenerateKeySet draws from the system random source, so the four keys an
// identity is reached on exist in exactly one place: that device. Restore from
// the recovery phrase and the KERI identity returns while the messaging keys do
// not — and because the identifier now commits to them, the restored identity
// advertises keys nobody holds the private half of. It can prove who it is and
// can never again be sent anything, permanently, since no later event can
// withdraw what an inception committed to.
//
// A recovery phrase that restores an identity into a state where it cannot
// receive is not a recovery phrase. So the keys are derived from the same root
// seed as everything else the agent holds, at their own branch of it.
//
// Every algorithm here defines keygen from a seed, so this is derivation rather
// than a scheme of our own: the same seed yields the same four keys on any
// implementation of them.

// Distinct labels per key.
//
// One derived secret must never be usable as another. HKDF with a different
// info string per key means learning one reveals nothing about the rest, and it
// costs nothing to separate them at the point they are made rather than hoping
// nothing ever mixes them up.
const (
	infoEd25519 = "IA-MSG-ED25519-V1"
	infoMLDSA65 = "IA-MSG-MLDSA65-V1"
	infoX25519  = "IA-MSG-X25519-V1"
	infoMLKEM   = "IA-MSG-MLKEM768-V1"
)

// DeriveKeySet reproduces an identity's four messaging keys from a seed.
//
// Deterministic: the same seed always yields the same keyset, which is the
// entire point — it is what makes a restored agent reachable at the keys its
// identifier already committed to.
func DeriveKeySet(aid string, seed []byte) (*KeySet, error) {
	if len(seed) < 32 {
		return nil, fmt.Errorf("a messaging keyset needs at least 32 bytes of seed, got %d", len(seed))
	}

	edSeed, err := expand(seed, infoEd25519, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	edPriv := ed25519.NewKeyFromSeed(edSeed)

	dsaSeedBytes, err := expand(seed, infoMLDSA65, mldsa65.SeedSize)
	if err != nil {
		return nil, err
	}
	var dsaSeed [mldsa65.SeedSize]byte
	copy(dsaSeed[:], dsaSeedBytes)
	dsaPub, dsaPriv := mldsa65.NewKeyFromSeed(&dsaSeed)

	kemSeed, err := expand(seed, infoMLKEM, mlkem768.KeySeedSize)
	if err != nil {
		return nil, err
	}
	kemPub, kemPriv := mlkem768.NewKeyFromSeed(kemSeed)

	ks := &KeySet{
		AID:     aid,
		EdPub:   edPriv.Public().(ed25519.PublicKey),
		EdPriv:  edPriv,
		DsaPub:  dsaPub,
		DsaPriv: dsaPriv,
		KemPub:  kemPub,
		KemPriv: kemPriv,
	}

	xSeed, err := expand(seed, infoX25519, 32)
	if err != nil {
		return nil, err
	}
	copy(ks.XPriv[:], xSeed)
	pub, err := curve25519.X25519(ks.XPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("x25519 derive: %w", err)
	}
	copy(ks.XPub[:], pub)
	return ks, nil
}

func expand(seed []byte, info string, n int) ([]byte, error) {
	out := make([]byte, n)
	// No salt: the seed is already a derived secret with its own branch, and a
	// salt would have to be stored and kept alongside it to reproduce anything.
	if _, err := io.ReadFull(hkdf.New(sha256.New, seed, nil, []byte(info)), out); err != nil {
		return nil, fmt.Errorf("derive %s: %w", info, err)
	}
	return out, nil
}
