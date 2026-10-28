// Package fixedkeys makes a DIDComm keyset from published seeds, so the
// vectors that need one — a body's sealing keys, the keys that countersign a
// conversation — are bytes anybody can reproduce rather than keys minted at
// random each time the vectors are written.
//
// Each key comes from its own seed, by the standard derivation for its
// algorithm: an Ed25519 key from its 32-byte seed (RFC 8032), an ML-DSA-65 key
// from its 32-byte seed and an ML-KEM-768 key from its 64-byte seed (FIPS 204
// and 203 key generation), and an X25519 key whose 32-byte private key is the
// seed (RFC 7748).
package fixedkeys

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"identity-agent-core/didcomm"
	"identity-agent-core/internal/vectorseeds"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"golang.org/x/crypto/curve25519"
)

// KeySet is the keyset these seeds make, for aid.
func KeySet(aid string, s vectorseeds.Seeds) (*didcomm.KeySet, error) {
	ed, err := seed(s.Ed25519, ed25519.SeedSize, "ed25519")
	if err != nil {
		return nil, err
	}
	dsa, err := seed(s.MLDSA65, mldsa65.SeedSize, "mldsa65")
	if err != nil {
		return nil, err
	}
	x, err := seed(s.X25519, 32, "x25519")
	if err != nil {
		return nil, err
	}
	kem, err := seed(s.MLKEM768, mlkem768.KeySeedSize, "mlkem768")
	if err != nil {
		return nil, err
	}
	ks := &didcomm.KeySet{AID: aid}
	ks.EdPriv = ed25519.NewKeyFromSeed(ed)
	ks.EdPub = ks.EdPriv.Public().(ed25519.PublicKey)
	ks.DsaPub, ks.DsaPriv = mldsa65.NewKeyFromSeed((*[mldsa65.SeedSize]byte)(dsa))
	ks.KemPub, ks.KemPriv = mlkem768.NewKeyFromSeed(kem)
	copy(ks.XPriv[:], x)
	pub, err := curve25519.X25519(ks.XPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(ks.XPub[:], pub)
	return ks, nil
}

func seed(h string, size int, name string) ([]byte, error) {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != size {
		return nil, fmt.Errorf("the %s seed must be %d bytes, hex", name, size)
	}
	return b, nil
}
