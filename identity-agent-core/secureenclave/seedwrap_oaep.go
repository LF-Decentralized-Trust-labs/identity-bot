package secureenclave

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"math/big"
)

// RSA-OAEP with SHA-256 for the label hash and SHA-1 for the mask function,
// which is what the Android Keystore does for "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
// on every API level before 34, whatever the Java spec says. StrongBox is
// guaranteed only SHA-256 as a digest, so SHA-256 is the choice that works in
// StrongBox as well as in the TEE.
//
// Go's crypto/rsa masks with the same hash it labels with until Go 1.26, which
// is newer than this module's go.mod, so the encoding (RFC 8017 7.1.1) is done
// here and only the public-key exponentiation, which has no secret in it, is
// left to math/big. It is checked against OpenSSL in the tests, and is used
// only to seal a random data key.
//
// When go.mod moves to Go 1.26 or later, replace oaepEncryptSHA256MGF1SHA1 with
// rsa.EncryptOAEPWithOptions (Hash SHA-256, MGFHash SHA-1) and delete this file;
// the OpenSSL test vector in seedwrap_oaep_test.go stays as the check.

const oaepHashLen = sha256.Size

func mgf1SHA1(seed []byte, n int) []byte {
	out := make([]byte, 0, n+sha1.Size)
	for c := uint32(0); len(out) < n; c++ {
		h := sha1.New()
		h.Write(seed)
		h.Write([]byte{byte(c >> 24), byte(c >> 16), byte(c >> 8), byte(c)})
		out = h.Sum(out)
	}
	return out[:n]
}

func xorInto(dst, mask []byte) {
	for i := range dst {
		dst[i] ^= mask[i]
	}
}

func oaepEncryptSHA256MGF1SHA1(pub *rsa.PublicKey, msg []byte) ([]byte, error) {
	k := (pub.N.BitLen() + 7) / 8
	if len(msg) > k-2*oaepHashLen-2 {
		return nil, errors.New("message too long for RSA-OAEP")
	}
	lHash := sha256.Sum256(nil)
	em := make([]byte, k)
	seed := em[1 : 1+oaepHashLen]
	db := em[1+oaepHashLen:]
	copy(db, lHash[:])
	db[len(db)-len(msg)-1] = 1
	copy(db[len(db)-len(msg):], msg)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	xorInto(db, mgf1SHA1(seed, len(db)))
	xorInto(seed, mgf1SHA1(db, oaepHashLen))
	c := new(big.Int).Exp(new(big.Int).SetBytes(em), big.NewInt(int64(pub.E)), pub.N)
	return c.FillBytes(make([]byte, k)), nil
}
