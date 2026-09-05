//go:build windows

package secureenclave

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// What the provider hands back is checked, not trusted.
//
// This needs no TPM, which is the point: the parsing was reachable only through
// a real key handle, so nothing exercised it and the one check that mattered was
// missing. Every case below is a blob a provider could return.
func TestWhatAKeyBlobMustSayBeforeItIsAKey(t *testing.T) {
	blob := func(magic uint32, size uint32, coords int) []byte {
		b := make([]byte, 8+coords)
		binary.LittleEndian.PutUint32(b[0:4], magic)
		binary.LittleEndian.PutUint32(b[4:8], size)
		for i := range b[8:] {
			b[8+i] = byte(i + 1)
		}
		return b
	}

	t.Run("a P-256 public blob becomes an uncompressed point", func(t *testing.T) {
		got, err := pointFromECCBlob(blob(bcryptECDSAPublicP256Magic, 32, 64))
		if err != nil {
			t.Fatalf("a well-formed P-256 blob must parse: %v", err)
		}
		if len(got) != 65 {
			t.Fatalf("an uncompressed P-256 point is 65 bytes, got %d", len(got))
		}
		if got[0] != 0x04 {
			t.Fatalf("an uncompressed point starts 0x04, got %#x", got[0])
		}
		// X then Y, in the order the blob carried them. A transposition here
		// would still produce a valid-looking point and a key nobody can verify.
		if !bytes.Equal(got[1:], blob(bcryptECDSAPublicP256Magic, 32, 64)[8:]) {
			t.Fatal("the coordinates were not carried across unchanged")
		}
	})

	t.Run("a curve that is not P-256 is refused", func(t *testing.T) {
		// THE CASE THE SIZE CHECK CANNOT CATCH, and the reason the magic is read.
		// BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC is what a blob carries for a NIST
		// curve other than the three named ones, and a 32-byte coordinate size
		// does not narrow it to P-256. Accepted, it would be assembled into a
		// point off the curve and surface far away, as a signature that never
		// verifies against a key that looked perfectly well-formed.
		const genericECDSAMagic = 0x50444345 // "ECDP"
		if _, err := pointFromECCBlob(blob(genericECDSAMagic, 32, 64)); err == nil {
			t.Fatal("a blob that does not say P-256 must be refused, not assembled into a point")
		}
	})

	t.Run("the same curve for a different algorithm is refused", func(t *testing.T) {
		// BCRYPT_ECDH_PUBLIC_P256_MAGIC. Same curve, same coordinates, agreed
		// for key exchange rather than signing. Using one where the other is
		// meant is a misuse worth refusing at the door, and the size check
		// cannot see it either.
		const ecdhP256Magic = 0x314B4345 // "ECK1"
		if _, err := pointFromECCBlob(blob(ecdhP256Magic, 32, 64)); err == nil {
			t.Fatal("a key-agreement blob must not be accepted as a signing key")
		}
	})

	t.Run("a private key blob is not accepted as a public one", func(t *testing.T) {
		// BCRYPT_ECDSA_PRIVATE_P256_MAGIC. Distinct value, same shape.
		const privateMagic = 0x32534345
		if _, err := pointFromECCBlob(blob(privateMagic, 32, 96)); err == nil {
			t.Fatal("a private key blob must not be read as a public key")
		}
	})

	t.Run("a blob too short to describe a key says so", func(t *testing.T) {
		for _, b := range [][]byte{nil, {}, {1, 2, 3}, make([]byte, 7)} {
			if _, err := pointFromECCBlob(b); err == nil {
				t.Fatalf("a %d-byte blob must be refused", len(b))
			}
		}
	})

	t.Run("a blob whose coordinates are cut short is refused", func(t *testing.T) {
		// Claims 32-byte coordinates and carries one and a half. Truncating the
		// read would produce a point built partly from whatever followed.
		if _, err := pointFromECCBlob(blob(bcryptECDSAPublicP256Magic, 32, 48)); err == nil {
			t.Fatal("a blob shorter than the size it declares must be refused")
		}
	})

	t.Run("only the provider's no-key-yet answers create a key", func(t *testing.T) {
		// THE HALF THAT HAD NO TEST. exportPublic was split out so it could be
		// checked; the classification that decides whether to MINT A NEW KEY was
		// left inline, and it is the one with consequences — a machine that
		// mints a new key has a new identity, and every grant made to it is void.
		for _, c := range []struct {
			code uint32
			name string
			want bool
		}{
			{0x80090016, "NTE_BAD_KEYSET", true},
			{0x8009000D, "NTE_NO_KEY", true},
			{0x80090011, "NTE_NOT_FOUND", true},

			// NOT first-run answers. NTE_PERM is a key that exists and cannot be
			// opened; treating it as absence would mint a second key alongside
			// the real one and silently change who this machine is.
			{0x80090010, "NTE_PERM", false},
			{0x8009000F, "NTE_EXISTS", false},
			{0x80090029, "NTE_NOT_SUPPORTED", false},
			{0, "success", false},
		} {
			if got := meansNoKeyYet(c.code); got != c.want {
				t.Errorf("%s (%#x): treated as no-key-yet=%v, want %v", c.name, c.code, got, c.want)
			}
		}
	})
}
