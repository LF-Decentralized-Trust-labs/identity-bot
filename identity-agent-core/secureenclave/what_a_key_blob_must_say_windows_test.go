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

	t.Run("another curve with the same coordinate size is refused", func(t *testing.T) {
		// THE CASE THE SIZE CHECK CANNOT CATCH, and the reason the magic is read.
		// Several curves have 32-byte coordinates, so this blob passes every
		// other test in the function and is not a P-256 key. Accepted, it would
		// be assembled into a point off the curve and surface far away, as a
		// signature that never verifies.
		const someOtherCurveMagic = 0x314B4345
		if _, err := pointFromECCBlob(blob(someOtherCurveMagic, 32, 64)); err == nil {
			t.Fatal("a blob for a different curve must be refused, not assembled into a point")
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

	t.Run("the three ways of saying there is no key yet are distinct values", func(t *testing.T) {
		// Guards against a copy-paste that makes two of them equal, which would
		// silently narrow first-run handling back to what it was.
		seen := map[int]string{nteBadKeyset: "NTE_BAD_KEYSET", nteNoKey: "NTE_NO_KEY", nteNotFound: "NTE_NOT_FOUND"}
		if len(seen) != 3 {
			t.Fatalf("expected three distinct not-found codes, got %d", len(seen))
		}
	})
}
