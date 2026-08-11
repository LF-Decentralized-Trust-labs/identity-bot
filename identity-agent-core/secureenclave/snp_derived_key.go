package secureenclave

import (
	"golang.org/x/crypto/hkdf"

	"crypto/sha512"
	"io"
)

// DerivedKeySize is what the firmware returns, and what every key derived from
// it is cut to.
const DerivedKeySize = 32

// deriveForPurpose separates one firmware key into several.
//
// The firmware returns the same key for the same field selection, so every use
// that asked it directly would share one key. Then a weakness anywhere — a key
// recovered from a log, a scheme broken later — is a weakness everywhere, and
// two uses that should have been independent are not.
//
// HKDF with the purpose as info, so the derived keys are independent and each
// one is reproducible from the same firmware key on the next boot. That
// reproducibility is the whole point: nothing is stored, it is asked for again.
func deriveForPurpose(firmwareKey []byte, purpose string) []byte {
	out := make([]byte, DerivedKeySize)
	r := hkdf.New(sha512.New384, firmwareKey, nil, []byte("IA-SNP-DERIVE-V1\n"+purpose))
	if _, err := io.ReadFull(r, out); err != nil {
		// HKDF cannot fail for this output length; a failure here would mean
		// the standard library is broken, and returning a short key would be
		// worse than any panic.
		panic("deriving a key from the firmware key failed: " + err.Error())
	}
	return out
}
