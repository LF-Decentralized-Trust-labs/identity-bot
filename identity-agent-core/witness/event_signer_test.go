package witness

import (
	"crypto/ed25519"

	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
)

// eventSignerFor is the host's signer of event receipts for a witness key, as
// the agent supplies it: an indexed signature over the event's bytes. A witness
// that is not in the list is indexed 0, which the real signer refuses and these
// tests, whose events do not always designate their witness, do not care about.
func eventSignerFor(seed []byte) func([]byte, []string) (string, string, error) {
	aid := iacrypto.NonTransferableAIDQB64(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	return func(raw []byte, designated []string) (string, string, error) {
		at := drivers.WitnessPosition(designated, aid)
		if at < 0 {
			at = 0
		}
		sig, err := drivers.SignEventReceipt(raw, seed, at)
		return aid, sig, err
	}
}
