package secureenclave

// tpmEndorsementID returns a stable identifier for this machine's TPM 2.0
// endorsement key, or an empty string and a reason.
//
// NOT IMPLEMENTED. It returns an explained absence on every platform, which is
// the honest answer and deliberately not a placeholder: a hardware identity
// that is fabricated when the hardware is missing would be indistinguishable
// from a real one at every call site that matters.
//
// What implementing it requires, so the next person does not have to work it
// out — the endorsement key alone is not enough:
//
//   - Read the EK public area, and the EK certificate the manufacturer issued.
//     The certificate is what makes the key mean "a real TPM" rather than "a
//     key some software generated".
//   - Create a restricted signing attestation key, and bind it to that EK with
//     TPM2_ActivateCredential. Without this step the two are unrelated: an
//     attacker can present a genuine EK and sign with a key that is not in the
//     same TPM.
//   - Check the attestation key's attributes — restricted, sign, fixedTPM,
//     fixedParent. A NON-restricted signing key will sign attacker-chosen bytes
//     shaped like a quote, producing a forgery from genuine hardware.
//
// The identifier itself should be a hash of the EK public area rather than the
// raw key, so it is fixed-length, and privacy-preserving where the same code
// runs on a user's own device.
//
// Note this is the identifier a HOST needs. A sealed guest uses CHIP_ID from an
// SEV-SNP report instead, because only a guest can obtain one — a machine that
// runs guests cannot attest itself that way, which is exactly why a host needs
// a TPM and a guest does not.
func tpmEndorsementID() (id string, why string) {
	return "", "TPM 2.0 endorsement identity is not implemented on this build"
}
