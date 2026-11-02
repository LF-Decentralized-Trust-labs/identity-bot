package secureenclave

// THE SEALED MACHINE'S PROTECTION: THE VOLUME, NOT A KEY.
//
// An AMD SEV-SNP (or Intel TDX) sealed machine has no TPM and no per-key
// hardware wrapper, and does not need one: its data volume is encrypted under a
// key only that measured machine can derive (volume/seal.go), so a file on it
// cannot be read anywhere else. The root identity's seed therefore lives on the
// volume as it is, and the envelope says so under the scheme below — truthfully
// "protected by the sealed volume", never "unwrapped".
//
// Available is the proof that this process is inside the sealed machine: the
// confidential-guest device node, which the kernel registers only for a real
// guest (see detectConfidentialGuest). On any other host it is false, so the
// scheme can never be claimed by a machine that is not sealed — a desktop Linux
// box with a TPM does not get "sealed-volume" written into its envelope.
//
// Wrap and Unwrap are the identity function on purpose. Anything stronger would
// pretend the file is protected by something other than the volume.

// SealedVolumeScheme is the envelope scheme recorded for a seed held on a
// sealed machine's volume.
const SealedVolumeScheme = "sealed-volume"

type sealedVolumeWrapper struct{}

// SealedVolumeSeedWrapper is the protection for a seed on a sealed machine.
// Exposed so a test (or an embedder) can stand a sealed host on any platform.
func SealedVolumeSeedWrapper() SeedWrapper { return sealedVolumeWrapper{} }

func (sealedVolumeWrapper) Available() bool {
	c := detectCapability()
	return c.Status == Usable && (c.Kind == KindSEVSNP || c.Kind == KindTDX)
}
func (sealedVolumeWrapper) Scheme() string { return SealedVolumeScheme }
func (sealedVolumeWrapper) Wrap(p []byte) ([]byte, error) {
	return append([]byte(nil), p...), nil
}
func (sealedVolumeWrapper) Unwrap(b []byte) ([]byte, error) {
	return append([]byte(nil), b...), nil
}
