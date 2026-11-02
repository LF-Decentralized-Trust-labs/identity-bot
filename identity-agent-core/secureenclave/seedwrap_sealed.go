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

// sealedVolumeWrapper's storage check asks whether the data directory is on the
// encrypted volume. Nil means the real one, which reads the machine.
type sealedVolumeWrapper struct{ storage func() error }

// SealedVolumeSeedWrapper is the protection for a seed on a sealed machine.
// Exposed so a test (or an embedder) can stand a sealed host on any platform.
func SealedVolumeSeedWrapper() SeedWrapper { return sealedVolumeWrapper{} }

// SealedVolumeSeedWrapperOn is the same, with the question "is the data directory
// on the encrypted volume" answered by storage, so a test can stand a sealed
// host without a real mount.
func SealedVolumeSeedWrapperOn(storage func() error) SeedWrapper {
	return sealedVolumeWrapper{storage: storage}
}

func (w sealedVolumeWrapper) inAConfidentialGuest() bool {
	c := detectCapability()
	return c.Status == Usable && (c.Kind == KindSEVSNP || c.Kind == KindTDX)
}

// storageError is nil only when the data directory is on the encrypted volume.
func (w sealedVolumeWrapper) storageError() error {
	return w.storageErrorAt(agentDataDir())
}

// storageErrorAt asks about the directory actually being written.
func (w sealedVolumeWrapper) storageErrorAt(dataDir string) error {
	if w.storage != nil {
		return w.storage()
	}
	return dataDirIsOnADmCryptVolume(dataDir)
}

// wrapperWorksAt is whether w can protect a seed written to dataDir. For the
// sealed volume that depends on the directory; for every other wrapper it is
// Available.
func wrapperWorksAt(w SeedWrapper, dataDir string) bool {
	if w == nil {
		return false
	}
	if sv, ok := w.(sealedVolumeWrapper); ok {
		return sv.inAConfidentialGuest() && sv.storageErrorAt(dataDir) == nil
	}
	return w.Available()
}

// whyNotWrappedAt is whyNotWrapped for a seed written to dataDir.
func whyNotWrappedAt(dataDir string) string {
	if sv, ok := platformSeedWrapper().(sealedVolumeWrapper); ok && sv.inAConfidentialGuest() {
		if err := sv.storageErrorAt(dataDir); err != nil {
			return "the sealed volume is not mounted, so the data directory is not on encrypted storage: " + err.Error()
		}
	}
	return whyNotWrapped()
}

// Available is true only inside a confidential guest AND when the data
// directory is on the encrypted volume. The first alone checks the device and
// not the storage: the volume mount is nofail, so a machine whose volume did not
// come up would write to its plain root filesystem and still call the seed
// sealed.
func (w sealedVolumeWrapper) Available() bool {
	return w.inAConfidentialGuest() && w.storageError() == nil
}

// whyUnavailable says which half failed.
func (w sealedVolumeWrapper) whyUnavailable() string {
	if !w.inAConfidentialGuest() {
		return "this build has no hardware seed wrapper for this platform, and the " +
			"sealed-volume protection applies only inside a sealed machine"
	}
	return "the sealed volume is not mounted, so the data directory is not on encrypted storage: " +
		w.storageError().Error()
}

func (sealedVolumeWrapper) Scheme() string { return SealedVolumeScheme }
func (sealedVolumeWrapper) Wrap(p []byte) ([]byte, error) {
	return append([]byte(nil), p...), nil
}
func (sealedVolumeWrapper) Unwrap(b []byte) ([]byte, error) {
	return append([]byte(nil), b...), nil
}
