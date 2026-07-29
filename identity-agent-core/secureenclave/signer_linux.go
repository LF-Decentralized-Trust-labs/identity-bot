//go:build linux && !android

package secureenclave

// Linux has no Apple Secure Enclave or Android StrongBox — these hardware-backed
// signers are unavailable here; NewPlatformSigner falls back to TPM/software.
func newDarwinSecureEnclaveSigner() PlatformSigner { return nil }
func newStrongBoxSigner() PlatformSigner           { return nil }

// tpmSigner is a TPM 2.0 stub; production wiring will bind to tpm2-tools or go-tpm.
type tpmSigner struct{}

func newTPMSigner() PlatformSigner {
	return &tpmSigner{}
}

func (s *tpmSigner) Available() bool  { return false }
func (s *tpmSigner) Platform() string { return "tpm2" }
func (s *tpmSigner) Label() string    { return "TPM 2.0 (stub)" }

func (s *tpmSigner) PublicKey() ([]byte, error)  { return nil, ErrSignerUnavailable }
func (s *tpmSigner) Sign([]byte) ([]byte, error) { return nil, ErrSignerUnavailable }
