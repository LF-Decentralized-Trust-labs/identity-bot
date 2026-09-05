//go:build linux && !android

package secureenclave

// Linux has no Apple Secure Enclave or Android StrongBox — these hardware-backed
// signers are unavailable here; NewPlatformSigner falls back to TPM/software.
func newDarwinSecureEnclaveSigner(dataDir string) PlatformSigner { return nil }
func newStrongBoxSigner() PlatformSigner                         { return nil }

// tpmSigner refuses on purpose. This is not an unfinished implementation.
//
// A Linux DESKTOP is not a supported place to run this software, decided
// 2026-09-03. The reasoning, so nobody has to reconstruct it: desktop Linux is
// roughly four percent of desktops, no user or commitment depends on it, and the
// per-platform work does not carry over -- macOS needed Swift and CryptoKit,
// Windows needed NCrypt and its own key blob, and Linux would need go-tpm plus a
// package that grants the tss group membership the TPM device requires. Three
// implementations behind one interface, sharing only the interface.
//
// THE SEALED BLACK BOX IS ALSO LINUX AND IS ENTIRELY UNAFFECTED. It never comes
// here: DetectCapability checks for a confidential guest first and answers from
// the SEV-SNP processor, and the key that protects its storage comes from
// DeriveKey rather than from any TPM. Removing desktop support takes nothing
// away from it.
//
// So the refusal above is the supported behaviour, and it is honest -- a Linux
// desktop is told it cannot act for an identity, rather than being allowed to
// arrive somewhere that then fails. If demand appears, the work is a go-tpm
// signer plus the seed wrapper, together, and packaging is the larger half.
type tpmSigner struct{}

func newTPMSigner() PlatformSigner {
	return &tpmSigner{}
}

func (s *tpmSigner) Available() bool  { return false }
func (s *tpmSigner) Platform() string { return "tpm2" }
func (s *tpmSigner) Label() string    { return "TPM 2.0 (stub)" }

func (s *tpmSigner) PublicKey() ([]byte, error)  { return nil, ErrSignerUnavailable }
func (s *tpmSigner) Sign([]byte) ([]byte, error) { return nil, ErrSignerUnavailable }
