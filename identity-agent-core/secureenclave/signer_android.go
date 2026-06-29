//go:build android

package secureenclave

// strongBoxSigner is an Android StrongBox stub for hosts that embed the Go core.
type strongBoxSigner struct{}

func newStrongBoxSigner() PlatformSigner {
	return &strongBoxSigner{}
}

func (s *strongBoxSigner) Available() bool { return false }
func (s *strongBoxSigner) Platform() string { return "strongbox" }
func (s *strongBoxSigner) Label() string  { return "Android StrongBox (stub)" }

func (s *strongBoxSigner) PublicKey() ([]byte, error) { return nil, ErrSignerUnavailable }
func (s *strongBoxSigner) Sign([]byte) ([]byte, error) { return nil, ErrSignerUnavailable }

// newDarwinSecureEnclaveSigner is called unconditionally from signer.go but only
// defined in darwin-tagged files. Stub it out for Android cross-compilation.
func newDarwinSecureEnclaveSigner() PlatformSigner { return nil }