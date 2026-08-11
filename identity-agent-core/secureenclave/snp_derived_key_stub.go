//go:build !linux

package secureenclave

import "fmt"

// DeriveKey is available only where there is a processor to ask.
//
// Refuses rather than returning something derived in software. A caller here is
// about to encrypt storage with it, and a key this process could compute is a
// key the machine's operator could compute too — which is the one thing the key
// exists to prevent.
func DeriveKey(purpose string) ([]byte, error) {
	return nil, fmt.Errorf("no SEV-SNP processor on this platform, so no key can be derived that its operator cannot also derive")
}
