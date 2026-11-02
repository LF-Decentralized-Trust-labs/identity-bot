// Package seedwraptest lets a test stand a machine that CAN protect a root seed
// (key hardware proven usable, and a seed wrapper that works) on any host, and
// the opposite. It is for tests only: its wrapper does not protect anything.
package seedwraptest

import (
	"testing"

	"identity-agent-core/secureenclave"
)

// Wrapper is a SeedWrapper that reverses the bytes. It is not security; it makes
// a wrapped envelope visibly different from a plain one.
type Wrapper struct{ Works bool }

func (w Wrapper) Available() bool { return w.Works }
func (Wrapper) Scheme() string    { return "test-wrap" }
func (Wrapper) Wrap(p []byte) ([]byte, error) {
	out := make([]byte, len(p))
	for i, b := range p {
		out[len(p)-1-i] = b
	}
	return out, nil
}
func (w Wrapper) Unwrap(b []byte) ([]byte, error) { return w.Wrap(b) }

// ThisMachineCanProtectASeed installs usable key hardware and a working wrapper.
func ThisMachineCanProtectASeed(t testing.TB) {
	t.Helper()
	r1 := secureenclave.UseCapabilityDetector(func() secureenclave.Capability {
		return secureenclave.Capability{Status: secureenclave.Usable, Kind: secureenclave.KindTPM2}
	})
	r2 := secureenclave.UseSeedWrapper(Wrapper{Works: true})
	t.Cleanup(func() { r2(); r1() })
}

// ThisMachineCannot installs a machine whose key protection is cap and whose
// wrapper works if wrapperWorks.
func ThisMachineCannot(t testing.TB, cap secureenclave.Capability, wrapperWorks bool) {
	t.Helper()
	r1 := secureenclave.UseCapabilityDetector(func() secureenclave.Capability { return cap })
	r2 := secureenclave.UseSeedWrapper(Wrapper{Works: wrapperWorks})
	t.Cleanup(func() { r2(); r1() })
}
