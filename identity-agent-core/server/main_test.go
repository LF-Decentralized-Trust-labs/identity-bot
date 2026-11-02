package server

import (
	"os"
	"testing"

	"identity-agent-core/secureenclave"
	"identity-agent-core/secureenclave/seedwraptest"
)

// The tests here install root seeds, which a machine only
// accepts if it can protect one. The suite runs on machines of every kind, so it
// stands one that can; tests of the refusal stand one that cannot.
func TestMain(m *testing.M) {
	restoreCap := secureenclave.UseCapabilityDetector(func() secureenclave.Capability {
		return secureenclave.Capability{Status: secureenclave.Usable, Kind: secureenclave.KindTPM2}
	})
	restoreWrap := secureenclave.UseSeedWrapper(seedwraptest.Wrapper{Works: true})
	code := m.Run()
	restoreWrap()
	restoreCap()
	os.Exit(code)
}
