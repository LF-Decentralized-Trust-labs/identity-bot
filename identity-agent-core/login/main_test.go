package login

import (
	"os"
	"testing"

	"identity-agent-core/secureenclave"
	"identity-agent-core/secureenclave/seedwraptest"
)

// These tests store the machine's own seed, which a production build only does
// where a wrapper works. The suite runs on machines of every kind, so it stands
// one that has one.
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
