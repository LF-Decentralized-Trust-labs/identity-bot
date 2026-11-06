// Package seedwraptest lets a test stand a machine that CAN protect a root seed
// (key hardware proven usable, and a seed wrapper that works) on any host, and
// the opposite. It is for tests only: its wrapper does not protect anything.
package seedwraptest

import (
	"testing"

	"identity-agent-core/secureenclave"
)

// Wrapper is a SeedWrapper that XORs the bytes. It is not security; it makes a
// wrapped envelope visibly different from a plain one, even for a seed of one
// repeated byte (a reversal would leave that unchanged, and the core refuses a
// wrapper whose output contains the seed).
type Wrapper struct{ Works bool }

func (w Wrapper) Available() bool { return w.Works }
func (Wrapper) Scheme() string    { return "test-wrap" }
func (Wrapper) Wrap(p []byte) ([]byte, error) {
	out := make([]byte, len(p))
	for i, b := range p {
		out[i] = b ^ 0xA5
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
	r3 := thisPlatformMayFound()
	t.Cleanup(func() { r3(); r2(); r1() })
}

// thisPlatformMayFound stands a platform that can prove its software (a phone or
// a sealed machine), so a test about something else gets past the founding rule.
func thisPlatformMayFound() func() {
	return secureenclave.UseFoundingVerdict(func() secureenclave.FoundingVerdict {
		return secureenclave.FoundingVerdict{Permitted: true, Platform: "test"}
	})
}

// ThisMachineIsAProductionMac stands a production Apple-silicon Mac: the Secure
// Enclave is usable and the seed wrapper works, and it still cannot prove its
// software, so it may not hold a person's root seed.
func ThisMachineIsAProductionMac(t testing.TB) {
	t.Helper()
	r1 := secureenclave.UseCapabilityDetector(func() secureenclave.Capability {
		return secureenclave.Capability{Status: secureenclave.Usable, Kind: secureenclave.KindAppleEnclave}
	})
	r2 := secureenclave.UseSeedWrapper(Wrapper{Works: true})
	r3 := secureenclave.UseFoundingVerdict(func() secureenclave.FoundingVerdict {
		return secureenclave.FoundingVerdict{Permitted: false, Platform: "macos",
			Why: secureenclave.CannotProveItsSoftware, Instead: secureenclave.ActForOneInstead}
	})
	t.Cleanup(func() { r3(); r2(); r1() })
}

// ThisMachineIsAnIPhone stands an iPhone: usable Secure Enclave, a working
// wrapper, and a platform that attests its application.
func ThisMachineIsAnIPhone(t testing.TB) {
	t.Helper()
	ThisMachineCanProtectASeed(t)
}

// ThisMachineCannot installs a machine whose key protection is cap and whose
// wrapper works if wrapperWorks.
func ThisMachineCannot(t testing.TB, cap secureenclave.Capability, wrapperWorks bool) {
	t.Helper()
	r1 := secureenclave.UseCapabilityDetector(func() secureenclave.Capability { return cap })
	r2 := secureenclave.UseSeedWrapper(Wrapper{Works: wrapperWorks})
	t.Cleanup(func() { r2(); r1() })
}

// ThisMachineIsASealedHost stands the black box: a confidential guest (SEV-SNP)
// whose protection is the sealed volume, with no per-key hardware wrapper.
func ThisMachineIsASealedHost(t testing.TB) {
	t.Helper()
	r1 := secureenclave.UseCapabilityDetector(func() secureenclave.Capability {
		return secureenclave.Capability{Status: secureenclave.Usable, Kind: secureenclave.KindSEVSNP, Reason: "attested_execution"}
	})
	r2 := secureenclave.UseSeedWrapper(secureenclave.SealedVolumeSeedWrapperOn(func() error { return nil }))
	r4 := thisPlatformMayFound()
	t.Cleanup(func() { r4(); r2(); r1() })
}

// ThisMachineIsAPhoneWithNoWrapper stands an Android phone: its Keystore is
// usable and reported, and its app has registered no seed wrapper. A production
// build refuses to hold a root identity on it.
func ThisMachineIsAPhoneWithNoWrapper(t testing.TB) {
	t.Helper()
	r1 := secureenclave.UseCapabilityDetector(func() secureenclave.Capability {
		return secureenclave.Capability{Status: secureenclave.Usable, Kind: secureenclave.KindAndroidTEE}
	})
	r2 := secureenclave.UseSeedWrapper(nil)
	r3 := secureenclave.UseThisIsAPhone()
	r4 := thisPlatformMayFound()
	t.Cleanup(func() { r4(); r3(); r2(); r1() })
}
