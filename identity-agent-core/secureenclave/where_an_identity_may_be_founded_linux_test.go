//go:build linux && !android

package secureenclave

import "testing"

// A sealed guest whose encrypted volume is not under the data directory may not
// found an identity; with the volume there it may. Same check the seed path uses.
func TestASealedGuestMayFoundOnlyWithItsVolumeUnderTheDataDirectory(t *testing.T) {
	r := UseCapabilityDetector(func() Capability { return Capability{Status: Usable, Kind: KindSEVSNP} })
	defer r()

	fakeMachine(t, rootOnly, nil)
	v := foundingVerdictForThisPlatform("/var/lib/identity-agent")
	if v.Permitted || v.Why == "" || v.Instead == "" {
		t.Fatalf("a sealed guest without its volume founded: %+v", v)
	}

	fakeMachine(t, withVolume, map[string]string{"253:0": "CRYPT-LUKS2-x"})
	if v := foundingVerdictForThisPlatform("/var/lib/identity-agent"); !v.Permitted || v.Platform != "amd_sev_snp" {
		t.Fatalf("a sealed guest with its volume was refused: %+v", v)
	}
	if v := foundingVerdictForThisPlatform("./data"); v.Permitted {
		t.Fatalf("a data directory off the volume was permitted: %+v", v)
	}
}
