//go:build linux && !android

package server

import "identity-agent-core/secureenclave"

// Linux is the one platform where the answer is not a property of the operating
// system, so it is asked at runtime rather than decided at build time.
//
// A sealed machine — an AMD SEV-SNP guest — attests the whole guest, image and
// all, which is a stronger proof than either mobile platform offers: it covers
// the software, not just the application asking. An ordinary Linux desktop
// running the same binary can prove nothing of the sort, and the two are the
// same GOOS.
//
// Asked through the same detection everything else uses, so a machine cannot be
// judged capable here and incapable one function away.
func foundingVerdictForThisPlatform() foundingVerdict {
	cap := secureenclave.DetectCapability()
	if cap.Kind == secureenclave.KindSEVSNP && cap.Status == secureenclave.Usable {
		return foundingVerdict{Permitted: true, Platform: "amd_sev_snp"}
	}
	// Present-but-unusable is refused with everything else, and deliberately.
	// Hardware that answered and will not hold a key cannot produce the report
	// either, and an identity founded on a promise that the hardware will start
	// working is one nobody can check today.
	return foundingVerdict{
		Permitted: false,
		Platform:  "linux",
		Why:       cannotProveItsSoftware,
		Instead:   actForOneInstead,
	}
}
