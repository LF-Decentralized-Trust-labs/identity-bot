//go:build linux && !android

package secureenclave

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
//
// A sealed guest whose encrypted volume did not come up is not a sealed machine
// for this purpose: the volume mount is nofail, so the data directory would be
// an ordinary folder on the root filesystem. So the directory being written must
// also be on dm-crypt — asked through dataDirIsOnADmCryptVolume, the same
// function the seed wrapper uses, not a copy of it.
func foundingVerdictForThisPlatform(dataDir string) FoundingVerdict {
	cap := detectCapability()
	if cap.Kind == KindSEVSNP && cap.Status == Usable {
		if err := dataDirIsOnADmCryptVolume(dataDir); err != nil {
			return FoundingVerdict{
				Permitted: false,
				Platform:  "amd_sev_snp",
				Why: "this sealed machine's encrypted volume is not mounted under the " +
					"data directory, so an identity founded here would sit on plain storage: " + err.Error(),
				Instead: ActForOneInstead,
			}
		}
		return FoundingVerdict{Permitted: true, Platform: "amd_sev_snp"}
	}
	// Present-but-unusable is refused with everything else, and deliberately.
	// Hardware that answered and will not hold a key cannot produce the report
	// either, and an identity founded on a promise that the hardware will start
	// working is one nobody can check today.
	return FoundingVerdict{
		Permitted: false,
		Platform:  "linux",
		Why:       CannotProveItsSoftware,
		Instead:   ActForOneInstead,
	}
}
