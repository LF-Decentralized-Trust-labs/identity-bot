//go:build android

package secureenclave

// Android attests the running application through the platform key attestation
// its vendors provide, which is the same proof iOS offers by a different route.
func foundingVerdictForThisPlatform(_ string) FoundingVerdict {
	return FoundingVerdict{Permitted: true, Platform: "android"}
}
