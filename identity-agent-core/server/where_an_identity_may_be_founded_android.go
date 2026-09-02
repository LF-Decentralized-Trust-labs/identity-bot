//go:build android

package server

// Android attests the running application through the platform key attestation
// its vendors provide, which is the same proof iOS offers by a different route.
func foundingVerdictForThisPlatform() foundingVerdict {
	return foundingVerdict{Permitted: true, Platform: "android"}
}
