//go:build ios

package server

// iOS attests the running application: the vendor signs a statement about which
// build is asking, which is exactly the proof an identity's keys need to be
// worth relying on.
//
// GOOS=ios also satisfies the `darwin` build tag, so without this file the
// macOS answer would run here and refuse an iPhone.
func foundingVerdictForThisPlatform() foundingVerdict {
	return foundingVerdict{Permitted: true, Platform: "ios"}
}
