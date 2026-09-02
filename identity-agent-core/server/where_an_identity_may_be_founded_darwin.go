//go:build darwin && !ios

package server

// macOS cannot prove its software to a stranger, and this is measured rather
// than assumed: the attestation service reports itself unsupported, and a build
// carrying the entitlement that would enable it is killed at launch.
//
// A Mac has a Secure Enclave and can hold a key perfectly well. That is a
// different question, and answering it instead is exactly how root identities
// came to be founded on Macs.
func foundingVerdictForThisPlatform() foundingVerdict {
	return foundingVerdict{
		Permitted: false,
		Platform:  "macos",
		Why:       cannotProveItsSoftware,
		Instead:   actForOneInstead,
	}
}
