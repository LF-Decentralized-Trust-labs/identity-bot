//go:build windows

package server

// Windows offers no mechanism by which an ordinary user-mode application can
// prove to a third party what software it is. A TPM can hold a key and a
// virtualisation-based enclave can produce a report, and neither is something a
// peer can independently verify for an application distributed to the public.
func foundingVerdictForThisPlatform() foundingVerdict {
	return foundingVerdict{
		Permitted: false,
		Platform:  "windows",
		Why:       cannotProveItsSoftware,
		Instead:   actForOneInstead,
	}
}
