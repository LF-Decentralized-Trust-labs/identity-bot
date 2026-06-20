package witness

import "identity-agent-core/store"

// IsBackendEligible returns true for always-on desktop or hosted (M02) backends.
func IsBackendEligible(backendType string) bool {
	switch backendType {
	case BackendDesktop, BackendHosted, BackendCommercial:
		return true
	default:
		return false
	}
}

// IsContactWitnessEligible applies M11 enrollment rules.
func IsContactWitnessEligible(c store.ContactRecord) bool {
	if c.Status != "accepted" {
		return false
	}
	if c.ContactSource == ContactSourceTransactional {
		return false
	}
	switch c.ContactType {
	case "general", "trusted", "professional", "coworker":
		return true
	default:
		return c.ContactType == "" || c.ContactType == "general"
	}
}

// MajorityThreshold returns the minimum safe threshold for N witnesses.
func MajorityThreshold(n int) int {
	if n <= 0 {
		return DefaultThreshold
	}
	return (n / 2) + 1
}

// ClassifyAID returns pairwise when aid differs from the agent root AID.
func ClassifyAID(aid, rootAID string) AidKind {
	if rootAID != "" && aid != rootAID {
		return AidKindPairwise
	}
	return AidKindRoot
}

// ContactWitnessAllowedForAID enforces commercial-only for Pairwise (OQ-W2).
func ContactWitnessAllowedForAID(kind AidKind, isCommercial bool) bool {
	if isCommercial {
		return true
	}
	return kind == AidKindRoot
}