package witness

import "identity-agent-core/store"

// IsBackendEligible returns true for always-on desktop or hosted (attestation-backed) backends.
func IsBackendEligible(backendType string) bool {
	switch backendType {
	case BackendDesktop, BackendHosted, BackendCommercial:
		return true
	default:
		return false
	}
}

// IsContactWitnessEligible applies witness enrollment rules.
func IsContactWitnessEligible(c store.ContactRecord) bool {
	if c.Status != "accepted" {
		return false
	}
	if c.ContactSource == ContactSourceTransactional {
		return false
	}
	switch c.ContactCategory {
	case "general", "trusted", "professional", "transactional":
		return true
	default:
		return c.ContactCategory == "" || c.ContactCategory == "general"
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

// ContactWitnessAllowedForAID decides whether a contact may witness a given
// identity. A pairwise AID takes commercial witnesses only.
//
// This is permanent, not a default somebody should feel free to relax later.
// Witness lists are public — they are named in the inception event — so the SET
// is an identifier in its own right. Two pairwise AIDs naming the same
// distinctive handful of friends are linkable to one person, which defeats the
// entire reason for holding separate AIDs per relationship: separate keys and
// separate relay URLs buy nothing if the witness list rejoins them.
//
// A commercially operated witness does not carry that signal, because it serves
// a large population. Naming one says almost nothing about who you are.
//
// This is the one place where two otherwise-good instincts pull against each
// other. Elsewhere the intent is that a person's own contacts displace
// commercial witnesses as they accumulate — peer witnessing is the design, and
// depending on somebody's business is the thing being grown out of. On a
// pairwise AID that instinct is inverted: the peers are precisely what leaks,
// so they never displace here, no matter how many of them there are.
func ContactWitnessAllowedForAID(kind AidKind, isCommercial bool) bool {
	if isCommercial {
		return true
	}
	return kind == AidKindRoot
}
