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

// EntityType is what kind of thing an Identity Agent belongs to.
type EntityType string

const (
	EntityIndividual   EntityType = "individual"
	EntityOrganization EntityType = "organization"
	// EntityUnknown is a contact that has not said. It is not a third kind of
	// entity; it is the absence of an answer, and it is treated as such.
	EntityUnknown EntityType = ""
)

// NormaliseEntityType maps what a contact publishes onto the two kinds.
//
// Anything unrecognised becomes unknown rather than being guessed at. Guessing
// here would decide, on no evidence, whether somebody's root identifier gets
// published in a stranger's key log.
func NormaliseEntityType(v string) EntityType {
	switch EntityType(v) {
	case EntityIndividual:
		return EntityIndividual
	case EntityOrganization:
		return EntityOrganization
	default:
		return EntityUnknown
	}
}

// PeerWitnessAllowedAcross reports whether one entity may witness for another.
//
// An individual is witnessed by individuals and an organization by
// organizations. Never across, and this is a boundary rather than a preference.
//
// The two kinds treat their root identifier in opposite ways. An organization
// publishes its root AID — being findable is the point of it. An individual's
// root AID is kept as unexposed as possible, because everything that names it
// becomes a way to correlate them. A witness list is named in the inception
// event, so it is public and permanent and cannot be amended away.
//
// So an organization witnessing an individual writes that organization
// permanently into the individual's founding event, where anyone who resolves
// the org's witness key can read it — an employer, a clinic, a shelter, a place
// of worship. The person never chose to publish that and cannot unpublish it.
// The reverse leaks the same fact in the other direction: an individual
// witnessing an organization ties that person to it just as publicly.
//
// The asymmetry is the whole reason. Mixing costs the organization nothing and
// costs the individual something they cannot take back, so the two are kept
// apart rather than balanced against each other.
//
// COMMERCIAL WITNESSES ARE NOT PEERS and are not governed by this. A dedicated
// witness service serves a large population, so naming one says almost nothing
// about who its subject is — the same reason pairwise AIDs may use them and may
// not use contacts. Without that exemption a newly created individual identity
// could be witnessed by nobody at all, since it has no contacts yet.
func PeerWitnessAllowedAcross(ours, theirs EntityType) bool {
	if ours == EntityUnknown || theirs == EntityUnknown {
		// Refused rather than assumed. The cost of wrongly allowing it is a
		// permanent disclosure in somebody's founding event; the cost of
		// wrongly refusing is one fewer witness, recoverable the moment the
		// contact says what it is.
		return false
	}
	return ours == theirs
}
