package server

import (
	"fmt"

	"identity-agent-core/buildmode"
)

// Keeping a development agent and a production agent from transacting with each
// other by accident.
//
// A development build is run against disjoint infrastructure — its own witnesses,
// its own endpoints, its own trust anchor (which is what update verification and
// signing actually rest on). That separation is the real boundary, and most of
// the time it is why a development agent and a production agent never reach each
// other at all. This file is not that boundary. It is a tag carried on the OOBI
// handshake so that when the two DO meet — a development endpoint left pointing
// at a production peer, an OOBI pasted across from the wrong environment — the
// contact fails closed with a reason a person can read, instead of silently
// forming a relationship that spans the two realms.
//
// It is self-reported and therefore not proof: a rebuilt binary can emit any
// realm it likes. That is exactly why it is defence-in-depth and not the wall.
// What it buys is that an honest cross-realm contact stops here rather than
// three layers deeper, where the only remaining signal would be a trust-anchor
// mismatch no human was watching for.

// realmOf maps an absent realm to production. An agent built before this tag
// existed, or a production agent, serves no realm; reading that as production is
// what keeps every existing production relationship working rather than refusing
// peers that predate the tag.
func realmOf(realm string) string {
	if realm == "" {
		return buildmode.Prod
	}
	return realm
}

// peerRealmRefused reports whether an agent in ourRealm must refuse a peer that
// presented peerRealm. Both are normalised first, so an absent realm on either
// side is treated as production. The realm is passed in rather than read from
// buildmode here, so the decision is testable in both directions without
// rebuilding under a different linker flag.
func peerRealmRefused(ourRealm, peerRealm string) bool {
	return realmOf(ourRealm) != realmOf(peerRealm)
}

// crossRealmMessage is the one wording every resolve path uses to refuse a
// cross-realm peer, kept in a single place so the paths that share this gate
// cannot drift apart in what they say. peerRealm is normalised, so an untagged
// peer is named as production.
func crossRealmMessage(peerAID, peerRealm string) string {
	return fmt.Sprintf(
		"this Identity Agent runs in the %s realm and %s runs in the %s realm, so no "+
			"relationship was formed — a development-realm and a production-realm Identity "+
			"Agent are kept apart",
		buildmode.Mode(), peerAID, realmOf(peerRealm))
}
