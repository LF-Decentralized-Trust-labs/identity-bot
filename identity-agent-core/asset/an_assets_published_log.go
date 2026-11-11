package asset

import (
	"encoding/base64"
	"log"

	"identity-agent-core/login"
)

// PublishedLog is an asset's log as published: each event's bytes, and the
// asset's signature over them where this Identity Agent holds the asset's key.
//
// The engine keeps no signatures, so an asset's log was served as parsed events
// alone and a verifier could confirm the chain and nothing more — not that the
// asset's own key ever authorised its inception. An asset whose key this
// Identity Agent derived is signed here; the signature is deterministic, so it
// is the same every time it is served. An asset whose key lives on its own
// machine is served unsigned (an empty signature for each event), because only
// that machine can sign for it.
//
// This is the one place the published log is made: /public/oobi/{aid} serves
// it, and anything that carries the same log elsewhere — an app's sign-in
// link — calls this rather than signing again.
func PublishedLog(dataDir string, a Asset, rawEventsB64 []string) (events, signatures []string) {
	signatures = make([]string, len(rawEventsB64))
	if a.SigningIndex == 0 {
		return rawEventsB64, signatures
	}
	seed, err := AssetSigningSeed(dataDir, a.SigningIndex)
	if err != nil {
		log.Printf("[keri] the log of %s is served unsigned: %v", a.PairwiseAID, err)
		return rawEventsB64, signatures
	}
	for i, rawB64 := range rawEventsB64 {
		raw, err := base64.StdEncoding.DecodeString(rawB64)
		if err != nil || len(raw) == 0 {
			continue
		}
		if sig, err := login.SignString(string(raw), seed); err == nil {
			signatures[i] = sig
		}
	}
	return rawEventsB64, signatures
}
