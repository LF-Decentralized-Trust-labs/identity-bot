package server

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
)

// The keys a cross-check request is signed and checked with.
//
// A request is signed as the identifier a contact already knows this agent by:
// the one minted for that relationship alone. Signing with the witness key
// instead would hand the contact, and anybody it showed, a signature by a key
// others know this agent by saying "this Identity Agent asked about X", which
// is more than the contact needs to answer.
//
// It is checked against the key an accepted contact's record holds for the
// requester, so a requester who is not a contact, or whose key is not the one
// recorded, is not answered.

// signRequestToContact signs statement as the identifier the contact peerAID
// knows this agent by, and names that identifier.
func (s *CoreServer) signRequestToContact(peerAID, statement string) (string, string, error) {
	if s.DataStore == nil {
		return "", "", fmt.Errorf("no contacts to sign a request for")
	}
	contacts, err := s.DataStore.GetContacts()
	if err != nil {
		return "", "", err
	}
	for _, c := range contacts {
		if c.AID != peerAID || c.RelationshipAID == "" {
			continue
		}
		seed, err := s.signingSeedForAID(c.RelationshipAID)
		if err != nil {
			return "", "", err
		}
		sig, err := login.SignString(statement, seed)
		if err != nil {
			return "", "", err
		}
		return c.RelationshipAID, sig, nil
	}
	return "", "", fmt.Errorf("no identifier this agent is known by to that contact")
}

// standInKey is a key nobody is known by, in the form a contact's is held in. A
// request from somebody who is not a contact is decoded and checked against it,
// so it costs the same as one from a contact and the time taken says nothing
// about which identifiers are contacts.
var standInKey = iacrypto.VerkeyQB64(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey))

// What a request is checked with, as variables so a test can count that a
// stranger's request takes the same steps as a contact's.
var (
	decodeVerkey = login.DecodeVerkey
	verifyString = login.VerifyString
)

// verifyContactRequest says whether requester is an accepted contact and sig is
// its signature over statement. It always decodes a key and checks a signature,
// against the stand-in when there is no such contact.
func (s *CoreServer) verifyContactRequest(requester, statement, sig string) bool {
	held, accepted := standInKey, false
	if s.DataStore != nil && requester != "" {
		if contacts, err := s.DataStore.GetContacts(); err == nil {
			for _, c := range contacts {
				if c.AID == requester && c.Status == "accepted" {
					held, accepted = c.PublicKey, true
					break
				}
			}
		}
	}
	key, err := decodeVerkey(held)
	if err != nil {
		accepted = false
		key, _ = decodeVerkey(standInKey)
	}
	ok, verr := verifyString(statement, sig, key)
	return accepted && verr == nil && ok
}

// contactAddress is the address an accepted contact is asked at, as peerWatchers
// gives it. Empty for anybody who is not an accepted contact.
func (s *CoreServer) contactAddress(requester string) string {
	if s.DataStore == nil || requester == "" {
		return ""
	}
	contacts, err := s.DataStore.GetContacts()
	if err != nil {
		return ""
	}
	for _, c := range contacts {
		if c.AID == requester && c.Status == "accepted" && c.OobiURL != "" {
			return peerBaseURL(c.OobiURL)
		}
	}
	return ""
}

// ownPublicURL is the address a cross-check must be signed for: where this agent
// knows it is reached, from its relay allocation or its endpoint service. Never
// from the request, whose Host and forwarding headers are the caller's to choose,
// which would let the caller pick the address its signature has to name. Empty
// when neither is known, and then nothing is answered but "no match".
func (s *CoreServer) ownPublicURL(r *http.Request) string {
	if url, ok := s.relayedAddress(r); ok {
		return url
	}
	if s.EndpointService != nil {
		return strings.TrimRight(s.EndpointService.CurrentURL(), "/")
	}
	return ""
}

// servedLog is the log this agent serves for aid at its own address, the set
// GET /public/oobi/{aid} answers: its own identity (not at a private address),
// an asset's, a minted pairwise one's. Not served, not found.
func (s *CoreServer) servedLog(aid string, r *http.Request) ([]map[string]interface{}, bool) {
	if s.DataStore == nil || aid == "" {
		return nil, false
	}
	if id, err := s.DataStore.GetIdentity(); err == nil && id != nil && id.AID == aid {
		if s.reachedAtPrivateAddress(r) {
			return nil, false
		}
		events, err := s.DataStore.GetEvents(aid)
		if err != nil {
			return nil, false
		}
		// As GET /public/oobi/{aid} serves it: the stored records themselves
		// ("kel": events), which is what the asker digests. Not the parsed
		// event inside each, or the two sides digest different things.
		b, err := json.Marshal(events)
		if err != nil {
			return nil, false
		}
		var kel []map[string]interface{}
		if json.Unmarshal(b, &kel) != nil {
			return nil, false
		}
		return kel, len(kel) > 0
	}
	if s.assetHandler != nil && s.KeriDriver != nil {
		if assets, err := s.assetHandler.Store.ListAssets(); err == nil {
			for _, a := range assets {
				if a.PairwiseAID == aid {
					k, err := s.KeriDriver.GetKel(a.DisplayName)
					if err != nil || k == nil || k.AID != aid {
						return nil, false
					}
					return k.KEL, true
				}
			}
		}
	}
	return getPairwiseKEL(aid)
}
