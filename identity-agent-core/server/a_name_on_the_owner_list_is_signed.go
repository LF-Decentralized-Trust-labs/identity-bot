package server

import (
	"encoding/json"

	"identity-agent-core/asset"
	"identity-agent-core/login"
)

// A name on the owner list is one the owner signed.
//
// The owner list is read from the identity's key log and holds identifiers
// only. The roster has a name for each person who agreed to own the
// organisation, but that name arrives in the redeem request body and nothing
// signs it, so the roster alone cannot say who an owner is.
//
// The vouch can. The owner's agent signs {signer_aid, org_aid, name} with its
// relationship key, and that key is the one the owner was sealed under. So a
// name is shown only when the stored vouch verifies against the key this agent
// holds for that owner, and says this owner, this organisation and this name.
// Anything else -- an old roster row with no signed name, a name edited after
// the fact, a signature by another key -- yields no name, and the caller shows
// the key identifier it already has.

// verifiedOwnerNames maps owner identifier to signed name, for the owners
// whose name verifies. An owner with no verified name is absent.
func (s *CoreServer) verifiedOwnerNames(orgAID string, owners []string) map[string]string {
	out := map[string]string{}
	if s.assetHandler == nil {
		return out
	}
	rows := s.assetHandler.Store.ListEmployees()
	for _, aid := range owners {
		key := s.keyHeldForOwner(aid)
		if key == "" {
			continue
		}
		if name := signedNameOf(aid, orgAID, key, rows); name != "" {
			out[aid] = name
		}
	}
	return out
}

// keyHeldForOwner is the key this agent holds for an owner: the one it sealed
// them under, else the one on file for that identifier.
func (s *CoreServer) keyHeldForOwner(aid string) string {
	if oa, err := s.sealedOwnerAuthority(); err == nil && oa != nil && oa.AID == aid {
		return oa.PublicKey
	}
	if key, err := s.publicKeyOf(aid); err == nil {
		return key
	}
	return ""
}

// signedNameOf returns the name in the roster row for owner aid only if the
// row's vouch is that owner's signature over exactly that name.
func signedNameOf(aid, orgAID, publicKey string, rows []asset.Employee) string {
	pub, err := login.DecodeVerkey(publicKey)
	if err != nil {
		return ""
	}
	for _, e := range rows {
		if e.PairwiseAID != aid || !e.IsSigner || e.VouchSig == "" || e.VouchPayload == "" {
			continue
		}
		var p map[string]string
		if json.Unmarshal([]byte(e.VouchPayload), &p) != nil {
			continue
		}
		if p["action"] != "sign_org" || p["signer_aid"] != aid || p["org_aid"] != orgAID ||
			p["name"] == "" || p["name"] != e.Name {
			continue
		}
		if ok, err := login.VerifyAsk([]byte(e.VouchPayload), e.VouchSig, pub); err == nil && ok {
			return p["name"]
		}
	}
	return ""
}
