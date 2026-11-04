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
// relationship key. So a name is shown only when the stored vouch verifies
// against the owner's current key (keyToCheckAnOwnersNameAgainst), and says this owner, this organisation and this name.
// Anything else -- an old roster row with no signed name, a name edited after
// the fact, a signature by another key -- yields no name, and the caller shows
// the key identifier it already has.

// A signedOwnerName is a name together with the vouch that carries it, so the
// device holding the owner's key can check the name itself rather than trust
// this computer's word that it checked.
type signedOwnerName struct {
	Name string `json:"name"`
	// Payload is the exact text the owner signed; Signature is their
	// signature over it, CESR qb64, verifiable with the owner's current key.
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// verifiedOwnerNames maps owner identifier to the signed name, for the owners
// whose name verifies. An owner with no verified name is absent.
//
// WHO SHOWS NO NAME, ON PURPOSE. The name comes from the vouch an owner signed
// when they accepted ownership through an invite (ask_add_signer.go) and that
// this computer's roster stored. So:
//   - an owner added through the ownership ceremony has no roster row and no
//     key event log on file here, and shows no name;
//   - the same holds when an overlay owns the roster (OVERLAY_OWNS_ORG_ROUTES),
//     because this core's roster is then empty or not the one in use;
//   - an owner who has rotated shows no name until they sign a new name vouch (today, by redeeming another invitation), because
//     their old vouch no longer verifies against their current key.
//
// All three show the key identifier the caller already has. That is the safe
// outcome, and nothing here guesses a name to fill the gap.
func (s *CoreServer) verifiedOwnerNames(orgAID string, owners []string) map[string]signedOwnerName {
	out := map[string]signedOwnerName{}
	if s.assetHandler == nil {
		return out
	}
	rows := s.assetHandler.Store.ListEmployees()
	for _, aid := range owners {
		key := s.keyToCheckAnOwnersNameAgainst(aid)
		if key == "" {
			continue
		}
		if v, ok := signedNameOf(aid, orgAID, key, rows); ok {
			out[aid] = v
		}
	}
	return out
}

// keyToCheckAnOwnersNameAgainst is the key an owner's current signature is
// checked against, resolved the way the owner's own requests are and no more
// loosely.
//
// For any owner, a key event log this agent verified, because that is the only
// source that follows a rotation and that a caller cannot write
// (ownerKeyFromAVerifiedLog). For the founding owner, whose log may not be on
// file, whatever ownerAuthority settles on: the key that already decides
// whether they may administer this agent decides whether their name is shown,
// so a name adds no trust that ownership did not already carry. The sealed
// record and a contact row are NOT consulted for anyone else: nothing updates
// the sealed key when an owner rotates, so a vouch signed by an old or
// compromised key would go on naming them, and contact rows are written by
// routes that take an address from the caller.
func (s *CoreServer) keyToCheckAnOwnersNameAgainst(aid string) string {
	if key, err := s.ownerKeyFromAVerifiedLog(aid); err == nil {
		return key
	}
	if oa, err := s.ownerAuthority(); err == nil && oa != nil && oa.AID == aid {
		return oa.PublicKey
	}
	return ""
}

// signedNameOf returns the name in the roster row for owner aid only if the
// row's vouch is that owner's signature over exactly that name.
func signedNameOf(aid, orgAID, publicKey string, rows []asset.Employee) (signedOwnerName, bool) {
	pub, err := login.DecodeVerkey(publicKey)
	if err != nil {
		return signedOwnerName{}, false
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
			return signedOwnerName{Name: p["name"], Payload: e.VouchPayload, Signature: e.VouchSig}, true
		}
	}
	return signedOwnerName{}, false
}
