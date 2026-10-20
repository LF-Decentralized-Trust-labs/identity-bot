package server

import (
	"encoding/json"

	"identity-agent-core/didcomm"
)

// Whether a set of keys belongs to an identifier is decided in the didcomm
// package (didcomm.CheckKeysBelongTo), the one implementation, so that an
// Identity Agent and a machine checking an Identity Agent's keys use the same
// rule. These names keep the server's call sites reading as they did.

type peerKeyTrust = didcomm.KeyTrust

const (
	peerKeysAnchored = didcomm.KeysAnchored
	peerKeysVouched  = didcomm.KeysVouched
	peerKeysUntied   = didcomm.KeysUntied
)

func checkPeerKeys(did *didcomm.DID, kelEvents []map[string]interface{}, currentKey string) (peerKeyTrust, error) {
	return didcomm.CheckKeysBelongTo(did, kelEvents, currentKey)
}

// storedKELEvents returns the key history recorded for an identifier, which is
// what a freshly-run check wrote there.
func (s *CoreServer) storedKELEvents(aid string) []map[string]interface{} {
	if s.DataStore == nil {
		return nil
	}
	rec, err := s.DataStore.GetContactKEL(aid)
	if err != nil || rec == nil {
		return nil
	}
	var out []map[string]interface{}
	raw, merr := json.Marshal(rec.KEL)
	if merr != nil {
		return nil
	}
	if json.Unmarshal(raw, &out) != nil {
		return nil
	}
	return out
}
