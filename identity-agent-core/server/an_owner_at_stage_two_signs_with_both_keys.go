package server

import (
	"bytes"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/store"

	keri "github.com/grapeid/keri-go"
)

// An owner at stage two signs a request with both keys (ADR-061 section 6).
//
// A stage-two identity's k holds its classical key and a post-quantum one, and
// every event it makes needs both. The owner's requests are the same: the
// classical signature is in X-IA-Owner-Sig as always, and the post-quantum one,
// over the same bytes, is in X-IA-Owner-Sig-PQ as an indexed signature at place
// 1. An identity at stage two whose request carries the first alone is refused,
// so the post-quantum key is not a key nobody has to hold. Only a build that
// reads post-quantum keys (the kerigo_pqtest tag) has an owner at stage two;
// in any other the owner's k never holds one, and nothing here applies.
const headerOwnerSigPostQuantum = "X-IA-Owner-Sig-PQ"

// ownerPostQuantumKey is the post-quantum key among the keys in force of the
// owner, and the place it holds in that list; "" where there is none to require.
//
// Only this core's own identity is held to it, and only in a build that reads
// post-quantum keys (keri.PostQuantumTestCodes). A default build returns "" at
// once and nothing here runs. For the own identity it fails closed: it refuses
// where the key state does not name the key the request was verified under,
// where the own log is empty, or where more post-quantum keys are named than one
// header can answer.
//
// An owner that is NOT this core's own identity (a paired machine's owner)
// returns "": no post-quantum signature is required of it yet. A stage-two
// contact log cannot be verified today (drivers/validate_kel.go refuses a
// multi-key log), so whether such an owner is at stage two cannot be read from
// anything this machine could trust, and a requirement read from an unverified
// log could be made up or wound back by whoever supplied it. Task T-945 (verify
// multi-key contact logs, then hold a paired machine's stage-two owner to both
// keys) removes this gap.
func (s *CoreServer) ownerPostQuantumKey(authority *OwnerAuthority) (string, int, error) {
	if !keri.PostQuantumTestCodes() || authority == nil || authority.AID == "" || s.DataStore == nil {
		return "", 0, nil
	}
	own, _ := s.DataStore.GetIdentity()
	if own == nil || own.AID != authority.AID {
		return "", 0, nil // not this core's own identity: deferred, see T-945
	}
	keys, err := s.ownKeysInForce(authority.AID)
	if err != nil {
		return "", 0, fmt.Errorf("the owner's key state cannot be read, so whether it is at stage two is unknown: %w", err)
	}
	if len(keys) == 0 {
		// An identity with no key event is not one this machine can hold a
		// request to; it is a restore that stopped, not an identity at stage one.
		return "", 0, fmt.Errorf("this machine's own key log is empty, so what its key state is cannot be told")
	}
	if !namesTheKey(keys, authority.PublicKey) {
		// A log that stops before the rotation names an older key than the one
		// the request was verified under, and says nothing of what came after.
		return "", 0, fmt.Errorf("the key state held for the owner does not name the key this request was signed with, so it is not the owner's current one")
	}
	found, at := "", 0
	for i, key := range keys {
		if !strings.HasPrefix(key, iacrypto.CESRMLDSA65Verkey) {
			continue
		}
		if found != "" {
			return "", 0, fmt.Errorf("the owner names more than one post-quantum key, and a request carries one post-quantum signature")
		}
		found, at = key, i
	}
	return found, at, nil
}

// namesTheKey says whether key is among keys, comparing the keys and not their
// spellings: a key sealed in base64url and the same key in qb64 are one key.
// Used only by the stage-two check above.
func namesTheKey(keys []string, key string) bool {
	want, err := login.DecodeVerkey(key)
	if err != nil {
		return slices.Contains(keys, key)
	}
	for _, k := range keys {
		if got, err := login.DecodeVerkey(k); err == nil && bytes.Equal(got, want) {
			return true
		}
	}
	return false
}

// ownKeysInForce is the key list in force of this Identity Agent's own log,
// read as any key log is (KeyStateOf); nil where the log is empty.
func (s *CoreServer) ownKeysInForce(aid string) ([]string, error) {
	events, err := s.DataStore.GetEvents(aid)
	if err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return nil, nil
	}
	signed, err := store.SignedLogOf(events)
	if err != nil {
		return nil, err
	}
	messages, err := drivers.StoredLogMessages(signed)
	if err != nil {
		return nil, err
	}
	state, err := KeyStateOf(aid, messages)
	if err != nil {
		return nil, err
	}
	return state.K, nil
}

// thePostQuantumSignatureOfAnOwnerRequest checks the second signature of an
// owner request at stage two over message, the bytes the first covers.
func thePostQuantumSignatureOfAnOwnerRequest(r *http.Request, pqKey string, index int, message string) error {
	return thePostQuantumSignatureOver(r.Header.Get(headerOwnerSigPostQuantum), pqKey, index, message)
}

// thePostQuantumSignatureOver checks sig, an owner request's second signature
// as it is sent and as it is kept: it must be an indexed post-quantum signature
// at place index, the place pqKey holds in the owner's key list, that verifies
// under pqKey over message.
func thePostQuantumSignatureOver(sig, pqKey string, index int, message string) error {
	if sig == "" {
		return fmt.Errorf("this owner is at stage two: a request is signed by both its keys, and this one " +
			"carries the classical signature alone")
	}
	read, err := keri.ParseIndexedSignature(sig)
	if err != nil {
		return fmt.Errorf("%s is unreadable: %w", headerOwnerSigPostQuantum, err)
	}
	if int(read.At.Index) != index {
		return fmt.Errorf("%s names key %d, and the post-quantum key is key %d", headerOwnerSigPostQuantum, read.At.Index, index)
	}
	if err := keri.VerifyUnderKey(pqKey, []byte(message), read.Code, read.Raw); err != nil {
		return fmt.Errorf("the post-quantum signature does not match the owner's post-quantum key: %w", err)
	}
	return nil
}
