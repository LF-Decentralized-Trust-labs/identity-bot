package server

// The device that holds an identity's key signing for another Identity Agent.
//
// This device's key log is the identity's: it holds the key. So what it signs
// for another Identity Agent it also records, in the same step, as the next
// event of its own key log, and it never signs a second, different event at a
// place it has already filled. Signing the bytes alone, without recording
// them, would let two different events be signed at one place, which is
// duplicity, and would leave this device's key log behind the other's, so
// every later request would fail its check.
//
// The other Identity Agent appends the same signed event when the signature
// reaches it; both logs then hold the same event, and both send it to the
// witnesses.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"identity-agent-core/drivers"

	keri "github.com/grapeid/keri-go"
)

// signForAnotherMu makes signing for another Identity Agent one at a time on
// this device, so two requests cannot both be checked against the same tip.
var signForAnotherMu sync.Mutex

// handleSignForAnother is run by the device that holds the identity's key, on
// its own core: it checks what it is asked to sign as handleCheckWhatIsToBeSigned
// does, records it in its own key log, and returns the signature to send to
// the Identity Agent that asked.
func (s *CoreServer) handleSignForAnother(w http.ResponseWriter, r *http.Request) {
	if !s.isOwner(r) {
		writeError(w, http.StatusForbidden, "owner only", "only this agent's owner signs for it")
		return
	}
	var body struct {
		PayloadB64    string `json:"payload_b64"`
		CredentialB64 string `json:"credential_b64"`
		IssuanceB64   string `json:"issuance_b64"`
		RegistryB64   string `json:"registry_b64"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body", err.Error())
		return
	}
	sig, err := s.signForAnother(body.PayloadB64, body.CredentialB64, body.IssuanceB64, body.RegistryB64)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "this is not signed here", err.Error())
		return
	}
	writeJSON(w, map[string]string{"signature": sig})
}

// signForAnother signs, and records in this device's own key log, an
// interaction another Identity Agent asks it to sign. The same interaction
// asked for again is answered with the signature already given; a different
// one at a place already filled is refused.
func (s *CoreServer) signForAnother(payloadB64, credentialB64, issuanceB64, registryB64 string) (string, error) {
	signForAnotherMu.Lock()
	defer signForAnotherMu.Unlock()
	payload, err := base64.StdEncoding.DecodeString(payloadB64)
	if err != nil || len(payload) == 0 {
		return "", fmt.Errorf("there is nothing to sign")
	}
	ixn, err := keri.ParseEvent(payload)
	if err != nil {
		return "", fmt.Errorf("what is to be signed is not an event: %w", err)
	}
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil || identity.AID != ixn.Identifier {
		return "", fmt.Errorf("this is not this identity's key log to extend")
	}
	events, err := s.DataStore.GetEvents(identity.AID)
	if err != nil {
		return "", err
	}
	// A place already filled: the same event again is answered with the
	// signature it was given; any other is a second event at that place.
	for _, ev := range events {
		if ev.SequenceNumber != int(ixn.SN) {
			continue
		}
		held, _ := base64.StdEncoding.DecodeString(ev.RawBytesB64)
		if bytes.Equal(held, payload) && ev.CesrSignature != "" {
			return ev.CesrSignature, nil
		}
		return "", fmt.Errorf("this device has already signed another event at place %d of this identity's key log, and signs no second one there", ixn.SN)
	}
	if _, err := s.whatIsToBeSigned(payloadB64, credentialB64, issuanceB64, registryB64); err != nil {
		return "", err
	}
	seed, err := s.identitySigningSeed()
	if err != nil {
		return "", fmt.Errorf("this device cannot sign as this identity: %w", err)
	}
	keeper, ok := s.KeriDriver.(drivers.KELKeeper)
	if !ok {
		return "", fmt.Errorf("this device's engine cannot keep its key log")
	}
	// Built again by this device's own engine on its own tip, and appended
	// only if that is byte for byte what it was asked to sign.
	var body struct {
		A []json.RawMessage `json:"a"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		return "", err
	}
	data := make([]interface{}, 0, len(body.A))
	for _, a := range body.A {
		data = append(data, a)
	}
	var signature string
	keep := func(k drivers.KELKeep) error {
		if !bytes.Equal(k.Raw, payload) {
			return fmt.Errorf("the interaction this device would make here is not the one it was asked to sign")
		}
		sig, err := signEventBytes(k.Raw, seed)
		if err != nil {
			return err
		}
		var parsed map[string]interface{}
		if err := json.Unmarshal(k.Raw, &parsed); err != nil {
			return err
		}
		rec, err := s.ownInteractionRecord(identity.AID, parsed, base64.StdEncoding.EncodeToString(k.Raw), k.SN, sig)
		if err != nil {
			return err
		}
		if err := s.DataStore.SaveEvent(rec); err != nil {
			return err
		}
		signature = sig
		return nil
	}
	if _, err := keeper.InteractKept(identity.AID, data, keep); err != nil {
		return "", err
	}
	s.witnessOwnLog()
	return signature, nil
}
