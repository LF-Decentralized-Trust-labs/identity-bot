package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"time"

	"identity-agent-core/asset"
	"identity-agent-core/login"
	"identity-agent-core/store"
)

// An identity that holds its own key signs the events it writes into its own log.
//
// Several things this Identity Agent does append an interaction to the identity's key
// log: approving a delegated identity, opening a credential registry, issuing a
// credential into it, revoking one. Each was stored with no signature, so the
// log this Identity Agent publishes carried events nobody had been shown to authorise,
// and a verifier refuses such a log — the approval of an AI agent, and every
// grant, then proved nothing to anybody but this machine.
//
// Where this Identity Agent holds the identity's key — an organisation holds its own —
// it signs the event's serialised bytes when it writes it. Where the key lives
// on another device, it cannot, and says so: the event is stored unsigned and
// the log is reported as unverified until that device signs it.
//
// A signature the caller already made over the event is kept as given. That is
// the case where the key lives on the caller's device and it signed the bytes
// itself; this Identity Agent has nothing better to offer.
func (s *CoreServer) saveOwnInteraction(
	aid string, ixn map[string]interface{}, rawB64 string, sn int, callerSignature string,
) error {
	rec, err := s.ownInteractionRecord(aid, ixn, rawB64, sn, callerSignature)
	if err != nil {
		return err
	}
	return s.DataStore.SaveEvent(rec)
}

// ownInteractionRecord is the stored form of an interaction this identity
// wrote, signed where this Identity Agent holds the key, for a caller that has
// to keep it together with something else.
func (s *CoreServer) ownInteractionRecord(
	aid string, ixn map[string]interface{}, rawB64 string, sn int, callerSignature string,
) (store.EventRecord, error) {
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		return store.EventRecord{}, fmt.Errorf("no identity to write an event for")
	}
	if rawB64 == "" {
		return store.EventRecord{}, fmt.Errorf("the event's serialised bytes were not supplied, so it could never be signed or checked")
	}
	if sn < 0 {
		sn = sequenceOf(ixn)
	}
	body, _ := json.Marshal(ixn)
	rec := store.EventRecord{
		AID:            aid,
		SequenceNumber: sn,
		EventType:      "ixn",
		EventJSON:      string(body),
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		RawBytesB64:    rawB64,
		CesrSignature:  callerSignature,
	}
	if aid == identity.AID {
		rec.PublicKey, rec.NextKeyDigest = identity.PublicKey, identity.NextKeyDigest
		if rec.CesrSignature == "" {
			sig, serr := s.signOwnEventBytes(rawB64)
			if serr != nil {
				log.Printf("[keri] event %d of %s is stored unsigned: %v", sn, aid, serr)
			} else {
				rec.CesrSignature = sig
			}
		}
	}
	return rec, nil
}

// signOwnEventBytes signs an event's serialised bytes with this identity's
// current key, when this Identity Agent holds it.
func (s *CoreServer) signOwnEventBytes(rawB64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(rawB64)
	if err != nil {
		return "", fmt.Errorf("the event bytes are unreadable: %w", err)
	}
	seed, err := s.identitySigningSeed()
	if err != nil {
		return "", fmt.Errorf("this Identity Agent does not hold the identity's key: %w", err)
	}
	return signEventBytes(raw, seed)
}

// signEventBytes is the one way an event's serialised bytes are signed: a CESR
// signature over exactly those bytes, so a verifier holding only the bytes and
// the key checks it.
func signEventBytes(raw, seed []byte) (string, error) {
	if len(raw) == 0 {
		return "", fmt.Errorf("there are no event bytes to sign")
	}
	return login.SignString(string(raw), seed)
}

func sequenceOf(ev map[string]interface{}) int {
	if str, ok := ev["s"].(string); ok {
		if n, err := strconv.ParseInt(str, 16, 64); err == nil {
			return int(n)
		}
	}
	return 0
}

// storedKelForVerifying is an identity's key log as it is stored — each event
// with the bytes it was published as and the signature over them — in the form
// the engine checks as a log rather than only as a chain of parsed records.
func (s *CoreServer) storedKelForVerifying(aid string) ([]map[string]interface{}, error) {
	events, err := s.DataStore.GetEvents(aid)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]interface{}, 0, len(events))
	for _, ev := range events {
		m := map[string]interface{}{}
		_ = json.Unmarshal([]byte(ev.EventJSON), &m)
		m["raw_bytes_b64"] = ev.RawBytesB64
		m["cesr_signature"] = ev.CesrSignature
		out = append(out, m)
	}
	return out, nil
}

// assetEventsAndSignatures is an asset's log as published: each event's bytes,
// and the asset's signature over them where this Identity Agent holds the asset's key.
//
// The engine keeps no signatures, so an asset's log was served as parsed events
// alone and a verifier could confirm the chain and nothing more — not that the
// asset's own key ever authorised its inception. An asset whose key this Identity Agent
// derived is signed here; the signature is deterministic, so it is the same
// every time it is served. An asset whose key lives on its own machine is
// served unsigned, because only that machine can sign for it.
func (s *CoreServer) assetEventsAndSignatures(a asset.Asset, rawEventsB64 []string) ([]string, []string) {
	signatures := make([]string, len(rawEventsB64))
	if a.SigningIndex == 0 {
		return rawEventsB64, signatures
	}
	seed, err := asset.AssetSigningSeed(s.DataDir, a.SigningIndex)
	if err != nil {
		log.Printf("[keri] the log of %s is served unsigned: %v", a.PairwiseAID, err)
		return rawEventsB64, signatures
	}
	for i, rawB64 := range rawEventsB64 {
		raw, err := base64.StdEncoding.DecodeString(rawB64)
		if err != nil {
			continue
		}
		if sig, err := signEventBytes(raw, seed); err == nil {
			signatures[i] = sig
		}
	}
	return rawEventsB64, signatures
}

// warnAboutUnprovableEvents says once, at startup, when this identity's own log
// holds events nobody else could verify — stored without the bytes they were
// serialised as, or without a signature over them. Anything anchored after such
// an event, an AI agent's approval or grant among them, is refused by a verifier,
// and without this the only trace is a denial logged much later for some other
// reason. An identity whose log was written before its events were signed has to
// be founded again; one whose key lives on another device needs that device to
// sign them.
func warnAboutUnprovableEvents(aid string, events []store.EventRecord) {
	var unprovable []int
	for _, ev := range events {
		if ev.RawBytesB64 == "" || ev.CesrSignature == "" {
			unprovable = append(unprovable, ev.SequenceNumber)
		}
	}
	if len(unprovable) == 0 {
		return
	}
	log.Printf("[keri] %d of %d events in the log of %s carry no signature or no bytes (sequence numbers %v). "+
		"Nobody else can verify this log past the first of them, so AI agent grants and credentials anchored "+
		"after it will be refused. An identity written before its events were signed must be founded again.",
		len(unprovable), len(events), aid, unprovable)
}
