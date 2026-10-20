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
// Several things this agent does append an interaction to the identity's key
// log: approving a delegated identity, opening a credential registry, issuing a
// credential into it, revoking one. Each was stored with no signature, so the
// log this agent publishes carried events nobody had been shown to authorise,
// and a verifier refuses such a log — the approval of an AI agent, and every
// grant, then proved nothing to anybody but this machine.
//
// Where this agent holds the identity's key — an organisation holds its own —
// it signs the event's serialised bytes when it writes it. Where the key lives
// on another device, it cannot, and says so: the event is stored unsigned and
// the log is reported as unverified until that device signs it.
func (s *CoreServer) saveOwnInteraction(
	aid string, ixn map[string]interface{}, rawB64 string, sn int,
) error {
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		return fmt.Errorf("no identity to write an event for")
	}
	if rawB64 == "" {
		return fmt.Errorf("the event's serialised bytes were not supplied, so it could never be signed or checked")
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
		PublicKey:      identity.PublicKey,
		NextKeyDigest:  identity.NextKeyDigest,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		RawBytesB64:    rawB64,
	}
	if aid == identity.AID {
		sig, serr := s.signOwnEventBytes(rawB64)
		if serr != nil {
			log.Printf("[keri] event %d of %s is stored unsigned: %v", sn, aid, serr)
		} else {
			rec.CesrSignature = sig
		}
	}
	return s.DataStore.SaveEvent(rec)
}

// signOwnEventBytes signs an event's serialised bytes with this identity's
// current key, when this agent holds it.
func (s *CoreServer) signOwnEventBytes(rawB64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(rawB64)
	if err != nil {
		return "", fmt.Errorf("the event bytes are unreadable: %w", err)
	}
	seed, err := s.identitySigningSeed()
	if err != nil {
		return "", fmt.Errorf("this agent does not hold the identity's key: %w", err)
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
// and the asset's signature over them where this agent holds the asset's key.
//
// The engine keeps no signatures, so an asset's log was served as parsed events
// alone and a verifier could confirm the chain and nothing more — not that the
// asset's own key ever authorised its inception. An asset whose key this agent
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
		if err != nil || len(raw) == 0 {
			continue
		}
		if sig, err := login.SignString(string(raw), seed); err == nil {
			signatures[i] = sig
		}
	}
	return rawEventsB64, signatures
}
