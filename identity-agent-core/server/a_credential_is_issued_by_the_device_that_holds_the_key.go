package server

// A credential issued where the identity's key is held by the app (ADR-061).
//
// Anchoring a credential appends an interaction to the identity's key log, and
// only the device that holds the key signs one. So issuing is three steps, the
// middle one not this Identity Agent's:
//
//  1. POST /api/credential/prepare builds the credential and says what must be
//     anchored for it. Nothing is added or kept.
//  2. The app checks the credential is the one it asked for, has the interaction
//     prepared and committed through POST /api/events/prepare and /commit
//     with exactly that seal, checks it, and signs it.
//  3. POST /api/credential/record is given the credential back and the
//     interaction, finds the interaction in the key log anchoring that
//     credential, and only then keeps the credential.
//
// Nothing is kept for a credential the key log does not anchor, and nothing is
// anchored here unsigned. The record is made from the credential's own bytes,
// never from fields the caller adds beside them.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"identity-agent-core/internal/jsonreply"
	"log"
	"net/http"
	"sort"
	"time"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/backup"
	"identity-agent-core/drivers"
	"identity-agent-core/schemas"
	"identity-agent-core/store"
)

// credentialBuilder is an engine that builds a credential without anchoring it.
type credentialBuilder interface {
	BuildCredential(issuer string, claims map[string]interface{}, schemaSaid, holderAid string, edges map[string]interface{}) ([]byte, string, error)
}

// issuedCredentialRecord is the record of a credential issued, as every route
// that issues one keeps it.
func (s *CoreServer) issuedCredentialRecord(said, issuer, holder, schema, acdcB64, ixnSAID, cesrSignature string) store.CredentialRecord {
	credType := ""
	if sc := schemas.Get(schema); sc != nil {
		credType = sc.Name
	}
	issuerName := ""
	if profile, _ := s.DataStore.GetProfile(); profile != nil {
		issuerName = profile.FullName
	}
	return store.CredentialRecord{
		SAID:           said,
		IssuerAID:      issuer,
		HolderAID:      holder,
		SchemaSAID:     schema,
		AcdcJson:       acdcB64,
		IxnSAID:        ixnSAID,
		CesrSignature:  cesrSignature,
		IssuedAt:       time.Now().UTC().Format(time.RFC3339),
		Status:         "issued",
		Format:         "acdc",
		CredentialType: credType,
		IssuerName:     issuerName,
	}
}

// keepIssuedCredential keeps the record and, where the holder is a known
// contact, delivers the credential to them.
func (s *CoreServer) keepIssuedCredential(record store.CredentialRecord) {
	if err := s.DataStore.SaveCredential(record); err != nil {
		log.Printf("[identity-agent-core] CREDENTIAL: Failed to persist credential %s: %v", record.SAID, err)
	} else {
		s.notifyBackupEvent(backup.EventCredential)
	}
	if contact, err := s.DataStore.GetContact(record.HolderAID); err == nil && contact != nil && contact.OobiURL != "" {
		s.inBackground(func(context.Context) { s.deliverCredentialToContact(contact, record) })
	}
}

func (s *CoreServer) handlePrepareCredential(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Claims     map[string]interface{} `json:"claims"`
		SchemaSaid string                 `json:"schema_said"`
		HolderAid  string                 `json:"holder_aid"`
		Edges      map[string]interface{} `json:"edges,omitempty"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxKeyEventBody)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	if len(req.Claims) == 0 || req.SchemaSaid == "" {
		writeError(w, http.StatusBadRequest, "Missing required fields", "claims and schema_said are required")
		return
	}
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		writeError(w, http.StatusBadRequest, "No identity found", "Create an identity before issuing credentials")
		return
	}
	b, ok := s.KeriDriver.(credentialBuilder)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "No KERI engine here builds credentials",
			"credentials are built by the in-process engine")
		return
	}
	// Issued as the identity itself: the app holds that identity's keys, and no
	// other's, so a credential of a pairwise relationship is not built here.
	acdc, said, err := b.BuildCredential(identity.AID, req.Claims, req.SchemaSaid, req.HolderAid, req.Edges)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Credential build failed", err.Error())
		return
	}
	seal, err := credentialSeal(said)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Credential build failed", err.Error())
		return
	}
	jsonreply.Write(w, http.StatusOK, map[string]any{
		"issuer_aid":    identity.AID,
		"acdc_said":     said,
		"acdc_json_b64": base64.StdEncoding.EncodeToString(acdc),
		// What the interaction must anchor. The app derives this itself and
		// compares; it is here for a caller that does not.
		"anchors": []json.RawMessage{seal},
	})
}

// credentialSeal is the seal that anchors a credential issued outside a
// registry: its identifier, at sequence 0, with its own digest.
func credentialSeal(said string) (json.RawMessage, error) {
	return json.Marshal(map[string]string{"i": said, "s": "0", "d": said})
}

func (s *CoreServer) handleRecordCredential(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AcdcJsonB64 string `json:"acdc_json_b64"`
		IxnSaid     string `json:"ixn_said"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxKeyEventBody)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(req.AcdcJsonB64)
	if err != nil || len(raw) == 0 || req.IxnSaid == "" {
		writeError(w, http.StatusBadRequest, "Missing required fields",
			"acdc_json_b64 is the credential's bytes, and ixn_said the interaction that anchors it")
		return
	}
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		writeError(w, http.StatusBadRequest, "No identity found", "Create an identity before issuing credentials")
		return
	}
	cred, err := keri.VerifyCredential(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "That is not a credential", err.Error())
		return
	}
	if cred.Issuer != identity.AID {
		writeError(w, http.StatusBadRequest, "That is not this identity's credential",
			"a credential is recorded here as issued only by the identity kept here")
		return
	}
	// A credential already kept was judged when it was kept, so it is answered
	// without judging the key log again: that costs work in the log's length,
	// and a record can be sent again by anybody who holds its bytes.
	if have, _ := s.DataStore.GetCredential(cred.SAID); have != nil {
		s.answerKeptCredential(w, cred.SAID, have.Status)
		return
	}
	if err := s.keyLogAnchors(identity.AID, req.IxnSaid, cred.SAID); err != nil {
		writeError(w, http.StatusConflict, "The key log does not anchor that credential", err.Error())
		return
	}
	// Finding whether it is kept and keeping it are one step, so two records of
	// one credential send one delivery and one backup event.
	s.recordingCredential.Lock()
	have, _ := s.DataStore.GetCredential(cred.SAID)
	if have != nil {
		s.recordingCredential.Unlock()
		s.answerKeptCredential(w, cred.SAID, have.Status)
		return
	}
	record := s.issuedCredentialRecord(cred.SAID, cred.Issuer, cred.Recipient, cred.SchemaSAID,
		req.AcdcJsonB64, req.IxnSaid, "")
	s.keepIssuedCredential(record)
	s.recordingCredential.Unlock()
	log.Printf("[identity-agent-core] CREDENTIAL: Recorded %s for holder %s (anchored by %s)", cred.SAID, cred.Recipient, req.IxnSaid)
	jsonreply.Write(w, http.StatusCreated, map[string]any{"acdc_said": cred.SAID, "status": "issued"})
}

// answerKeptCredential answers a record of a credential already kept with what
// it is now, which is not "issued" once it is revoked.
func (s *CoreServer) answerKeptCredential(w http.ResponseWriter, said, status string) {
	jsonreply.Write(w, http.StatusOK, map[string]any{"acdc_said": said, "status": status})
}

// keyLogAnchors is nil where aid's key log holds an interaction with digest ixn
// that seals the credential said, as a credential issued outside a registry is
// sealed. The log up to and including that interaction is judged as every key
// log is, signatures and all: a row somebody stored is not an event of the log
// until it verifies as one. Otherwise it says which of those failed.
//
// The log is read as it is kept (store.SignedLogOf) and judged whole, with no
// cap on its length: that cap is for logs somebody sent.
func (s *CoreServer) keyLogAnchors(aid, ixn, said string) error {
	events, err := s.DataStore.GetEvents(aid)
	if err != nil {
		return fmt.Errorf("this identity's key log cannot be read: %w", err)
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].SequenceNumber < events[j].SequenceNumber })
	for i, rec := range events {
		if rec.EventType != "ixn" || rec.RawBytesB64 == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(rec.RawBytesB64)
		if err != nil {
			continue
		}
		ev, err := keri.ParseEvent(raw)
		if err != nil || ev.SAID != ixn || ev.Identifier != aid {
			continue
		}
		// The seal is read from the bytes that are judged, not from the
		// copy kept beside them.
		if !anchorsExactSealOf([]store.EventRecord{{EventJSON: string(raw)}}, said, "0", said) {
			return fmt.Errorf("the interaction %s is in this identity's key log and does not seal that credential", ixn)
		}
		prefix, err := store.SignedLogOf(events[:i+1])
		if err != nil {
			return fmt.Errorf("the key log up to %s cannot be judged: %w", ixn, err)
		}
		messages, err := drivers.StoredLogMessages(prefix)
		if err != nil {
			return fmt.Errorf("the key log up to %s cannot be judged: %w", ixn, err)
		}
		if _, err := drivers.VerifiedLogOf(aid, messages); err != nil {
			return fmt.Errorf("the key log up to %s does not verify: %w", ixn, err)
		}
		return nil
	}
	return fmt.Errorf("this identity's key log holds no interaction with digest %s", ixn)
}
