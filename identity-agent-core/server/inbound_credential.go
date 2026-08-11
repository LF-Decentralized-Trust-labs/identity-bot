package server

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"identity-agent-core/backup"
	"identity-agent-core/didcomm"
	"identity-agent-core/store"
)

// A credential arriving inside an envelope.
//
// This is the first action to move, because it is the one that most obviously
// should never have been anywhere else. A credential is the most sensitive thing
// two agents exchange, and it was posted as plain JSON to an endpoint that
// identified its sender by a field in the body — and then refused it anyway,
// since that endpoint is owner-only and an issuer is neither on loopback nor
// holding the recipient's owner key. The caller logged the status without
// looking at it, so every cross-agent delivery had been failing silently.
//
// Inside an envelope, the issuer is established by the envelope rather than
// asserted in the body, the credential is not readable in transit, and a
// captured copy cannot be delivered a second time.

func init() { registerInboundAction(credentialIssuance{}) }

type credentialIssuance struct{}

func (credentialIssuance) Type() string { return didcomm.TypeCredentialIssuance }

// credentialDelivery is what an issuer sends. Deliberately without an issuer
// field: who issued this is the envelope's answer, and a body that could name
// one would be a second answer to a question already settled — and the one an
// attacker gets to write.
type credentialDelivery struct {
	SAID           string `json:"said"`
	AcdcJSON       string `json:"acdc_json"`
	CredentialType string `json:"credential_type,omitempty"`
	IssuerName     string `json:"issuer_name,omitempty"`
	SchemaSAID     string `json:"schema_said,omitempty"`
}

func (credentialIssuance) Perform(s *CoreServer, in InboundMessage) error {
	var body credentialDelivery
	if err := json.Unmarshal(in.Body, &body); err != nil {
		return fmt.Errorf("the credential could not be read: %w", err)
	}
	if body.SAID == "" || body.AcdcJSON == "" {
		return fmt.Errorf("a credential needs both an identifier and its contents")
	}

	// Only from somebody the owner has agreed to hear from. Being able to open
	// an envelope to us means the relationship exists; it does not mean anyone
	// consented to receive things from them. Without this, anybody we have ever
	// exchanged keys with could put credentials in front of the owner.
	contact, cerr := s.DataStore.GetContact(in.FromAID)
	if cerr != nil || contact == nil {
		return fmt.Errorf("%s is not a contact, so nothing they issue is accepted", in.FromAID)
	}

	holderAID := ""
	if identity, err := s.DataStore.GetIdentity(); err == nil && identity != nil {
		holderAID = identity.AID
	}

	record := store.CredentialRecord{
		SAID: body.SAID,
		// From the envelope, not the body. This is the whole difference.
		IssuerAID:      in.FromAID,
		HolderAID:      holderAID,
		SchemaSAID:     body.SchemaSAID,
		AcdcJson:       body.AcdcJSON,
		IssuedAt:       time.Now().UTC().Format(time.RFC3339),
		Status:         "pending_inbound",
		Format:         detectCredentialFormat(body.AcdcJSON, ""),
		CredentialType: body.CredentialType,
		IssuerName:     body.IssuerName,
	}
	if err := s.DataStore.SaveCredential(record); err != nil {
		return fmt.Errorf("could not keep the credential: %w", err)
	}
	s.notifyBackupEvent(backup.EventCredential)

	s.EventHub.Broadcast(AgentEvent{
		Type: "credential_received",
		Payload: map[string]interface{}{
			"said":            body.SAID,
			"credential_type": body.CredentialType,
			"issuer_aid":      in.FromAID,
			"issuer_name":     body.IssuerName,
		},
	})
	log.Printf("[credential] received %s from %s, waiting to be accepted", body.SAID, in.FromAID)
	return nil
}

// SendCredential delivers a credential to its holder inside an envelope.
//
// Replaces a plain POST to the holder's REST endpoint that could not have
// worked: that endpoint is owner-only, so every remote delivery was refused
// before the handler ran, and the caller never read the answer.
func (s *CoreServer) SendCredential(fromAID, toAID string, cred store.CredentialRecord) error {
	body, err := json.Marshal(credentialDelivery{
		SAID:           cred.SAID,
		AcdcJSON:       cred.AcdcJson,
		CredentialType: cred.CredentialType,
		IssuerName:     cred.IssuerName,
		SchemaSAID:     cred.SchemaSAID,
	})
	if err != nil {
		return err
	}
	_, status, err := s.SendDIDCommMessage(fromAID, toAID, didcomm.TypeCredentialIssuance, body)
	if err != nil {
		return fmt.Errorf("could not deliver the credential to %s: %w", toAID, err)
	}
	if status < 200 || status >= 300 {
		// Looked at, rather than logged and ignored. The reason the old path's
		// failure went unnoticed for so long is that nobody read the answer.
		return fmt.Errorf("%s refused the credential (%d)", toAID, status)
	}
	return nil
}
