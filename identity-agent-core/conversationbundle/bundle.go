// Package conversationbundle is an exported conversation between AI agents,
// and the offline check of it.
//
// A conversation between AI agents is kept as a chain of countersigned
// entries, every message is written to a signed governance log, and the heads
// of both are anchored in a record identity's key log. Build gathers
// everything needed to check that record into one bundle, from whichever store
// keeps it:
// the entries and their words, the key logs of every identity that signed any
// part of it, the credentials that made each machine an AI agent's body and
// granted each AI agent what it did, with their transaction logs, the log
// rows, and the anchors.
//
// Verify checks a bundle with nothing else: no network, no store, no running
// Identity Agent. Its report says what held, what did not, what is not yet
// anchored, and exactly what the check rests on.
package conversationbundle

import (
	"bytes"
	"encoding/json"
	"errors"

	"identity-agent-core/didcomm"
	"identity-agent-core/sandbox"
)

// CapabilityRecordAnchoring is the governance log's row for an anchoring of
// the record, written just before the anchor that fixes it.
const CapabilityRecordAnchoring = "record.anchoring"

// Format names this version of the bundle.
const Format = "IA-CONVERSATION-BUNDLE-V1"

// Bundle is one exported conversation.
type Bundle struct {
	Format       string `json:"format"`
	Conversation string `json:"conversation"`
	// ExportedAt and ExportedBy say when and by whom it was exported, as the
	// Identity Agent recorded it. The export is itself a row in Log.
	ExportedAt string `json:"exported_at"`
	ExportedBy string `json:"exported_by"`

	// Root is the organisation's own identity: the one every other identity in
	// the bundle is delegated from, and the issuer of every credential in it.
	Root string `json:"root"`
	// RecordIdentity is the identity whose key log anchors the record. Empty
	// when this Identity Agent has anchored nothing yet.
	RecordIdentity string `json:"record_identity,omitempty"`

	// Entries are the conversation's entries, in order, with their words.
	Entries []Entry `json:"entries"`
	// Countersigners are the messaging keys of every identity that
	// countersigned an entry, each signed by that identity's current key.
	Countersigners []didcomm.DID `json:"countersigners"`
	// KeyLogs are the key logs of the root, the record identity, the log's
	// signer and every AI agent in the conversation, as published and signed,
	// with the witness receipts held for each event.
	KeyLogs []KeyLog `json:"key_logs"`
	// Registries are the inceptions of the registries the credentials are in.
	Registries []Registry `json:"registries"`
	// Credentials are every credential an entry rests on — the body
	// credentials, the AI agents' grants, the Controller Grants of the machines
	// people spoke from — and every Controller Grant those name as having
	// authorised them, each with its whole transaction log as kept.
	Credentials []Credential `json:"credentials"`
	// Owner is the owner the root names, with the key this Identity Agent
	// holds for them. Present when a credential rests on a request the owner
	// signed.
	Owner *Owner `json:"owner,omitempty"`
	// Log is the stretch of the governance log from the conversation's first
	// row to the newest row when it was exported.
	Log Log `json:"log"`
	// Anchors are the statements the record identity's interactions seal: one
	// for every interaction in its key log, so none can be withheld.
	Anchors []Anchor `json:"anchors"`
}

// Entry is one conversation entry: the envelope the Identity Agent
// countersigned, and the words it carries the digest of.
type Entry struct {
	Envelope *didcomm.Envelope `json:"envelope"`
	// Body is the words, base64 (standard encoding).
	Body string `json:"body"`
}

// KeyLog is one identity's key log.
type KeyLog struct {
	AID    string  `json:"aid"`
	Events []Event `json:"events"`
}

// Event is one key event exactly as published.
type Event struct {
	// Raw is the event's bytes, base64 (standard encoding).
	Raw string `json:"raw"`
	// Signature is the controller's signature over Raw, CESR.
	Signature string `json:"signature"`
	// Receipts are the witness receipts held for the event.
	Receipts []Receipt `json:"receipts,omitempty"`
}

// Receipt is one witness's signature over an event's identifier.
type Receipt struct {
	Witness   string `json:"witness"`
	Signature string `json:"signature"`
}

// Registry is a credential registry's inception as published.
type Registry struct {
	SAID string `json:"said"`
	// Inception is the registry's inception event, base64 (standard encoding).
	Inception string `json:"inception"`
}

// Credential is one credential and its transaction log.
type Credential struct {
	SAID string `json:"said"`
	// Raw is the credential as issued, base64 (standard encoding).
	Raw string `json:"raw"`
	// Log is its transaction log as kept, in order, each event base64
	// (standard encoding): its issuance, and its revocation if there is one.
	Log []string `json:"log"`
	// RequestBody is the body of the request that authorised it, when the
	// Identity Agent kept one. The credential carries the request's signature
	// and digest; the body ties what was asked for to what was signed.
	RequestBody *string `json:"request_body,omitempty"`
}

// Owner is the owner the root names.
type Owner struct {
	AID string `json:"aid"`
	// Key is the owner's current key as this Identity Agent holds it.
	Key string `json:"key"`
}

// Log is a stretch of the governance log.
type Log struct {
	// Signer is the identity that signs the log's rows.
	Signer string `json:"signer"`
	// Rows are the rows, oldest first, with no gap.
	Rows []sandbox.StoredRow `json:"rows"`
}

// Anchor is what one interaction of the record identity seals.
type Anchor struct {
	// Seq is the interaction's place in the record identity's key log.
	Seq int `json:"seq"`
	// Statement is what was anchored, exactly as digested.
	Statement string `json:"statement"`
}

// AnchorStatement is what an anchor fixes: the newest row of the governance
// log and its hash, and the newest entry of every conversation that grew since
// the anchor before.
type AnchorStatement struct {
	Log           AnchoredLog            `json:"log"`
	Conversations []AnchoredConversation `json:"conversations,omitempty"`
	At            string                 `json:"at"`
	// Signer is the identity that signs the governance log, named so the
	// record identity, which the root delegates, vouches for it. Absent from
	// anchors made before it was named.
	Signer string `json:"signer,omitempty"`
}

// AnchoredLog is the log's newest row as an anchor fixes it.
type AnchoredLog struct {
	Row  int64  `json:"row"`
	Head string `json:"head"`
}

// AnchoredConversation is a conversation's newest entry as an anchor fixes it.
type AnchoredConversation struct {
	ID   string `json:"id"`
	Seq  int    `json:"seq"`
	Head string `json:"head"`
}

// Read reads a bundle, refusing anything an export does not write: a field it
// does not have, or more than one bundle. Go's decoder would otherwise drop an
// unknown field quietly, and a bundle would carry something nobody checked.
func Read(data []byte) (*Bundle, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var b Bundle
	if err := dec.Decode(&b); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("more than one bundle")
	}
	return &b, nil
}
