package conversationbundle

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"identity-agent-core/agentmessage"
	"identity-agent-core/didcomm"
)

// A bundle is gathered by Build from wherever the conversation's record is
// kept. Build decides what a bundle must carry and checks the words against
// the record; the store behind the three interfaces below only hands things
// over, so any store that keeps the record can export a bundle Verify accepts.
//
// Build never leaves anything out to succeed. Words missing, or no longer
// matching the digest the record holds, a credential whose log cannot be
// shown, a key log that cannot be had: each fails the build and says which,
// because a bundle missing any of them could not prove what it claims to.

// ErrIncomplete is a bundle that could not be gathered in full.
var ErrIncomplete = errors.New("the conversation cannot be exported in full")

// Record is the conversation record: its entries, the anchors that fix it, and
// the governance log it was written to.
type Record interface {
	// Entries are the conversation's entries, in order.
	Entries(ctx context.Context, conversation string) ([]RecordedEntry, error)
	// Words are the words the store holds for one entry.
	Words(ctx context.Context, e RecordedEntry) ([]byte, error)
	// Anchors are the record identity's key log and every statement its
	// interactions seal, read together so the two agree. ok is false when
	// nothing has been anchored yet.
	Anchors() (identity KeyLog, anchors []Anchor, ok bool, err error)
	// Log is the stretch of the governance log from the conversation's first
	// row to the newest, and the identity that signs it.
	Log(conversation string) (Log, error)
}

// RecordedEntry is one entry as the record holds it.
type RecordedEntry struct {
	MessageID string
	Envelope  *didcomm.Envelope
	// BodyHash is the digest of the words the entry was signed over.
	BodyHash string
	// ContentRef is where the store keeps the words. Build only hands it back.
	ContentRef string
}

// Identities are the key logs and messaging keys of the identities that signed
// any part of the record.
type Identities interface {
	// KeyLog is an identity's key log as published, every event signed, with
	// the witness receipts held for each.
	KeyLog(aid string) (KeyLog, error)
	// MessagingKeys are the messaging keys an identity countersigned with,
	// signed by its current key.
	MessagingKeys(aid string) (didcomm.DID, error)
}

// Credentials are the credentials the entries rest on.
type Credentials interface {
	// Credential is one credential with its transaction log as kept, and the
	// registry it is in.
	Credential(said string) (c Credential, registry string, err error)
	// Registry is a registry's inception as published.
	Registry(said string) (Registry, error)
	// Owner is the owner the root names, with the key held for them.
	Owner() (*Owner, error)
}

// Sources are what Build gathers a bundle from.
type Sources struct {
	Record      Record
	Identities  Identities
	Credentials Credentials
}

// Build gathers the bundle for one conversation of root's, exported by who at
// the time the governance log recorded it.
func Build(ctx context.Context, src Sources, conversation, root, who, at string) (*Bundle, error) {
	if root == "" {
		return nil, incomplete("there is no root identity")
	}
	b := &Bundle{
		Format: Format, Conversation: conversation, Root: root,
		ExportedAt: at, ExportedBy: who,
	}

	// The anchors first: an entry added and anchored while the bundle is
	// gathered is then simply after the newest anchor carried, never fixed by
	// an anchor whose entry the bundle lacks.
	recordLog, anchors, anchored, err := src.Record.Anchors()
	if err != nil {
		return nil, incomplete("the anchors: %v", err)
	}
	if anchored {
		b.RecordIdentity = recordLog.AID
		b.KeyLogs = append(b.KeyLogs, recordLog)
		b.Anchors = append(b.Anchors, anchors...)
	}

	// The entries, each with its words, checked against the digest the record
	// holds before they are handed out.
	entries, err := src.Record.Entries(ctx, conversation)
	if err != nil {
		return nil, err
	}
	agents := map[string]bool{}
	countersigners := map[string]bool{}
	credentials := map[string]bool{}
	for _, e := range entries {
		body, err := src.Record.Words(ctx, e)
		if err != nil {
			return nil, incomplete("the words of message %s cannot be had from the record store (%v)", e.MessageID, err)
		}
		if agentmessage.HashBody(body) != e.BodyHash {
			return nil, incomplete("the words the record store holds for message %s are not the words it was signed over", e.MessageID)
		}
		b.Entries = append(b.Entries, Entry{Envelope: e.Envelope, Body: base64.StdEncoding.EncodeToString(body)})
		rec, err := agentmessage.Read(e.Envelope)
		if err != nil {
			return nil, incomplete("message %s is unreadable: %v", e.MessageID, err)
		}
		for _, party := range []string{rec.From, rec.To} {
			if _, person := agentmessage.IsPerson(party); !person && party != "" {
				agents[party] = true
			}
		}
		// A person's words are countersigned by the root on their behalf.
		if _, person := agentmessage.IsPerson(rec.From); person {
			countersigners[root] = true
		} else {
			countersigners[rec.From] = true
		}
		for _, said := range []string{rec.BodyCredential, rec.GrantSAID} {
			if said != "" {
				credentials[said] = true
			}
		}
		if rec.ControllerProof != nil && rec.ControllerProof.ControllerGrant != "" {
			credentials[rec.ControllerProof.ControllerGrant] = true
		}
	}

	// The messaging keys every entry was countersigned with.
	for _, aid := range sortedKeys(countersigners) {
		did, err := src.Identities.MessagingKeys(aid)
		if err != nil {
			return nil, incomplete("the messaging keys of %s: %v", aid, err)
		}
		b.Countersigners = append(b.Countersigners, did)
	}

	// The credentials, and every Controller Grant one names as having
	// authorised it, with their registries and logs.
	if err := gatherCredentials(b, src.Credentials, credentials); err != nil {
		return nil, err
	}

	// The key logs: the root and every AI agent.
	for _, aid := range append([]string{root}, sortedKeys(agents)...) {
		kl, err := src.Identities.KeyLog(aid)
		if err != nil {
			return nil, incomplete("the key log of %s: %v", aid, err)
		}
		b.KeyLogs = append(b.KeyLogs, kl)
	}

	// The stretch of the governance log, and its signer's key log.
	if b.Log, err = src.Record.Log(conversation); err != nil {
		return nil, incomplete("the governance log: %v", err)
	}
	if len(b.Log.Rows) == 0 {
		return nil, incomplete("the governance log holds no row for this conversation")
	}
	signer, err := src.Identities.KeyLog(b.Log.Signer)
	if err != nil {
		return nil, incomplete("the key log of the governance log's signer %s: %v", b.Log.Signer, err)
	}
	b.KeyLogs = append(b.KeyLogs, signer)
	return b, nil
}

// gatherCredentials adds each credential named, and every Controller Grant
// those name as having authorised them, with their logs and registries.
func gatherCredentials(b *Bundle, src Credentials, named map[string]bool) error {
	registries := map[string]bool{}
	done := map[string]bool{}
	queue := sortedKeys(named)
	ownerSigned := false
	for len(queue) > 0 {
		said := queue[0]
		queue = queue[1:]
		if done[said] {
			continue
		}
		done[said] = true
		c, registry, err := src.Credential(said)
		if err != nil {
			return incomplete("credential %s: %v", said, err)
		}
		raw, err := base64.StdEncoding.DecodeString(c.Raw)
		if err != nil {
			return incomplete("credential %s is unreadable", said)
		}
		c.SAID = said
		b.Credentials = append(b.Credentials, c)
		registries[registry] = true
		var acdc struct {
			A struct {
				Request struct {
					Kind string `json:"kind"`
				} `json:"request"`
			} `json:"a"`
			E struct {
				AuthorisedBy struct {
					N string `json:"n"`
				} `json:"authorised_by"`
			} `json:"e"`
		}
		_ = json.Unmarshal(raw, &acdc)
		if g := acdc.E.AuthorisedBy.N; g != "" {
			queue = append(queue, g)
		}
		ownerSigned = ownerSigned || acdc.A.Request.Kind == "owner"
	}
	for _, said := range sortedKeys(registries) {
		reg, err := src.Registry(said)
		if err != nil {
			return incomplete("registry %s: %v", said, err)
		}
		reg.SAID = said
		b.Registries = append(b.Registries, reg)
	}
	if ownerSigned {
		owner, err := src.Owner()
		if err != nil || owner == nil {
			return incomplete("a credential rests on the owner's signed request, and the owner is not known")
		}
		b.Owner = owner
	}
	return nil
}

func incomplete(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrIncomplete, fmt.Sprintf(format, args...))
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
