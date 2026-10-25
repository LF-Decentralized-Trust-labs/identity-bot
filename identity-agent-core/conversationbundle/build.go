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

	keri "github.com/grapeid/keri-go"
)

// A bundle is gathered by Build from two sides. The store that keeps the
// conversation hands over its entries and their words (Record). The Identity
// Agent hands over what only it holds: the anchors and the governance log
// (Ledger), the key logs and messaging keys of the identities that signed
// (Identities), and the credentials the entries rest on (Credentials). Some of
// that it produces at export time: a key log its engine holds unsigned is
// signed then by the key in force for it. Build decides what a bundle must
// carry and checks the words against the digests the entries were signed
// over, so a store that keeps the entries and words exports through Build.
//
// Build never leaves anything out to succeed. Words missing, or no longer
// matching the digest the record holds, a credential whose log cannot be
// shown, a key log that cannot be had: each fails the build and says which,
// because a bundle missing any of them could not prove what it claims to.

// ErrIncomplete is a bundle that could not be gathered in full.
var ErrIncomplete = errors.New("the conversation cannot be exported in full")

// Record is the conversation as the store that keeps it holds it: its entries
// and their words.
type Record interface {
	// Entries are the conversation's entries, in order.
	Entries(ctx context.Context, conversation string) ([]RecordedEntry, error)
	// Words are the words the store holds for one entry.
	Words(ctx context.Context, e RecordedEntry) ([]byte, error)
}

// Ledger is the Identity Agent's account of the conversation: the anchors that
// fix it and the governance log it was written to.
type Ledger interface {
	// Anchors are the record identity's key log and every statement its
	// interactions seal, read together so the two agree. ok is false when
	// nothing has been anchored yet.
	Anchors(ctx context.Context) (identity KeyLog, anchors []Anchor, ok bool, err error)
	// Log is the stretch of the governance log from the conversation's first
	// row to the newest, and the identity that signs it.
	Log(ctx context.Context, conversation string) (Log, error)
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
// any part of the record, as the Identity Agent holds them.
type Identities interface {
	// KeyLog is an identity's key log as published, every event signed, with
	// the witness receipts held for each.
	KeyLog(ctx context.Context, aid string) (KeyLog, error)
	// MessagingKeys are the messaging keys an identity countersigned with,
	// signed by its current key.
	MessagingKeys(ctx context.Context, aid string) (didcomm.DID, error)
}

// Credentials are the credentials the entries rest on, as the Identity Agent
// that issued them holds them.
type Credentials interface {
	// Credential is one credential with its transaction log as kept, and the
	// registry it is in.
	Credential(ctx context.Context, said string) (c Credential, registry string, err error)
	// Registry is a registry's inception as published.
	Registry(ctx context.Context, said string) (Registry, error)
	// Owner is the owner the root names, with the key held for them.
	Owner(ctx context.Context) (*Owner, error)
}

// Sources are what Build gathers a bundle from: the store's Record, and the
// Identity Agent's Ledger, Identities and Credentials.
type Sources struct {
	Record      Record
	Ledger      Ledger
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
	recordLog, anchors, anchored, err := src.Ledger.Anchors(ctx)
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
		return nil, incomplete("the entries: %v", err)
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
		countersigners[agentmessage.Countersigner(rec.From, root)] = true
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
		did, err := src.Identities.MessagingKeys(ctx, aid)
		if err != nil {
			return nil, incomplete("the messaging keys of %s: %v", aid, err)
		}
		b.Countersigners = append(b.Countersigners, did)
	}

	// The credentials, and every Controller Grant one names as having
	// authorised it, with their registries and logs.
	if err := gatherCredentials(ctx, b, src.Credentials, credentials); err != nil {
		return nil, err
	}

	// The key logs: the root and every AI agent.
	for _, aid := range append([]string{root}, sortedKeys(agents)...) {
		kl, err := src.Identities.KeyLog(ctx, aid)
		if err != nil {
			return nil, incomplete("the key log of %s: %v", aid, err)
		}
		b.KeyLogs = append(b.KeyLogs, kl)
	}

	// The stretch of the governance log, and its signer's key log.
	if b.Log, err = src.Ledger.Log(ctx, conversation); err != nil {
		return nil, incomplete("the governance log: %v", err)
	}
	if len(b.Log.Rows) == 0 {
		return nil, incomplete("the governance log holds no row for this conversation")
	}
	signer, err := src.Identities.KeyLog(ctx, b.Log.Signer)
	if err != nil {
		return nil, incomplete("the key log of the governance log's signer %s: %v", b.Log.Signer, err)
	}
	b.KeyLogs = append(b.KeyLogs, signer)
	return b, nil
}

// gatherCredentials adds each credential named, and every Controller Grant
// those name as having authorised them, with their logs and registries.
func gatherCredentials(ctx context.Context, b *Bundle, src Credentials, named map[string]bool) error {
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
		c, registry, err := src.Credential(ctx, said)
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
		grant, owner := restsOn(raw)
		if grant != "" {
			queue = append(queue, grant)
		}
		ownerSigned = ownerSigned || owner
	}
	for _, said := range sortedKeys(registries) {
		reg, err := src.Registry(ctx, said)
		if err != nil {
			return incomplete("registry %s: %v", said, err)
		}
		reg.SAID = said
		b.Registries = append(b.Registries, reg)
	}
	if ownerSigned {
		owner, err := src.Owner(ctx)
		if err != nil || owner == nil {
			return incomplete("a credential rests on the owner's signed request, and the owner is not known")
		}
		b.Owner = owner
	}
	return nil
}

// restsOn reads, from a credential that verifies, the Controller Grant it names
// as having authorised it and whether it rests on the owner's signed request.
// Build follows what it names and Verify checks against it, so both read it
// here. A credential that does not verify rests on nothing that can be read:
// Verify refuses it, so nothing gathered for it would be checked.
func restsOn(raw []byte) (grant string, ownerSigned bool) {
	cred, err := keri.VerifyCredential(raw)
	if err != nil {
		return "", false
	}
	var e struct {
		AuthorisedBy struct {
			N string `json:"n"`
		} `json:"authorised_by"`
	}
	if len(cred.Edges) > 0 {
		_ = json.Unmarshal(cred.Edges, &e)
	}
	var a struct {
		Request struct {
			Kind string `json:"kind"`
		} `json:"request"`
	}
	if len(cred.Attributes) > 0 {
		_ = json.Unmarshal(cred.Attributes, &a)
	}
	return e.AuthorisedBy.N, a.Request.Kind == "owner"
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
