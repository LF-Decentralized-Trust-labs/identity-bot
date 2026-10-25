package conversationbundle

import (
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"

	"identity-agent-core/agentmessage"
	"identity-agent-core/didcomm"
	"identity-agent-core/sandbox"
)

// Build is checked here against a store that is not an Identity Agent: what a
// bundle carries is decided by the package, so any store keeping a
// conversation record can export one. That the bundles a real Identity Agent
// builds verify is checked in the server's tests.

const (
	root   = "EROOT"
	agentA = "EAGENT_A"
	agentB = "EAGENT_B"
	signer = "ELOG_SIGNER"
	record = "ERECORD"
)

// aStore is a conversation record kept somewhere other than an Identity
// Agent: a person asks AI agent A, which asks AI agent B.
type aStore struct {
	entries     []RecordedEntry
	words       map[string][]byte
	credentials map[string]string // SAID → the credential as issued
	owner       *Owner
	logRows     []sandbox.StoredRow
	asked       []string // the key logs asked for, in order
}

func newStore(t *testing.T) *aStore {
	t.Helper()
	s := &aStore{
		words: map[string][]byte{},
		credentials: map[string]string{
			// A's body credential names the Controller Grant that authorised
			// it, and that grant rests on a request the owner signed.
			"EBODY_A":  `{"e":{"authorised_by":{"n":"EGRANT_C"}}}`,
			"EGRANT_C": `{"a":{"request":{"kind":"owner"}}}`,
			"EGRANT_B": `{}`,
		},
		owner:   &Owner{AID: "EOWNER", Key: "DOWNER"},
		logRows: []sandbox.StoredRow{{ID: 7}, {ID: 8}},
	}
	s.add(t, root, agentmessage.Record{MessageID: "m1", Kind: "message",
		From: agentmessage.Person("EPERSON"), To: agentA}, "what does the build server run?")
	s.add(t, agentA, agentmessage.Record{MessageID: "m2", Kind: "ask",
		From: agentA, To: agentB, BodyCredential: "EBODY_A", GrantSAID: "EGRANT_B"}, "what do you run?")
	return s
}

func (s *aStore) add(t *testing.T, as string, r agentmessage.Record, words string) {
	t.Helper()
	keys, err := didcomm.GenerateKeySet(as)
	if err != nil {
		t.Fatal(err)
	}
	r.BodyHash = agentmessage.HashBody([]byte(words))
	env, err := agentmessage.Countersign(keys, r)
	if err != nil {
		t.Fatal(err)
	}
	ref := "ref-" + r.MessageID
	s.words[ref] = []byte(words)
	s.entries = append(s.entries, RecordedEntry{MessageID: r.MessageID, Envelope: env, BodyHash: r.BodyHash, ContentRef: ref})
}

func (s *aStore) Entries(context.Context, string) ([]RecordedEntry, error) { return s.entries, nil }

func (s *aStore) Words(_ context.Context, e RecordedEntry) ([]byte, error) {
	w, ok := s.words[e.ContentRef]
	if !ok {
		return nil, errors.New("not kept")
	}
	return w, nil
}

func (s *aStore) Anchors() (KeyLog, []Anchor, bool, error) {
	return KeyLog{AID: record}, []Anchor{{Seq: 1, Statement: "{}"}}, true, nil
}

func (s *aStore) Log(string) (Log, error) { return Log{Signer: signer, Rows: s.logRows}, nil }

func (s *aStore) KeyLog(aid string) (KeyLog, error) {
	s.asked = append(s.asked, aid)
	return KeyLog{AID: aid}, nil
}

func (s *aStore) MessagingKeys(aid string) (didcomm.DID, error) { return didcomm.DID{AID: aid}, nil }

func (s *aStore) Credential(said string) (Credential, string, error) {
	raw, ok := s.credentials[said]
	if !ok {
		return Credential{}, "", errors.New("not on record")
	}
	return Credential{Raw: base64.StdEncoding.EncodeToString([]byte(raw))}, "EREGISTRY", nil
}

func (s *aStore) Registry(said string) (Registry, error) { return Registry{Inception: "vcp"}, nil }
func (s *aStore) Owner() (*Owner, error)                 { return s.owner, nil }

func (s *aStore) sources() Sources { return Sources{Record: s, Identities: s, Credentials: s} }

func build(t *testing.T, s *aStore) (*Bundle, error) {
	t.Helper()
	return Build(context.Background(), s.sources(), "c1", root, "EOWNER", "2026-10-24T00:00:00Z")
}

func TestAnyStoreBuildsABundleOfEverythingTheEntriesRestOn(t *testing.T) {
	s := newStore(t)
	b, err := build(t, s)
	if err != nil {
		t.Fatalf("building: %v", err)
	}
	if b.Format != Format || b.Conversation != "c1" || b.Root != root || b.RecordIdentity != record {
		t.Fatalf("the bundle names the wrong things: %+v", b)
	}
	if len(b.Entries) != 2 || len(b.Anchors) != 1 || len(b.Log.Rows) != 2 || b.Log.Signer != signer {
		t.Fatalf("entries %d, anchors %d, rows %d, signer %q", len(b.Entries), len(b.Anchors), len(b.Log.Rows), b.Log.Signer)
	}
	// A person's words are countersigned by the root; an AI agent's by itself.
	var countersigners []string
	for _, d := range b.Countersigners {
		countersigners = append(countersigners, d.AID)
	}
	if want := []string{agentA, root}; !reflect.DeepEqual(countersigners, want) {
		t.Fatalf("countersigners %v, want %v", countersigners, want)
	}
	// The record identity's key log first, then the root, every AI agent in
	// the conversation, and the governance log's signer.
	var logs []string
	for _, kl := range b.KeyLogs {
		logs = append(logs, kl.AID)
	}
	if want := []string{record, root, agentA, agentB, signer}; !reflect.DeepEqual(logs, want) {
		t.Fatalf("key logs %v, want %v", logs, want)
	}
	// The grant that authorised A's body is followed, and because it rests on
	// the owner's signed request, the owner comes with it.
	var creds []string
	for _, c := range b.Credentials {
		creds = append(creds, c.SAID)
	}
	if want := []string{"EBODY_A", "EGRANT_B", "EGRANT_C"}; !reflect.DeepEqual(creds, want) {
		t.Fatalf("credentials %v, want %v", creds, want)
	}
	if b.Owner == nil || b.Owner.AID != "EOWNER" || len(b.Registries) != 1 || b.Registries[0].SAID != "EREGISTRY" {
		t.Fatalf("owner %+v, registries %+v", b.Owner, b.Registries)
	}
}

func TestWordsNoLongerMatchingTheirDigestAreRefused(t *testing.T) {
	s := newStore(t)
	s.words["ref-m2"] = []byte("what do you run? (edited)")
	_, err := build(t, s)
	if !errors.Is(err, ErrIncomplete) || !strings.Contains(err.Error(), "m2") {
		t.Fatalf("edited words were exported: %v", err)
	}
}

func TestMissingWordsNameTheMessage(t *testing.T) {
	s := newStore(t)
	delete(s.words, "ref-m1")
	_, err := build(t, s)
	if !errors.Is(err, ErrIncomplete) || !strings.Contains(err.Error(), "m1") {
		t.Fatalf("a bundle was built without the words of m1: %v", err)
	}
}

func TestACredentialThatCannotBeShownFailsTheBundle(t *testing.T) {
	s := newStore(t)
	delete(s.credentials, "EGRANT_C")
	_, err := build(t, s)
	if !errors.Is(err, ErrIncomplete) || !strings.Contains(err.Error(), "EGRANT_C") {
		t.Fatalf("a bundle was built without the grant its body credential names: %v", err)
	}
}

func TestAnOwnerSignedGrantWithNoKnownOwnerFailsTheBundle(t *testing.T) {
	s := newStore(t)
	s.owner = nil
	if _, err := build(t, s); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("a bundle resting on the owner's request was built without the owner: %v", err)
	}
}

func TestAConversationTheLogNeverRecordedFailsTheBundle(t *testing.T) {
	s := newStore(t)
	s.logRows = nil
	if _, err := build(t, s); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("a bundle was built with no governance log rows: %v", err)
	}
}
