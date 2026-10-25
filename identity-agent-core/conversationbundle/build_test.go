package conversationbundle

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"

	"identity-agent-core/agentmessage"
	"identity-agent-core/didcomm"
	"identity-agent-core/sandbox"

	keri "github.com/grapeid/keri-go"
)

// Build is checked here against a store that is not an Identity Agent: the
// entries and words come from aStore, and so, standing in for the Identity
// Agent, do the anchors, governance log, key logs and credentials. What a
// bundle carries is decided by the package. That the bundles a real Identity
// Agent builds verify is checked in the server's tests.

const (
	root   = "EROOT"
	agentA = "EAGENT_A"
	agentB = "EAGENT_B"
	signer = "ELOG_SIGNER"
	record = "ERECORD"
)

// aStore is a conversation kept somewhere other than an Identity Agent: a
// person asks AI agent A, which asks AI agent B, and the person says thanks
// from a paired machine.
type aStore struct {
	entries     []RecordedEntry
	words       map[string][]byte
	credentials map[string]Credential // SAID → the credential as issued
	owner       *Owner
	anchored    bool
	logRows     []sandbox.StoredRow
	asked       []string // the key logs asked for, in order
	fail        map[string]error
	// The credentials the conversation rests on, by role.
	bodyA, grantB, grantC, grantMachine string
}

// issue makes a credential that verifies, so what it names is read the way
// Verify reads it.
func issue(t *testing.T, data, edges string) (string, Credential) {
	t.Helper()
	in := keri.CredentialInput{SchemaSAID: "ESCHEMA", Issuer: root, Data: json.RawMessage(data)}
	if edges != "" {
		in.Source = json.RawMessage(edges)
	}
	raw, err := keri.BuildCredential(in)
	if err != nil {
		t.Fatal(err)
	}
	c, err := keri.VerifyCredential(raw)
	if err != nil {
		t.Fatal(err)
	}
	return c.SAID, Credential{SAID: c.SAID, Raw: base64.StdEncoding.EncodeToString(raw)}
}

func newStore(t *testing.T) *aStore {
	t.Helper()
	s := &aStore{
		words:       map[string][]byte{},
		credentials: map[string]Credential{},
		owner:       &Owner{AID: "EOWNER", Key: "DOWNER"},
		anchored:    true,
		logRows:     []sandbox.StoredRow{{ID: 7}, {ID: 8}},
		fail:        map[string]error{},
	}
	const dt = `"dt":"2026-10-24T00:00:00Z"`
	// A's body credential names the Controller Grant that authorised it, and
	// that grant rests on a request the owner signed.
	var c Credential
	s.grantC, c = issue(t, `{`+dt+`,"request":{"kind":"owner"}}`, "")
	s.credentials[s.grantC] = c
	s.bodyA, c = issue(t, `{`+dt+`}`, `{"authorised_by":{"n":"`+s.grantC+`"}}`)
	s.credentials[s.bodyA] = c
	s.grantB, c = issue(t, `{`+dt+`,"to":"`+agentB+`"}`, "")
	s.credentials[s.grantB] = c
	s.grantMachine, c = issue(t, `{`+dt+`,"controller":"EMACHINE"}`, "")
	s.credentials[s.grantMachine] = c

	s.add(t, root, agentmessage.Record{MessageID: "m1", Kind: "message",
		From: agentmessage.Person("EPERSON"), To: agentA}, "what does the build server run?")
	s.add(t, agentA, agentmessage.Record{MessageID: "m2", Kind: "ask",
		From: agentA, To: agentB, BodyCredential: s.bodyA, GrantSAID: s.grantB}, "what do you run?")
	s.add(t, root, agentmessage.Record{MessageID: "m3", Kind: "message",
		From: agentmessage.Person("EPERSON"), To: agentA,
		ControllerProof: &agentmessage.ControllerProof{Controller: "EMACHINE", ControllerGrant: s.grantMachine}}, "thanks")
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

// The store's side.

func (s *aStore) Entries(context.Context, string) ([]RecordedEntry, error) { return s.entries, nil }

func (s *aStore) Words(_ context.Context, e RecordedEntry) ([]byte, error) {
	w, ok := s.words[e.ContentRef]
	if !ok {
		return nil, errors.New("not kept")
	}
	return w, nil
}

// The Identity Agent's side.

type identityAgent struct{ *aStore }

func (x identityAgent) Anchors(context.Context) (KeyLog, []Anchor, bool, error) {
	if err := x.fail["anchors"]; err != nil {
		return KeyLog{}, nil, false, err
	}
	if !x.anchored {
		return KeyLog{}, nil, false, nil
	}
	return KeyLog{AID: record}, []Anchor{{Seq: 1, Statement: "{}"}}, true, nil
}

func (x identityAgent) Log(context.Context, string) (Log, error) {
	if err := x.fail["log"]; err != nil {
		return Log{}, err
	}
	return Log{Signer: signer, Rows: x.logRows}, nil
}

func (x identityAgent) KeyLog(_ context.Context, aid string) (KeyLog, error) {
	if err := x.fail["keylog "+aid]; err != nil {
		return KeyLog{}, err
	}
	x.asked = append(x.asked, aid)
	return KeyLog{AID: aid}, nil
}

func (x identityAgent) MessagingKeys(_ context.Context, aid string) (didcomm.DID, error) {
	if err := x.fail["messaging "+aid]; err != nil {
		return didcomm.DID{}, err
	}
	return didcomm.DID{AID: aid}, nil
}

func (x identityAgent) Credential(_ context.Context, said string) (Credential, string, error) {
	c, ok := x.credentials[said]
	if !ok {
		return Credential{}, "", errors.New("not on record")
	}
	// A store naming some other SAID for what it hands over is not believed.
	c.SAID = "ESOMETHING_ELSE"
	return c, "EREGISTRY", nil
}

func (x identityAgent) Registry(_ context.Context, said string) (Registry, error) {
	if err := x.fail["registry"]; err != nil {
		return Registry{}, err
	}
	return Registry{SAID: "ESOMETHING_ELSE", Inception: "vcp"}, nil
}

func (x identityAgent) Owner(context.Context) (*Owner, error) { return x.owner, nil }

func (s *aStore) sources() Sources {
	ia := identityAgent{s}
	return Sources{Record: s, Ledger: ia, Identities: ia, Credentials: ia}
}

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
	if len(b.Entries) != 3 || len(b.Anchors) != 1 || len(b.Log.Rows) != 2 || b.Log.Signer != signer {
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
	// the conversation, and the governance log's signer — each asked for once.
	var logs []string
	for _, kl := range b.KeyLogs {
		logs = append(logs, kl.AID)
	}
	if want := []string{record, root, agentA, agentB, signer}; !reflect.DeepEqual(logs, want) {
		t.Fatalf("key logs %v, want %v", logs, want)
	}
	if want := []string{root, agentA, agentB, signer}; !reflect.DeepEqual(s.asked, want) {
		t.Fatalf("key logs asked for %v, want %v", s.asked, want)
	}
	// The grant that authorised A's body is followed, and because it rests on
	// the owner's signed request, the owner comes with it. The machine grant a
	// person's paired machine spoke under comes too.
	var creds []string
	for _, c := range b.Credentials {
		creds = append(creds, c.SAID)
	}
	want := []string{s.bodyA, s.grantB, s.grantMachine, s.grantC}
	sort.Strings(want[:3])
	if !reflect.DeepEqual(creds, want) {
		t.Fatalf("credentials %v, want %v", creds, want)
	}
	if b.Owner == nil || b.Owner.AID != "EOWNER" || len(b.Registries) != 1 || b.Registries[0].SAID != "EREGISTRY" {
		t.Fatalf("owner %+v, registries %+v", b.Owner, b.Registries)
	}
}

func TestTheGrantAPairedMachineSpokeUnderIsCarried(t *testing.T) {
	s := newStore(t)
	delete(s.credentials, s.grantMachine)
	_, err := build(t, s)
	if !errors.Is(err, ErrIncomplete) || !strings.Contains(err.Error(), s.grantMachine) {
		t.Fatalf("a bundle was built without the machine grant a message names: %v", err)
	}
}

func TestTheStoresOwnNameForACredentialIsNotBelieved(t *testing.T) {
	b, err := build(t, newStore(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range b.Credentials {
		if c.SAID == "ESOMETHING_ELSE" {
			t.Fatal("a credential was carried under the name the store gave it")
		}
	}
	for _, r := range b.Registries {
		if r.SAID == "ESOMETHING_ELSE" {
			t.Fatal("a registry was carried under the name the store gave it")
		}
	}
}

func TestARecordNotYetAnchoredCarriesNoAnchors(t *testing.T) {
	s := newStore(t)
	s.anchored = false
	b, err := build(t, s)
	if err != nil {
		t.Fatal(err)
	}
	if b.RecordIdentity != "" || len(b.Anchors) != 0 || b.KeyLogs[0].AID != root {
		t.Fatalf("an unanchored record was exported with anchors: identity %q, %d anchors, first key log %s",
			b.RecordIdentity, len(b.Anchors), b.KeyLogs[0].AID)
	}
}

func TestWhatTheIdentityAgentCannotShowFailsTheBundle(t *testing.T) {
	for name, key := range map[string]string{
		"the anchors":                     "anchors",
		"the governance log":              "log",
		"a registry":                      "registry",
		"an AI agent's key log":           "keylog " + agentB,
		"the governance log signer's log": "keylog " + signer,
		"an AI agent's messaging keys":    "messaging " + agentA,
		"the root's messaging keys":       "messaging " + root,
	} {
		t.Run(name, func(t *testing.T) {
			s := newStore(t)
			s.fail[key] = errors.New("cannot be had")
			_, err := build(t, s)
			if !errors.Is(err, ErrIncomplete) || !strings.Contains(err.Error(), "cannot be had") {
				t.Fatalf("a bundle was built without %s: %v", name, err)
			}
			if strings.Count(err.Error(), ErrIncomplete.Error()) != 1 {
				t.Fatalf("the error says it is incomplete more than once: %v", err)
			}
		})
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
	delete(s.credentials, s.grantC)
	_, err := build(t, s)
	if !errors.Is(err, ErrIncomplete) || !strings.Contains(err.Error(), s.grantC) {
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
