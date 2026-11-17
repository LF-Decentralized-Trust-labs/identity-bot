package server

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"identity-agent-core/agentpeer"
	"identity-agent-core/didcomm"
	"identity-agent-core/store"
)

type peerFixture struct {
	s      *CoreServer
	theirs *didcomm.KeySet
	taken  []agentpeer.Statement
}

// A receiver that knows one other Identity Agent's keys, and a keeper that records what it is given.
func newPeerFixture(t *testing.T, status string, keeper bool) *peerFixture {
	t.Helper()
	f := &peerFixture{s: agentWithDerivedIdentity(t)}
	ks, err := didcomm.GenerateKeySet("EBETA")
	if err != nil {
		t.Fatal(err)
	}
	f.theirs = ks
	did, _ := ks.DID()
	if status != "" {
		_ = f.s.DataStore.SaveContact(store.ContactRecord{AID: "EBETA", Status: status})
	}
	if status != "" {
		didcommMu.Lock()
		peers, _ := f.s.loadPeers()
		peers["EBETA"] = peerRecord{AID: "EBETA", DID: *did}
		_ = f.s.savePeers(peers)
		didcommMu.Unlock()
	}
	if keeper {
		f.s.OnAgentPeerMessage(func(_ string, st agentpeer.Statement, _ agentpeer.Message) error {
			f.taken = append(f.taken, st)
			return nil
		})
	}
	return f
}

func (f *peerFixture) deliver(t *testing.T, to string) error {
	t.Helper()
	m, err := agentpeer.Seal(f.theirs, agentpeer.Statement{Kind: agentpeer.KindAsk, ToAID: to, FromAgent: "EREVIEWER", ToAgent: "EALPHAAGENT", MessageID: "m-1"}, "hello", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(m)
	return (agentPeerMessage{}).Perform(f.s, InboundMessage{FromAID: "EBETA", ToAID: to, Body: body})
}

// An accepted contact's message, for this Identity Agent, reaches the keeper with
// the statement read from what was signed.
func TestAnAcceptedContactsPeerMessageReachesTheKeeper(t *testing.T) {
	f := newPeerFixture(t, "accepted", true)
	if err := f.deliver(t, "ETHISORG"); err != nil {
		t.Fatalf("a good message was refused: %v", err)
	}
	if len(f.taken) != 1 || f.taken[0].FromAID != "EBETA" || f.taken[0].ToAgent != "EALPHAAGENT" {
		t.Fatalf("the keeper was given %+v", f.taken)
	}
}

// Nothing is taken unless someone keeps AI agents' conversations here.
func TestWithNoKeeperNoPeerMessageIsTaken(t *testing.T) {
	f := newPeerFixture(t, "accepted", false)
	if err := f.deliver(t, "ETHISORG"); err == nil || !strings.Contains(err.Error(), "keeps no AI agents") {
		t.Fatalf("got %v", err)
	}
}

// Only an accepted contact may send one: a stranger, and a contact that asked
// to connect and was not agreed, are refused before the message is read.
func TestOnlyAnAcceptedContactMayMessageOurAIAgents(t *testing.T) {
	for status, want := range map[string]string{"": "not a contact", "pending_inbound": "not accepted", "pending_outbound": "not accepted"} {
		f := newPeerFixture(t, status, true)
		err := f.deliver(t, "ETHISORG")
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("status %q: got %v, want it to say %q", status, err, want)
		}
		if len(f.taken) != 0 {
			t.Errorf("status %q: the keeper was given a message", status)
		}
	}
}

// A message signed for another Identity Agent than this one is not kept, and neither is one
// from keys that are not the contact's.
func TestAPeerMessageForAnotherIdentityAgentOrByOtherKeysIsNotKept(t *testing.T) {
	f := newPeerFixture(t, "accepted", true)
	m, _ := agentpeer.Seal(f.theirs, agentpeer.Statement{Kind: agentpeer.KindAsk, ToAID: "ESOMEONEELSE", FromAgent: "A", ToAgent: "B", MessageID: "m-2"}, "hi", time.Now())
	body, _ := json.Marshal(m)
	if err := (agentPeerMessage{}).Perform(f.s, InboundMessage{FromAID: "EBETA", ToAID: "ETHISORG", Body: body}); err != agentpeer.ErrWrongRecipient {
		t.Fatalf("a message for another Identity Agent: %v", err)
	}
	impostor, _ := didcomm.GenerateKeySet("EBETA")
	m, _ = agentpeer.Seal(impostor, agentpeer.Statement{Kind: agentpeer.KindAsk, ToAID: "ETHISORG", FromAgent: "A", ToAgent: "B", MessageID: "m-3"}, "hi", time.Now())
	body, _ = json.Marshal(m)
	if err := (agentPeerMessage{}).Perform(f.s, InboundMessage{FromAID: "EBETA", ToAID: "ETHISORG", Body: body}); err != agentpeer.ErrNotSigned {
		t.Fatalf("a message signed by other keys: %v", err)
	}
	if len(f.taken) != 0 {
		t.Fatalf("the keeper was given %+v", f.taken)
	}
}

// The action is reachable: registered for a type the envelope carries.
func TestThePeerMessageActionIsDeliverable(t *testing.T) {
	if _, ok := lookupInboundAction(didcomm.TypeAgentPeerMessage); !ok {
		t.Fatal("no action is registered for agent-peer-message")
	}
	if !didcomm.KnownType(didcomm.TypeAgentPeerMessage) {
		t.Fatal("the envelope does not carry agent-peer-message")
	}
}

// A contact's directory reaches whoever keeps AI agents only from an accepted
// contact, only when its names can be shown as they stand, and not at all when
// nobody keeps AI agents here.
func TestAContactsDirectoryIsKeptOnlyFromAnAcceptedContact(t *testing.T) {
	var kept []agentpeer.Directory
	keep := func(f *peerFixture) *peerFixture {
		f.s.OnAgentPeerDirectory(func(from string, d agentpeer.Directory) error {
			if from != "EBETA" {
				t.Errorf("kept as from %s", from)
			}
			kept = append(kept, d)
			return nil
		})
		return f
	}
	send := func(f *peerFixture, d agentpeer.Directory) error {
		body, _ := json.Marshal(d)
		return (agentPeerDirectory{}).Perform(f.s, InboundMessage{FromAID: "EBETA", ToAID: "ETHISORG", Body: body})
	}
	good := agentpeer.Directory{Agents: []agentpeer.DirectoryEntry{{AID: "EREVIEWER", Name: "reviewer"}}}
	if err := send(newPeerFixture(t, "accepted", false), good); err == nil || !strings.Contains(err.Error(), "keeps no AI agents") {
		t.Fatalf("with nobody to keep it: %v", err)
	}
	f := keep(newPeerFixture(t, "accepted", true))
	if err := send(f, good); err != nil {
		t.Fatalf("a good directory: %v", err)
	}
	if len(kept) != 1 || kept[0].Agents[0].Name != "reviewer" {
		t.Fatalf("kept %+v", kept)
	}
	if err := send(f, agentpeer.Directory{Agents: []agentpeer.DirectoryEntry{{AID: "E1", Name: "boss@alias"}}}); err == nil {
		t.Fatal("a name that reads as an alias was kept")
	}
	if err := send(keep(newPeerFixture(t, "pending_inbound", true)), good); err == nil {
		t.Fatal("a directory from a contact that is not accepted was kept")
	}
	if len(kept) != 1 {
		t.Fatalf("a refused directory reached the keeper: %+v", kept)
	}
	if _, ok := lookupInboundAction(didcomm.TypeAgentPeerDirectory); !ok {
		t.Fatal("no action is registered for agent-peer-directory")
	}
}
