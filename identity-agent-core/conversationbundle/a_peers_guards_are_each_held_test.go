package conversationbundle

import (
	"strings"
	"testing"

	"identity-agent-core/agentmessage"
	"identity-agent-core/agentpeer"
)

// Each guard on an entry from an AI agent another Identity Agent holds has a test that
// fails without it.

func peerOpening(mut func(*agentmessage.Record)) agentmessage.Record {
	from := agentmessage.Peer("EBETA", "EREV")
	r := agentmessage.Record{MessageID: "m1", Seq: 1, Kind: agentmessage.KindAsk, From: from, To: "EWORKER",
		OpenedBy: from, Depth: 1, PeerProof: &agentpeer.Signed{}}
	if mut != nil {
		mut(&r)
	}
	return r
}

func TestAConversationAnotherIdentityAgentOpensBeginsWithItsAskAtDepthOne(t *testing.T) {
	v := newVerifier()
	v.checkOpening("entry 1", peerOpening(nil))
	if len(v.r.Faults) != 0 {
		t.Fatalf("a proper opening faulted: %s", openingFaults(v))
	}
	for name, mut := range map[string]func(*agentmessage.Record){
		"at depth 2":          func(r *agentmessage.Record) { r.Depth = 2 },
		"as the second entry": func(r *agentmessage.Record) { r.Seq = 2 },
		"opened by a local AI agent": func(r *agentmessage.Record) {
			r.From, r.OpenedBy = "ELOCAL", "ELOCAL"
		},
	} {
		v := newVerifier()
		v.checkOpening("entry 1", peerOpening(mut))
		if len(v.r.Faults) == 0 {
			t.Errorf("an opening %s was accepted", name)
		}
	}
}

// An AI agent this Identity Agent holds may not ask a third Identity Agent's AI
// agent inside a conversation another Identity Agent's AI agent opened, and an
// AI agent that opened a chain must itself hold a grant naming the contact.
func TestAnAskToAThirdIdentityAgentInAPeersConversationIsAFault(t *testing.T) {
	grant := peerGrant([]string{agentpeer.CapabilityMessagePeer}, map[string]interface{}{
		agentpeer.CapabilityMessagePeer:    map[string]interface{}{agentpeer.ConstraintContact: []string{"EGAMMA"}},
		agentmessage.CapabilityMessageOpen: map[string]interface{}{"per_hour": 6}})
	ask := agentmessage.Record{MessageID: "m3", Seq: 3, Kind: agentmessage.KindAsk, From: "EA",
		To: agentmessage.Peer("EGAMMA", "EX"), GrantSAID: "Egrant_a", IATime: "2026-11-02T10:00:00Z",
		OpenedBy: agentmessage.Peer("EBETA", "EREV"), Depth: 2,
		Statement: &agentmessage.Statement{Kind: agentmessage.KindAsk, From: "EA", To: agentmessage.Peer("EGAMMA", "EX"), Conversation: "c1"}}
	v := newVerifier()
	v.checkAskAllowed("entry 3", grant, ask, []byte("words"))
	if !strings.Contains(openingFaults(v), "not passed on to a third") {
		t.Fatalf("an ask to a third Identity Agent in a conversation another one opened: %q", openingFaults(v))
	}
	// The same ask in a conversation an AI agent this Identity Agent holds opened is
	// judged by the grant alone.
	ask.OpenedBy = "EA"
	v = newVerifier()
	v.checkAskAllowed("entry 3", grant, ask, []byte("words"))
	if f := openingFaults(v); strings.Contains(f, "third") || f != "" {
		t.Fatalf("a grant naming the contact was refused: %q", f)
	}
	// A grant that does not name that contact reaches it neither.
	v = newVerifier()
	v.checkAskAllowed("entry 3", peerGrant([]string{agentpeer.CapabilityMessagePeer}, map[string]interface{}{
		agentpeer.CapabilityMessagePeer:    map[string]interface{}{agentpeer.ConstraintContact: []string{"EDELTA"}},
		agentmessage.CapabilityMessageOpen: map[string]interface{}{"per_hour": 6}}), ask, []byte("words"))
	if openingFaults(v) == "" {
		t.Fatal("a grant naming another contact reached a third")
	}
}

func TestAnOpenersGrantMustAlsoNameThePeerContact(t *testing.T) {
	opener := agentmessage.Record{MessageID: "m1", From: "EOPEN", GrantSAID: "Egrant_opener"}
	narrow := peerGrant([]string{agentpeer.CapabilityMessagePeer}, map[string]interface{}{
		agentpeer.CapabilityMessagePeer: map[string]interface{}{agentpeer.ConstraintContact: []string{"EDELTA"}}})
	narrow.said, narrow.holder = "Egrant_opener", "EOPEN"
	v := newVerifier()
	v.opener = opener
	v.creds["Egrant_opener"] = narrow
	rec := agentmessage.Record{MessageID: "m3", Seq: 3, To: agentmessage.Peer("EBETA", "EREV"), GrantSAID: "Egrant_other", IATime: "2026-11-02T10:00:00Z"}
	v.checkOpenerReach("entry 3", rec, func(l map[string]interface{}) error { return agentpeer.CheckPeerGrant(l, "EBETA", "EREV") })
	if !strings.Contains(openingFaults(v), "opener") {
		t.Fatalf("an opener whose grant does not name the contact was let reach it: %q", openingFaults(v))
	}
}

// Words of an entry from another Identity Agent may be left out; when they are
// carried the salt comes with them and the fingerprint is the signed one.
func TestThePeerWordsAreCarriedWithTheirSaltOrNotAtAll(t *testing.T) {
	rec := agentmessage.Record{BodyHash: "Eanything"}
	words := []byte("hello")
	for name, c := range map[string]struct {
		e       Entry
		body    []byte
		bodyErr error
	}{
		"words without a salt":      {Entry{}, words, nil},
		"an unreadable salt":        {Entry{Salt: "***"}, words, nil},
		"a salt for other words":    {Entry{Salt: encodeWords("0123456789abcdef")}, words, nil},
		"words too long":            {Entry{Salt: encodeWords("0123456789abcdef")}, make([]byte, agentmessage.MaxBody+1), nil},
		"words that cannot be read": {Entry{}, nil, errBad},
	} {
		v := newVerifier()
		v.checkPeerWords("entry 1", rec, c.e, c.body, c.bodyErr)
		if len(v.r.Faults) == 0 {
			t.Errorf("%s was accepted", name)
		}
	}
	v := newVerifier()
	v.checkPeerWords("entry 1", rec, Entry{}, nil, nil)
	if len(v.r.Faults) != 0 {
		t.Fatal("words left out were refused")
	}
}

var errBad = errString("unreadable")

type errString string

func (e errString) Error() string { return string(e) }
