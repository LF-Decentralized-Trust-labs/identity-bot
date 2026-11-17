package agentmessage

import (
	"testing"
	"time"

	"identity-agent-core/agentpeer"
	"identity-agent-core/didcomm"
	"identity-agent-core/fingerprint"
)

func TestAPeerAIAgentIsAPartyThatThisIdentityAgentCountersignsFor(t *testing.T) {
	p := Peer("EHOLDER", "EAGENT")
	if holder, ag, ok := IsPeer(p); !ok || holder != "EHOLDER" || ag != "EAGENT" {
		t.Fatalf("read back %q %q %v", holder, ag, ok)
	}
	for _, bad := range []string{"EHOLDER", "peer:EHOLDER", "peer:/A", "peer:O/", "peer:O/A/B", "person:X"} {
		if _, _, ok := IsPeer(bad); ok {
			t.Errorf("%q read as a peer", bad)
		}
	}
	if Countersigner(p, "EROOT") != "EROOT" {
		t.Fatal("a peer's entry is countersigned by the AI agent's own keys, which this Identity Agent does not hold")
	}
	if Countersigner("EAGENT", "EROOT") != "EAGENT" {
		t.Fatal("a local AI agent's countersigner changed")
	}
}

func TestTheBoundIsTheOneThePeerPackageSigns(t *testing.T) {
	if agentpeer.MaxWords != MaxBody {
		t.Fatal("agentpeer's bound has drifted from agentmessage's")
	}
	salt := []byte("0123456789abcdef")
	want, _ := Fingerprint(salt, []byte("x"))
	if got, _ := fingerprint.Of(salt, []byte("x")); got != want {
		t.Fatal("the fingerprint a peer's message carries is not the one a person's statement does")
	}
}

func peerRecord(t *testing.T, words string) (Record, *didcomm.KeySet) {
	t.Helper()
	ks, err := didcomm.GenerateKeySet("EBETA")
	if err != nil {
		t.Fatal(err)
	}
	m, err := agentpeer.Seal(ks, agentpeer.Statement{Kind: agentpeer.KindAsk, ToAID: "EALPHA", FromAgent: "EREV", ToAgent: "EWORKER", MessageID: "m_1"}, words, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	did, _ := ks.DID()
	stmt, err := agentpeer.ReadStatement(m.Signed, did)
	if err != nil {
		t.Fatal(err)
	}
	return Record{MessageID: "m_1", Conversation: "c_1", Seq: 1, Kind: KindAsk, From: Peer("EBETA", "EREV"), To: "EWORKER",
		BodyHash: stmt.Fingerprint, OpenedBy: Peer("EBETA", "EREV"), PeerProof: &m.Signed}, ks
}

func TestAPeersEntryHoldsOnlyWithThatIdentityAgentsKeysAndWhatItSigned(t *testing.T) {
	r, ks := peerRecord(t, "hello")
	did, _ := ks.DID()
	if err := r.CheckPeerProof(did, "EALPHA"); err != nil {
		t.Fatalf("a good entry: %v", err)
	}
	if r.CheckSenderProof() == nil {
		t.Fatal("without the sending Identity Agent's keys the entry was believed")
	}
	other, _ := didcomm.GenerateKeySet("EBETA")
	odid, _ := other.DID()
	if r.CheckPeerProof(odid, "EALPHA") == nil {
		t.Fatal("other keys vouched for the sending Identity Agent")
	}
	for name, edit := range map[string]func(*Record){
		"another AI agent": func(r *Record) { r.To = "EOTHER" },
		"other words":      func(r *Record) { r.BodyHash, _ = Fingerprint([]byte("0123456789abcdef"), []byte("other")) },
		"another sender":   func(r *Record) { r.From = Peer("EBETA", "EIMPOSTOR") },
		"another message":  func(r *Record) { r.MessageID = "m_2" },
		"another kind":     func(r *Record) { r.Kind = KindReceipt },
		"a second proof":   func(r *Record) { r.PersonProof = &PersonProof{} },
	} {
		c := r
		edit(&c)
		if c.CheckPeerProof(did, "EALPHA") == nil {
			t.Errorf("%s: the record was believed", name)
		}
	}
}

func TestAPeersEntryIsForThisIdentityAgentAndFromAnother(t *testing.T) {
	r, ks := peerRecord(t, "hello")
	did, _ := ks.DID()
	if r.CheckPeerProof(did, "ESOMEONEELSE") == nil {
		t.Fatal("an entry signed for another Identity Agent was believed as this one's")
	}
	if r.CheckPeerProof(did, "EBETA") == nil {
		t.Fatal("an Identity Agent's statement to itself was believed")
	}
}

// Each equality CheckPeerProof makes is its own guard.
func TestAPeersEntryMustSayTheAnswerItNamesAndComeFromAnotherIdentityAgent(t *testing.T) {
	ks, _ := didcomm.GenerateKeySet("EBETA")
	did, _ := ks.DID()
	m, err := agentpeer.Seal(ks, agentpeer.Statement{Kind: agentpeer.KindReply, ToAID: "EALPHA", FromAgent: "EREV", ToAgent: "EWORKER", MessageID: "m_2", InReplyTo: "m_1"}, "done", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	stmt, _ := agentpeer.ReadStatement(m.Signed, did)
	r := Record{MessageID: "m_2", Conversation: "c_1", Seq: 2, Kind: KindReply, From: Peer("EBETA", "EREV"), To: "EWORKER",
		InReplyTo: "m_1", BodyHash: stmt.Fingerprint, OpenedBy: "EWORKER", PeerProof: &m.Signed}
	if err := r.CheckPeerProof(did, "EALPHA"); err != nil {
		t.Fatal(err)
	}
	c := r
	c.InReplyTo = "m_9"
	if c.CheckPeerProof(did, "EALPHA") == nil {
		t.Error("an entry answering another message than the one signed was believed")
	}
	c = r
	c.Kind = KindFailure
	if c.CheckPeerProof(did, "EALPHA") == nil {
		t.Error("an entry of another kind than the one signed was believed")
	}
}
