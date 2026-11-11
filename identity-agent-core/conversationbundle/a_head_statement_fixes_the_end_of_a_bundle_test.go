package conversationbundle

import (
	"strings"
	"testing"
	"time"

	"identity-agent-core/agentmessage"
	"identity-agent-core/didcomm"
)

// An export carries the Identity Agent's signed head statement, so a reader can
// see an end that was cut off, which no anchor shows (ADR-068).

func (c *conversation) signHead(t *testing.T, conversation string, count int, head string, at time.Time) *didcomm.Envelope {
	t.Helper()
	env, err := SignHead(rootAID, func(m *didcomm.JWM) (*didcomm.Envelope, error) { return didcomm.PackSigned(c.keys, m) },
		HeadStatement{Conversation: conversation, Count: count, Head: head, IATime: at.UTC().Format(time.RFC3339Nano)})
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func (c *conversation) checkHead(b *Bundle) *verifier {
	if b.ExportedAt == "" {
		b.ExportedAt = c.now.Add(time.Minute).UTC().Format(time.RFC3339Nano)
	}
	did, err := c.keys.DID()
	if err != nil {
		c.t.Fatal(err)
	}
	v := newVerifier()
	v.b, v.hashes, v.signedOnce, v.answered, v.notes = b, map[int]string{}, map[string]int{}, map[string]bool{}, map[string]bool{}
	v.dids = map[string]*didcomm.DID{rootAID: did}
	v.r = &Report{}
	v.openHead()
	v.checkEntries()
	v.checkHead()
	return v
}

func TestAHeadStatementHoldsTheEntriesToTheHeadItSigned(t *testing.T) {
	c := newConversation(t)
	writeMixed(c)
	n := len(c.chain)
	head := c.chain[n-1].Hash
	at := c.now

	good := c.bundle(false)
	good.Head = c.signHead(t, "c1", n, head, at)
	if v := c.checkHead(good); len(v.r.Faults) != 0 {
		t.Fatalf("a bundle that ends at its head has faults: %s", openingFaults(v))
	}

	// The end cut off: the statement says more than the bundle holds. Without
	// the statement the cut bundle verifies, which is what it is for.
	cut := c.bundle(false)
	cut.Entries = cut.Entries[:n-2]
	if v := c.check(cut); len(v.r.Faults) != 0 {
		t.Fatalf("an entry cut off the end is a fault without the head: %s", openingFaults(v))
	}
	cut.Head = good.Head
	if v := c.checkHead(cut); !strings.Contains(openingFaults(v), "removed from the end") {
		t.Fatalf("an entry cut off the end was not caught: %q", openingFaults(v))
	}

	// Another entry in the last place: the right count, another head.
	swapped := c.bundle(false)
	swapped.Head = c.signHead(t, "c1", n, "Eanotherhead", at)
	if v := c.checkHead(swapped); !strings.Contains(openingFaults(v), "substituted") {
		t.Fatalf("a substituted end was not caught: %q", openingFaults(v))
	}

	// An entry past the count was never committed: it is left out, and the
	// bundle still matches the head.
	c.say("EALICE", "five", nil)
	past := c.bundle(false)
	past.Head = good.Head
	if v := c.checkHead(past); len(v.r.Faults) != 0 {
		t.Fatalf("an entry committed after the statement is a fault: %s", openingFaults(v))
	}
}

func TestAHeadStatementIsTheIdentityAgentsAndThisConversations(t *testing.T) {
	c := newConversation(t)
	writeMixed(c)
	n := len(c.chain)
	head := c.chain[n-1].Hash

	other, err := didcomm.GenerateKeySet(rootAID)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := SignHead(rootAID, func(m *didcomm.JWM) (*didcomm.Envelope, error) { return didcomm.PackSigned(other, m) },
		HeadStatement{Conversation: "c1", Count: n, Head: head, IATime: c.now.UTC().Format(time.RFC3339Nano)})
	if err != nil {
		t.Fatal(err)
	}
	b := c.bundle(false)
	b.Head = forged
	if v := c.checkHead(b); len(v.r.Faults) == 0 {
		t.Fatal("a head statement signed by another key was accepted")
	}

	b = c.bundle(false)
	b.Head = c.signHead(t, "c2", n, head, c.now)
	if v := c.checkHead(b); !strings.Contains(openingFaults(v), "not c1") {
		t.Fatalf("a head statement for another conversation was accepted: %q", openingFaults(v))
	}

	// A statement is not an entry: it cannot be taken for one in the chain.
	entry := c.chain[0].Envelope
	if _, err := OpenHead(mustDID(t, c), entry); err == nil {
		t.Fatal("an entry was opened as a head statement")
	}
	// A countersigned entry of the chain is not a head statement's type.
	if _, err := agentmessage.Open(mustDID(t, c), c.signHead(t, "c1", n, head, c.now)); err == nil {
		t.Fatal("a head statement was opened as an entry")
	}

	// A statement dated after the export is a fault.
	b = c.bundle(false)
	b.ExportedAt = c.now.UTC().Format(time.RFC3339Nano)
	b.Head = c.signHead(t, "c1", n, head, c.now.Add(time.Hour))
	if v := c.checkHead(b); !strings.Contains(openingFaults(v), "after the export") {
		t.Fatalf("a statement dated after the export was accepted: %q", openingFaults(v))
	}
}

func TestABundleWithNoHeadStatementSaysItCannotRuleOutAnEndCutOff(t *testing.T) {
	c := newConversation(t)
	writeMixed(c)
	v := c.checkHead(c.bundle(false))
	if len(v.r.Faults) != 0 || !strings.Contains(strings.Join(v.r.CannotRuleOut, "\n"), "cut off the end") {
		t.Fatalf("faults %s, notes %v", openingFaults(v), v.r.CannotRuleOut)
	}
}

func TestAHeadStatementNamesAHeadExactlyWhenThereIsACount(t *testing.T) {
	c := newConversation(t)
	pack := func(m *didcomm.JWM) (*didcomm.Envelope, error) { return didcomm.PackSigned(c.keys, m) }
	for _, h := range []HeadStatement{{Conversation: "c1", Count: 0, Head: "Ex"}, {Conversation: "c1", Count: 2}, {Count: 0}, {Conversation: "c1", Count: -1, Head: "Ex"}} {
		if _, err := SignHead(rootAID, pack, h); err == nil {
			t.Errorf("%+v was signed", h)
		}
	}
	if _, err := SignHead(rootAID, pack, HeadStatement{Conversation: "c1"}); err != nil {
		t.Errorf("an empty conversation's statement was refused: %v", err)
	}
}

func mustDID(t *testing.T, c *conversation) *didcomm.DID {
	t.Helper()
	d, err := c.keys.DID()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// The entries past the head's count are not part of the conversation the report
// lists, and are only counted.
func TestEntriesPastTheHeadsCountAreNotListedAsMessages(t *testing.T) {
	c := newConversation(t)
	writeMixed(c)
	n := len(c.chain)
	head := c.chain[n-1].Hash
	c.say("EALICE", "after the statement", nil)

	b := c.bundle(false)
	b.Head = c.signHead(t, "c1", n, head, c.now)
	v := c.checkHead(b)
	if len(v.r.Faults) != 0 || len(v.r.Messages) != n || v.r.UncommittedEntries != len(b.Entries)-n {
		t.Fatalf("faults %q, %d messages (want %d), %d uncommitted", openingFaults(v), len(v.r.Messages), n, v.r.UncommittedEntries)
	}
	if !strings.Contains(Report{UncommittedEntries: 2}.Text(), "not committed") {
		t.Fatal("the report does not say entries were left out")
	}
}

// Verify itself reads the head statement: one it cannot check is a fault in its
// report, and a bundle without one says it cannot rule out an end cut off.
func TestVerifyRunsTheHeadCheck(t *testing.T) {
	_, b := theVector(t)
	with := *b
	other, err := didcomm.GenerateKeySet(b.Root)
	if err != nil {
		t.Fatal(err)
	}
	with.Head, err = SignHead(b.Root, func(m *didcomm.JWM) (*didcomm.Envelope, error) { return didcomm.PackSigned(other, m) },
		HeadStatement{Conversation: b.Conversation, Count: len(b.Entries), Head: "Ex", IATime: time.Now().UTC().Format(time.RFC3339Nano)})
	if err != nil {
		t.Fatal(err)
	}
	r := Verify(&with)
	found := false
	for _, f := range r.Faults {
		found = found || f.Where == "head statement"
	}
	if r.Verified || !found {
		t.Fatalf("a head statement signed by another key did not fail Verify: %+v", r.Faults)
	}
}

func TestOpenHeadRefusesAnotherMessageTypeAndAnotherId(t *testing.T) {
	c := newConversation(t)
	did := mustDID(t, c)
	pack := func(typ, id string) *didcomm.Envelope {
		body := []byte(`{"conversation":"c1","count":1,"head":"Ex","ia_time":"` + c.now.UTC().Format(time.RFC3339Nano) + `"}`)
		env, err := didcomm.PackSigned(c.keys, &didcomm.JWM{ID: id, Type: typ, From: "did:keri:" + rootAID, To: []string{"did:keri:" + rootAID}, CreatedTime: c.now.UTC().Format(time.RFC3339Nano), Body: body})
		if err != nil {
			t.Fatal(err)
		}
		return env
	}
	if _, err := OpenHead(did, pack(TypeTrailHead, "trail-head:c1:1")); err != nil {
		t.Fatalf("a good statement was refused: %v", err)
	}
	if _, err := OpenHead(did, pack("something-else", "trail-head:c1:1")); err == nil {
		t.Error("a message of another type was opened as a head statement")
	}
	if _, err := OpenHead(did, pack(TypeTrailHead, "trail-head:c1:2")); err == nil {
		t.Error("a head statement with an id that is not the one its body gives was accepted")
	}
}
