package conversationbundle

import (
	"bytes"
	"crypto/ed25519"
	"identity-agent-core/agentbody"
	"identity-agent-core/didcomm"
	"strings"
	"testing"
	"time"

	"identity-agent-core/agentmessage"
)

// A close is an entry of the one chain: a trail shows who closed a conversation
// and what ended under it. These write a conversation by hand and check it
// whole, through the verifier's entry checks.
func TestACloseInTheChainIsCheckedWhole(t *testing.T) {
	asAsk := func(s *agentmessage.PersonStatement) { s.Kind = agentmessage.PersonKindAsk }
	asClose := func(s *agentmessage.PersonStatement) { s.Kind, s.To = agentmessage.PersonKindClose, "" }
	asReopen := func(s *agentmessage.PersonStatement) { s.Kind, s.To = agentmessage.PersonKindReopen, "" }
	asLimit := func(s *agentmessage.PersonStatement) { s.Kind, s.To = agentmessage.PersonKindLimit, "" }

	t.Run("the opener closes, an ask after it is refused, a reopen lets it go on", func(t *testing.T) {
		c := newConversation(t)
		c.say("EALICE", "one", asAsk)
		c.say("EALICE", "", asClose)
		if v := c.check(c.bundle(true)); len(v.r.Faults) != 0 {
			t.Fatalf("a close by the opener has faults: %s", openingFaults(v))
		}
		c.say("EALICE", "again", asAsk)
		if got := openingFaults(c.check(c.bundle(true))); !strings.Contains(got, "closed and not reopened") {
			t.Fatalf("an ask after a close was not caught: %q", got)
		}
		c = newConversation(t)
		c.say("EALICE", "one", asAsk)
		c.say("EALICE", "", asClose)
		c.say("EALICE", "", asReopen)
		c.say("EALICE", "two", asAsk)
		c.say("EALICE", "80", asLimit)
		if v := c.check(c.bundle(true)); len(v.r.Faults) != 0 {
			t.Fatalf("close, reopen, ask and limit have faults: %s", openingFaults(v))
		}
	})
	t.Run("a close the Identity Agent refused changes nothing", func(t *testing.T) {
		c := newConversation(t)
		c.say("EALICE", "one", asAsk)
		c.say("EBOB", "", asClose) // refused: only the owner of the conversation may write
		c.say("EALICE", "two", asAsk)
		if v := c.check(c.bundle(true)); len(v.r.Faults) != 0 {
			t.Fatalf("a refused close was taken for a close: %s", openingFaults(v))
		}
	})
	// The harness has no key log for the AI agent an outcome is addressed to, so
	// the one fault that names it is set aside; any other fault is kept.
	without := func(v *verifier) string {
		var keep []string
		for _, f := range v.r.Faults {
			if !strings.Contains(f.Why, "no verified key log for EBOT") {
				keep = append(keep, f.Where+": "+f.Why)
			}
		}
		return strings.Join(keep, "\n")
	}
	t.Run("an ask unanswered when the conversation closed ends once, and only then", func(t *testing.T) {
		c := newConversation(t)
		e := c.say("EALICE", "one", asAsk)
		ended := func() {
			c.append(agentmessage.Record{Kind: agentmessage.KindOutcome, From: rootAID, To: "EBOT", InReplyTo: e.EntryID,
				BodyHash: agentmessage.HashBody(nil), Outcome: &agentmessage.Outcome{Entry: e.EntryID, State: agentmessage.OutcomeClosedUnanswered}})
		}
		ended() // before any close
		if got := without(c.check(c.bundle(true))); !strings.Contains(got, "the conversation is not closed") {
			t.Fatalf("an outcome of a close, with no close: %q", got)
		}
		c = newConversation(t)
		e = c.say("EALICE", "one", asAsk)
		c.say("EALICE", "", asClose)
		ended()
		if got := without(c.check(c.bundle(true))); got != "" {
			t.Fatalf("the outcome of a close has faults: %s", got)
		}
		ended()
		if got := without(c.check(c.bundle(true))); !strings.Contains(got, "ends so once") {
			t.Fatalf("a second outcome for one ask: %q", got)
		}
	})
}

// An ask whose body was lost ends once, in a conversation still open, and the
// one who asked is the one told.
func TestAnAskWhoseBodyWasLostEndsOnceAndTellsTheAsker(t *testing.T) {
	asAsk := func(s *agentmessage.PersonStatement) { s.Kind = agentmessage.PersonKindAsk }
	c := newConversation(t)
	e := c.say("EALICE", "one", asAsk)
	lost := func(to string) {
		c.append(agentmessage.Record{Kind: agentmessage.KindOutcome, From: rootAID, To: to, InReplyTo: e.EntryID,
			BodyHash: agentmessage.HashBody(nil), Outcome: &agentmessage.Outcome{Entry: e.EntryID, State: agentmessage.OutcomeBodyLost, Reason: "its machine was lost"}})
	}
	lost(agentmessage.Person("EALICE"))
	if v := c.check(c.bundle(true)); len(v.r.Faults) != 0 {
		t.Fatalf("a lost body's outcome, to the asker, has faults: %s", openingFaults(v))
	}
	lost(agentmessage.Person("EALICE"))
	if got := openingFaults(c.check(c.bundle(true))); !strings.Contains(got, "ends so once") {
		t.Fatalf("a second outcome for one ask: %q", got)
	}
	c = newConversation(t)
	e = c.say("EALICE", "one", asAsk)
	lost("EBOT")
	if got := openingFaults(c.check(c.bundle(true))); !strings.Contains(got, "the one who asked") {
		t.Fatalf("an outcome that is not addressed to the asker: %q", got)
	}
}

// An AI agent receipts an outcome it was handed, and the receipt is addressed to
// the Identity Agent whose entry it received. That Identity Agent is the root,
// not a delegate of it, so addressing it is not a fault of its own.
func TestAReceiptForTheIdentityAgentsOwnEntryIsNotFaultedForWhoItIsTo(t *testing.T) {
	c := newConversation(t)
	e := c.say("EALICE", "one", func(s *agentmessage.PersonStatement) { s.Kind = agentmessage.PersonKindAsk })
	c.append(agentmessage.Record{Kind: agentmessage.KindOutcome, From: rootAID, To: "EBOT", InReplyTo: e.EntryID,
		BodyHash: agentmessage.HashBody(nil), Outcome: &agentmessage.Outcome{Entry: e.EntryID, State: agentmessage.OutcomeClosedUnanswered}})
	botKeys, err := didcomm.GenerateKeySet("EBOT")
	if err != nil {
		t.Fatal(err)
	}
	botDID, err := botKeys.DID()
	if err != nil {
		t.Fatal(err)
	}
	receipt := agentmessage.Record{Conversation: "c1", Seq: len(c.chain) + 1, PrevHash: c.chain[len(c.chain)-1].Hash,
		IATime: c.now.Add(time.Second).UTC().Format(time.RFC3339Nano), MessageID: "m-receipt", OpenedBy: agentmessage.Person("EALICE"),
		Kind: agentmessage.KindReceipt, From: "EBOT", To: rootAID, InReplyTo: agentmessage.EntryID(len(c.chain)), BodyHash: agentmessage.HashBody(nil)}
	signer := edSigner{ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))}
	host, verkey, _ := agentbody.Identity(signer)
	st := agentmessage.Statement{Conversation: "c1", Kind: agentmessage.KindReceipt, From: "EBOT", To: rootAID, InReplyTo: receipt.InReplyTo,
		BodyHash: receipt.BodyHash, Host: host, HostNonce: "nonce-0123456789abcdef", HostTime: c.now.Format(time.RFC3339), BodyCredential: "ECRED"}
	sig, err := agentmessage.Sign(signer, st)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Statement, receipt.HostSignature, receipt.HostVerkey, receipt.BodyCredential = &st, sig, verkey, "ECRED"
	env, err := agentmessage.Countersign(botKeys, receipt)
	if err != nil {
		t.Fatal(err)
	}
	c.chain = append(c.chain, agentmessage.Entry{Conversation: "c1", Seq: receipt.Seq, MessageID: receipt.MessageID, Kind: receipt.Kind,
		From: receipt.From, To: receipt.To, InReplyTo: receipt.InReplyTo, BodyHash: receipt.BodyHash, Envelope: env, Hash: agentmessage.Hash(env)})
	rootDID, _ := c.keys.DID()
	v := newVerifier()
	b := c.bundle(true)
	v.b, v.hashes, v.signedOnce, v.answered, v.notes = b, map[int]string{}, map[string]int{}, map[string]bool{}, map[string]bool{}
	v.dids = map[string]*didcomm.DID{rootAID: rootDID, "EBOT": botDID}
	v.checkEntries()
	for _, f := range v.r.Faults {
		if strings.Contains(f.Why, "it is addressed to "+rootAID) {
			t.Fatalf("a receipt to the Identity Agent was faulted for who it is to: %s", f.Why)
		}
	}
}
