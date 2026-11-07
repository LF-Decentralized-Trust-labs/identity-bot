package conversationbundle

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"identity-agent-core/agentmessage"
	"identity-agent-core/authorisation"
	"identity-agent-core/trail"
)

// These write a conversation with the real trail and then run the verifier's
// entry checks over what it wrote, so the writer and the verifier cannot
// disagree unnoticed (ADR-068).

// verified fails the test if the verifier finds a fault in the chain as written.
func (c *conversation) verified() {
	c.t.Helper()
	if v := c.check(c.bundle(true)); len(v.r.Faults) != 0 {
		c.t.Fatalf("the verifier faults what the trail wrote: %s", openingFaults(v))
	}
}

// signerRoster makes EBOSS a signer; EBOT is the only AI agent.
type signerRoster struct{ allowAll }

func (signerRoster) IsSigner(p string) bool { return p == "EBOSS" }

// readingApp is an app that keeps words and gives them back.
type readingApp struct {
	keepingApp
	c *conversation
}

func (a readingApp) Read(_ context.Context, _, _, _ string) ([]trail.Stored, error) {
	var out []trail.Stored
	for i := 1; i <= len(a.c.tr.Chain("c1")); i++ {
		id := agentmessage.EntryID(i)
		if k, ok := a.c.words[id]; ok {
			out = append(out, trail.Stored{EntryID: id, Salt: k.salt, Words: k.words})
		}
	}
	return out, nil
}

func TestOnlyTheOpenerTheCurrentOwnerAndSignersMayRead(t *testing.T) {
	c := newConversationWith(t, signerRoster{}, func(c *conversation) trail.Backend { return readingApp{c: c} })
	handOff := func(from, to string) {
		t.Helper()
		r := c.say(from, "handing on", func(s *agentmessage.PersonStatement) { s.Kind, s.To = agentmessage.PersonKindHandOff, to })
		if r.State != trail.Committed {
			t.Fatalf("hand-off %s to %s: %+v", from, to, r)
		}
	}
	reads := func(person string) error {
		_, err := c.tr.Read(context.Background(), person, "c1", "", "")
		return err
	}
	mustRead := func(who ...string) {
		t.Helper()
		for _, p := range who {
			if err := reads(p); err != nil {
				t.Fatalf("%s was refused: %v", p, err)
			}
		}
	}
	mustNot := func(why string, who ...string) {
		t.Helper()
		for _, p := range who {
			if err := reads(p); err == nil || err.Error() != trail.ReasonMayNotRead {
				t.Fatalf("%s (%s) read it: %v", p, why, err)
			}
		}
	}

	c.say("EALICE", "to the bot", nil) // addresses EBOT
	// A writer who does not own it leaves a refusal; that admits nobody.
	if r := c.say("EDAVE", "from a stranger", nil); r.State != trail.Refused {
		t.Fatalf("a non-owner's write was %s", r.State)
	}
	mustRead("EALICE", "EBOSS")
	mustNot("addressed in a kept entry, an AI agent outside its thread", "EBOT")
	mustNot("wrote a refused entry", "EDAVE")

	handOff("EALICE", "EBOB")
	mustRead("EALICE", "EBOB", "EBOSS") // the opener, the owner, a signer
	handOff("EBOB", "ECAROL")
	mustRead("EALICE", "ECAROL", "EBOSS")
	mustNot("a former owner after hand-off, also named in a hand-off", "EBOB")
	mustNot("addressed in a kept entry", "EBOT")

	// A signer's hand-off names the signer without making the signer a writer;
	// the new owner reads, the one handed on from does not.
	handOff("EBOSS", "EFRANK")
	mustRead("EFRANK", "EBOSS", "EALICE")
	mustNot("a former owner after a signer's hand-off", "ECAROL")
	c.verified()
}

func TestAnIDReuseRefusalUsesUpItsNonceAsTheVerifierReadsIt(t *testing.T) {
	c := newConversation(t)
	c.say("EALICE", "one", nil) // m1, nonce-1
	reuse := c.say("EALICE", "two", func(s *agentmessage.PersonStatement) { s.MessageID = "m1" })
	if reuse.State != trail.Refused || reuse.Reason != trail.ReasonIDUsed {
		t.Fatalf("the reuse of an id was %+v", reuse)
	}
	c.verified()
	// The refusal used up its nonce: a fresh id with that nonce is refused by
	// the writer, as the verifier would fault it if it were kept.
	again := c.say("EALICE", "three", func(s *agentmessage.PersonStatement) { s.Nonce = "nonce-0000000000000002" })
	if again.State != trail.Refused || again.Reason != trail.ReasonNonceUsed {
		t.Fatalf("a nonce a refusal used was %+v", again)
	}
	c.verified()
	// And a fresh id and nonce is still kept.
	if r := c.say("EALICE", "four", nil); r.State != trail.Committed {
		t.Fatalf("a fresh write was %+v", r)
	}
	c.verified()
}

func TestAStatementSignedOutsideTheSkewIsRejectedAtWrite(t *testing.T) {
	c := newConversation(t)
	at := func(d time.Duration) func(*agentmessage.PersonStatement) {
		return func(s *agentmessage.PersonStatement) {
			now := c.now.Add(time.Second) // what the trail will read next, near enough
			s.Time = now.Add(d).Format(time.RFC3339)
		}
	}
	c.say("EALICE", "one", nil)
	before := len(c.tr.Chain("c1"))
	for name, d := range map[string]time.Duration{
		"hours old":   -3 * time.Hour,
		"just stale":  -(authorisation.Skew + time.Minute),
		"from ahead":  authorisation.Skew + time.Minute,
		"a day ahead": 24 * time.Hour,
	} {
		_, err := c.trySay("EALICE", "late", at(d))
		var rej *trail.Rejected
		if !errors.As(err, &rej) || !strings.Contains(rej.Reason, "5 minutes") {
			t.Fatalf("%s: got %v", name, err)
		}
		// The same with an id already used, which would be a refusal.
		_, err = c.trySay("EALICE", "late", func(s *agentmessage.PersonStatement) { at(d)(s); s.MessageID = "m1" })
		if !errors.As(err, &rej) {
			t.Fatalf("%s, reusing an id: got %v", name, err)
		}
	}
	if n := len(c.tr.Chain("c1")); n != before {
		t.Fatalf("a rejected write joined the chain: %d entries, was %d", n, before)
	}
	// Inside the skew, either side, is kept; the verifier agrees.
	for _, d := range []time.Duration{-(authorisation.Skew - time.Minute), authorisation.Skew - time.Minute} {
		if r, err := c.trySay("EALICE", "in time", at(d)); err != nil || r.State != trail.Committed {
			t.Fatalf("%v from now: %+v, %v", d, r, err)
		}
	}
	c.verified()
}
