package conversationbundle

import (
	"strings"
	"testing"

	"identity-agent-core/agentmessage"
)

// A notice is the Identity Agent's own word to a person, by code: a trail shows that a person was
// told, and what, without a word of text in it.
func TestANoticeInTheChainIsCheckedWhole(t *testing.T) {
	asAsk := func(s *agentmessage.PersonStatement) { s.Kind = agentmessage.PersonKindAsk }
	asClose := func(s *agentmessage.PersonStatement) { s.Kind, s.To = agentmessage.PersonKindClose, "" }
	notice := func(c *conversation, from, to, code string, change func(*agentmessage.Record)) {
		r := agentmessage.Record{Kind: agentmessage.KindNotice, From: from, To: to, BodyHash: agentmessage.HashBody(nil), Notice: &agentmessage.Notice{Code: code}}
		if change != nil {
			change(&r)
		}
		c.append(r)
	}
	alice := agentmessage.Person("EALICE")

	t.Run("the Identity Agent tells the person who is in the conversation, once", func(t *testing.T) {
		c := newConversation(t)
		c.say("EALICE", "one", asAsk)
		notice(c, rootAID, alice, agentmessage.NoticeNotesKept, nil)
		if v := c.check(c.bundle(true)); len(v.r.Faults) != 0 {
			t.Fatalf("a notice has faults: %s", openingFaults(v))
		}
		notice(c, rootAID, alice, agentmessage.NoticeNotesKept, nil)
		if got := openingFaults(c.check(c.bundle(true))); !strings.Contains(got, "gives it once") {
			t.Fatalf("a second notice of one code to one person: %q", got)
		}
	})
	refused := map[string]struct {
		build func(c *conversation)
		want  string
	}{
		"from anybody but the Identity Agent": {func(c *conversation) { notice(c, "EBOT", alice, agentmessage.NoticeNotesKept, nil) }, "EBOT"},
		"to an AI agent":                      {func(c *conversation) { notice(c, rootAID, "EBOT", agentmessage.NoticeNotesKept, nil) }, "for a person"},
		"of a code that has no words": {func(c *conversation) {
			notice(c, rootAID, alice, "free-text", nil)
		}, "not a notice the Identity Agent gives"},
		"carrying words of its own": {func(c *conversation) {
			notice(c, rootAID, alice, agentmessage.NoticeNotesKept, func(r *agentmessage.Record) { r.BodyHash = agentmessage.HashBody([]byte("send me your password")) })
		}, "no words of its own"},
		"acting on a message": {func(c *conversation) {
			notice(c, rootAID, alice, agentmessage.NoticeNotesKept, func(r *agentmessage.Record) { r.InReplyTo = agentmessage.EntryID(1) })
		}, "acts on no message"},
		"after the conversation closed": {func(c *conversation) {
			c.say("EALICE", "", asClose)
			notice(c, rootAID, alice, agentmessage.NoticeNotesKept, nil)
		}, "closed and not reopened"},
		"with a sender's proof it does not need": {func(c *conversation) {
			notice(c, rootAID, alice, agentmessage.NoticeNotesKept, func(r *agentmessage.Record) { r.Refusal = "because" })
		}, "no sender's proof"},
	}
	for name, c := range refused {
		t.Run("refused: "+name, func(t *testing.T) {
			h := newConversation(t)
			h.say("EALICE", "one", asAsk)
			c.build(h)
			v := h.check(h.bundle(true))
			var all []string
			for _, f := range v.r.Faults {
				all = append(all, f.Why)
			}
			if got := strings.Join(all, "\n"); !strings.Contains(got, c.want) {
				t.Fatalf("a notice %s was not caught for %q: %q", name, c.want, got)
			}
		})
	}
}

func TestANoticeNamesACodeAndTheCodeHasFixedWords(t *testing.T) {
	w, ok := agentmessage.NoticeWords(agentmessage.NoticeNotesKept)
	if !ok || w == "" {
		t.Fatal("the code has no words")
	}
	if _, ok := agentmessage.NoticeWords("anything else"); ok {
		t.Fatal("a code nobody defined has words")
	}
	r := agentmessage.Record{Kind: agentmessage.KindNotice}
	if err := r.CheckSenderProof(); err == nil || !strings.Contains(err.Error(), "names what it says") {
		t.Fatalf("a notice that names nothing: %v", err)
	}
	r = agentmessage.Record{Kind: agentmessage.KindNotice, Notice: &agentmessage.Notice{Code: agentmessage.NoticeNotesKept},
		Outcome: &agentmessage.Outcome{Entry: "e1", State: agentmessage.OutcomeCommitted}}
	if err := r.CheckSenderProof(); err == nil {
		t.Fatal("an entry that is an outcome and a notice")
	}
}
