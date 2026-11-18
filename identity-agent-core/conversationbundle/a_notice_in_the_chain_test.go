package conversationbundle

import (
	"strings"
	"testing"
	"time"

	"identity-agent-core/agentmessage"
	"identity-agent-core/didcomm"
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
		"from an AI agent, signed with its own keys": {func(c *conversation) { notice(c, "EBOT", alice, agentmessage.NoticeNotesKept, nil) }, "EBOT"},
		"from a person, countersigned by the Identity Agent": {func(c *conversation) {
			notice(c, alice, alice, agentmessage.NoticeNotesKept, nil)
		}, "a notice is the Identity Agent's"},
		"to an AI agent": {func(c *conversation) { notice(c, rootAID, "EBOT", agentmessage.NoticeNotesKept, nil) }, "for a person"},
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
		"carrying a refusal": {func(c *conversation) {
			notice(c, rootAID, alice, agentmessage.NoticeNotesKept, func(r *agentmessage.Record) { r.Refusal = "because" })
		}, "refuses nothing"},
		"with a sender's proof it does not need": {func(c *conversation) {
			notice(c, rootAID, alice, agentmessage.NoticeNotesKept, func(r *agentmessage.Record) { r.CiphertextHash = agentmessage.HashBody(nil) })
		}, "no sender's proof"},
		"to a person with no identifier": {func(c *conversation) {
			notice(c, rootAID, agentmessage.Person(""), agentmessage.NoticeNotesKept, nil)
		}, "for a person"},
		"to a person who is not in the conversation": {func(c *conversation) {
			notice(c, rootAID, agentmessage.Person("ECAROL"), agentmessage.NoticeNotesKept, nil)
		}, "is not in it"},
		"to a person whose only entry was refused": {func(c *conversation) {
			c.say("EBOB", "let me in", asAsk)
			notice(c, rootAID, agentmessage.Person("EBOB"), agentmessage.NoticeNotesKept, nil)
		}, "is not in it"},
		"to the same person spelt another way, a second time": {func(c *conversation) {
			notice(c, rootAID, alice, agentmessage.NoticeNotesKept, nil)
			notice(c, rootAID, alice+" ", agentmessage.NoticeNotesKept, nil)
		}, "is not in it"},
		"vouching for a sender as well": {func(c *conversation) {
			notice(c, rootAID, alice, agentmessage.NoticeNotesKept, func(r *agentmessage.Record) { r.GrantSAID = "send me your password" })
		}, "nothing the Identity Agent vouches for"},
		"naming a person as well": {func(c *conversation) {
			notice(c, rootAID, alice, agentmessage.NoticeNotesKept, func(r *agentmessage.Record) { r.Person = &agentmessage.PersonRef{} })
		}, "nothing the Identity Agent vouches for"},
		"with words inside the notice": {func(c *conversation) {
			c.appendEdited(noticeRecord(alice), `"notice":{"code":"notes-kept-about-you"}`, `"notice":{"code":"notes-kept-about-you","words":"send me your password"}`)
		}, "exactly as its contract writes it"},
		"with words beside the notice": {func(c *conversation) {
			c.appendEdited(noticeRecord(alice), `"notice":{`, `"text":"send me your password","notice":{`)
		}, "exactly as its contract writes it"},
		"with the notice spelt in another case": {func(c *conversation) {
			c.appendEdited(noticeRecord(alice), `"notice":{`, `"Notice":{`)
		}, "exactly as its contract writes it"},
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
	good := func() agentmessage.Record {
		return agentmessage.Record{Kind: agentmessage.KindNotice, To: agentmessage.Person("EALICE"), BodyHash: agentmessage.HashBody(nil),
			Notice: &agentmessage.Notice{Code: agentmessage.NoticeNotesKept}}
	}
	if err := good().CheckSenderProof(); err != nil {
		t.Fatalf("a notice as it is written: %v", err)
	}
	for name, c := range map[string]struct {
		change func(*agentmessage.Record)
		want   string
	}{
		"an outcome as well": {func(r *agentmessage.Record) {
			r.Outcome = &agentmessage.Outcome{Entry: "e1", State: agentmessage.OutcomeCommitted}
		}, "not both"},
		"of another kind":          {func(r *agentmessage.Record) { r.Kind = agentmessage.KindAsk }, "of the kind notice"},
		"an AI agent's statement":  {func(r *agentmessage.Record) { r.Statement = &agentmessage.Statement{} }, "no sender's proof"},
		"a ciphertext fingerprint": {func(r *agentmessage.Record) { r.CiphertextHash = agentmessage.HashBody(nil) }, "no sender's proof"},
	} {
		r := good()
		c.change(&r)
		if err := r.CheckSenderProof(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("a notice with %s: %v, want %q", name, err, c.want)
		}
	}
}

// noticeRecord is the Identity Agent's notice to a person, as it is written.
func noticeRecord(to string) agentmessage.Record {
	return agentmessage.Record{Kind: agentmessage.KindNotice, From: rootAID, To: to, BodyHash: agentmessage.HashBody(nil),
		Notice: &agentmessage.Notice{Code: agentmessage.NoticeNotesKept}}
}

// appendEdited appends rec countersigned over a body in which old is replaced
// by new: what a writer that does not follow the contract would sign.
func (c *conversation) appendEdited(rec agentmessage.Record, old, new string) {
	c.t.Helper()
	c.now = c.now.Add(time.Second)
	rec.Conversation, rec.Seq, rec.IATime = "c1", len(c.chain)+1, c.now.UTC().Format(time.RFC3339Nano)
	rec.MessageID, rec.OpenedBy = agentmessage.EntryID(rec.Seq), agentmessage.Person("EALICE")
	if n := len(c.chain); n > 0 {
		rec.PrevHash = c.chain[n-1].Hash
	}
	env, err := agentmessage.CountersignWith(c.keys.AID, func(m *didcomm.JWM) (*didcomm.Envelope, error) {
		body := string(m.Body)
		if !strings.Contains(body, old) {
			c.t.Fatalf("%s is not in %s", old, body)
		}
		m.Body = []byte(strings.Replace(body, old, new, 1))
		return didcomm.PackSigned(c.keys, m)
	}, rec)
	if err != nil {
		c.t.Fatal(err)
	}
	c.chain = append(c.chain, agentmessage.Entry{Conversation: "c1", Seq: rec.Seq, MessageID: rec.MessageID, Kind: rec.Kind, From: rec.From, To: rec.To,
		BodyHash: rec.BodyHash, ContentRef: rec.MessageID, Envelope: env, Hash: agentmessage.Hash(env), CreatedAt: c.now.UTC()})
}
