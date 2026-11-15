package conversationbundle

import (
	"strings"
	"testing"

	"identity-agent-core/agentmessage"
)

// An addendum is more to say about an ask already answered by a reply, from
// the one who answered to the one who asked, and it owes no answer. The ask
// may have been a person's.
func TestAnAddendumAddsToAnAnsweredAsk(t *testing.T) {
	ask := agentmessage.Record{MessageID: "m-ask", Kind: agentmessage.KindAsk, From: "agent-a", To: "agent-b"}
	personAsk := agentmessage.Record{MessageID: "m-pask", Kind: agentmessage.KindAsk, From: "person:EP", To: "agent-b"}
	reply := func(id, ask, from, to string) agentmessage.Record {
		return agentmessage.Record{MessageID: id, Kind: agentmessage.KindReply, From: from, To: to, InReplyTo: ask}
	}
	addendum := func(id, on, from, to string) agentmessage.Record {
		return agentmessage.Record{MessageID: id, Kind: agentmessage.KindAddendum, From: from, To: to, InReplyTo: on}
	}
	// run feeds a short chain, then the addendum, and returns the faults the addendum raised.
	run := func(chain []agentmessage.Record, add agentmessage.Record, closed bool) []string {
		r := &Report{}
		v := &verifier{r: r, entries: map[string]agentmessage.Record{}, answered: map[string]bool{}, repliedTo: map[string]bool{}}
		for _, e := range chain {
			v.entries[e.MessageID] = e
		}
		for _, e := range chain {
			if e.Kind == agentmessage.KindReply {
				v.checkThread("chain", e)
			}
		}
		v.closed = closed
		n := len(r.Faults)
		v.checkThread("addendum", add)
		var why []string
		for _, f := range r.Faults[n:] {
			why = append(why, f.Why)
		}
		return why
	}
	answeredAI := []agentmessage.Record{ask, reply("m-reply", "m-ask", "agent-b", "agent-a")}
	answeredPerson := []agentmessage.Record{personAsk, reply("m-preply", "m-pask", "agent-b", "person:EP")}

	if f := run(answeredAI, addendum("m-add", "m-ask", "agent-b", "agent-a"), false); len(f) != 0 {
		t.Fatalf("an addendum to an AI agent's answered ask was refused: %v", f)
	}
	if f := run(answeredPerson, addendum("m-add", "m-pask", "agent-b", "person:EP"), false); len(f) != 0 {
		t.Fatalf("an addendum to a person's answered ask was refused: %v", f)
	}
	for name, c := range map[string]struct {
		chain  []agentmessage.Record
		add    agentmessage.Record
		closed bool
		want   string
	}{
		"before the answer":        {[]agentmessage.Record{ask}, addendum("m-add", "m-ask", "agent-b", "agent-a"), false, "was answered by a reply"},
		"after only a failure":     {[]agentmessage.Record{ask, {MessageID: "m-f", Kind: agentmessage.KindFailure, From: "agent-b", To: "agent-a", InReplyTo: "m-ask"}}, addendum("m-add", "m-ask", "agent-b", "agent-a"), false, "was answered by a reply"},
		"from one not asked":       {answeredAI, addendum("m-add", "m-ask", "agent-c", "agent-a"), false, "goes only from the one"},
		"to one who did not ask":   {answeredAI, addendum("m-add", "m-ask", "agent-b", "agent-c"), false, "goes only from the one"},
		"on a reply":               {answeredAI, addendum("m-add", "m-reply", "agent-b", "agent-a"), false, "goes only from the one"},
		"in a closed conversation": {answeredAI, addendum("m-add", "m-ask", "agent-b", "agent-a"), true, "closed"},
	} {
		f := run(c.chain, c.add, c.closed)
		if len(f) != 1 || !strings.Contains(f[0], c.want) {
			t.Errorf("%s: want one fault containing %q, got %v", name, c.want, f)
		}
	}

	// Nothing answers an addendum: a reply, a failure or a progress note
	// naming one is refused. A receipt may acknowledge it, and the one it went
	// to may act on it as on any message given to them, by asking something new.
	answeredAdded := append(append([]agentmessage.Record{}, answeredAI...), addendum("m-add", "m-ask", "agent-b", "agent-a"))
	for name, rec := range map[string]agentmessage.Record{
		"a reply":         {MessageID: "m-x", Kind: agentmessage.KindReply, From: "agent-a", To: "agent-b", InReplyTo: "m-add"},
		"a failure":       {MessageID: "m-x", Kind: agentmessage.KindFailure, From: "agent-a", To: "agent-b", InReplyTo: "m-add"},
		"a progress note": {MessageID: "m-x", Kind: agentmessage.KindProgress, From: "agent-a", To: "agent-b", InReplyTo: "m-add"},
	} {
		if f := run(answeredAdded, rec, false); len(f) != 1 {
			t.Errorf("%s naming an addendum: want it refused with one fault, got %v", name, f)
		}
	}
	for name, rec := range map[string]agentmessage.Record{
		"a receipt": {MessageID: "m-r", Kind: agentmessage.KindReceipt, From: "agent-a", To: "agent-b", InReplyTo: "m-add"},
		"a new ask": {MessageID: "m-n", Kind: agentmessage.KindAsk, From: "agent-a", To: "agent-c", InReplyTo: "m-add"},
	} {
		if f := run(answeredAdded, rec, false); len(f) != 0 {
			t.Errorf("%s acting on an addendum was refused: %v", name, f)
		}
	}
}
