package conversationbundle

import (
	"strings"
	"testing"

	"identity-agent-core/agentmessage"
)

// A progress note says an ask is still being worked. It goes only from the one
// asked to the one who asked, and only while the ask is open: after the reply
// or failure that closes it, a note would read as news about finished work.
func TestAProgressNoteIsOnlyForAnOpenAsk(t *testing.T) {
	ask := agentmessage.Record{MessageID: "m-ask", Kind: agentmessage.KindAsk, From: "agent-a", To: "agent-b"}
	note := func(id, from, to string) agentmessage.Record {
		return agentmessage.Record{MessageID: id, Kind: agentmessage.KindProgress, From: from, To: to, InReplyTo: "m-ask"}
	}
	newVerifier := func() (*verifier, *Report) {
		r := &Report{}
		v := &verifier{r: r, entries: map[string]agentmessage.Record{"m-ask": ask}, answered: map[string]bool{}}
		return v, r
	}

	v, r := newVerifier()
	v.checkThread("note", note("m-note", "agent-b", "agent-a"))
	if len(r.Faults) != 0 {
		t.Fatalf("a note from the one asked, while the ask is open, was refused: %v", r.Faults)
	}

	v, r = newVerifier()
	v.checkThread("note", note("m-note", "agent-c", "agent-a"))
	if len(r.Faults) != 1 || !strings.Contains(r.Faults[0].Why, "goes only to the sender") {
		t.Fatalf("a note from someone the ask was not put to was not refused: %v", r.Faults)
	}

	v, r = newVerifier()
	v.checkThread("reply", agentmessage.Record{MessageID: "m-reply", Kind: agentmessage.KindReply, From: "agent-b", To: "agent-a", InReplyTo: "m-ask"})
	v.checkThread("late note", note("m-late", "agent-b", "agent-a"))
	if len(r.Faults) != 1 || !strings.Contains(r.Faults[0].Why, "after the ask it is about was answered") {
		t.Fatalf("a note after the answer was not refused: %v", r.Faults)
	}
}
