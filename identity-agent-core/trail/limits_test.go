package trail

import (
	"testing"
	"time"

	"identity-agent-core/agentmessage"
	"identity-agent-core/didcomm"
	"identity-agent-core/limits"
)

// agentEntry is an AI agent's reply, countersigned, following the chain's end.
func (f *fixture) agentEntry(i int) agentmessage.Entry {
	f.t.Helper()
	seq := len(f.tr.Chain("c1")) + 1
	rec := agentmessage.Record{
		MessageID: "a" + string(rune('A'+i%26)) + time.Duration(i).String(), Conversation: "c1", Seq: seq, PrevHash: f.tr.Head("c1"),
		IATime: "2026-11-06T12:00:00Z", Kind: agentmessage.KindReply, From: bot, To: agentmessage.Person(alice),
		InReplyTo: "e1", BodyHash: agentmessage.HashBody([]byte("r")), OpenedBy: agentmessage.Person(alice),
	}
	env, err := agentmessage.Countersign(f.keys, rec)
	if err != nil {
		f.t.Fatal(err)
	}
	return agentmessage.Entry{Conversation: "c1", Seq: seq, MessageID: rec.MessageID, Envelope: env, Hash: agentmessage.Hash(env)}
}

// With the back end down, the entries of AI agents that cannot be kept still
// count toward the turn limit, and the turn past it is refused.
func TestAgentsEntriesCountTowardTheTurnLimitWhileTheAppIsDown(t *testing.T) {
	f := newFixture(t)
	f.write(f.say(alice, "message", bot, "hello", nil))
	f.app.down = true
	for i := 0; i < limits.Defaults().MaxTurns; i++ {
		if err := f.tr.AppendAgent("c1", f.agentEntry(i)); err != nil {
			t.Fatalf("turn %d: %v", i+1, err)
		}
	}
	err := f.tr.AppendAgent("c1", f.agentEntry(99))
	if err == nil || err.Error() != ReasonTurnLimit {
		t.Fatalf("the turn past the limit got %v", err)
	}
	f.app.down = false
	if err := f.tr.AppendAgent("c1", f.agentEntry(99)); err == nil {
		t.Fatal("the app coming back lifted the turn limit")
	}
	// A new message from the person starts the count again.
	if r := f.write(f.say(alice, "message", bot, "go on", nil)); r.State != Committed {
		t.Fatalf("got %+v", r)
	}
	if err := f.tr.AppendAgent("c1", f.agentEntry(100)); err != nil {
		t.Fatalf("a new person message did not reset the turns: %v", err)
	}
}

func TestAFullConversationNamesTheLimit(t *testing.T) {
	f := newFixture(t)
	l := limits.Defaults()
	l.EntriesPerConversation = 4
	f.tr.lim = l
	f.write(f.say(alice, "message", bot, "1", nil)) // chain: e1 + outcome = 2
	f.write(f.say(alice, "message", bot, "2", nil)) // 4
	r := f.write(f.say(alice, "message", bot, "3", nil))
	if r.State != Refused || r.Reason != ReasonEntryLimit {
		t.Fatalf("got %+v", r)
	}
	if len(f.app.kept) != 2 {
		t.Fatal("a refused write reached the app")
	}
}

func TestAPersonIsHeldToMessagesAnHour(t *testing.T) {
	f := newFixture(t)
	l := limits.Defaults()
	l.MessagesPerPersonPerHour = 2
	f.tr.lim = l
	f.write(f.say(alice, "message", bot, "1", nil))
	f.write(f.say(alice, "message", bot, "2", nil))
	if r := f.write(f.say(alice, "message", bot, "3", nil)); r.State != Refused || r.Reason != ReasonRateLimit {
		t.Fatalf("got %+v", r)
	}
	f.now = f.now.Add(61 * time.Minute)
	if r := f.write(f.say(alice, "message", bot, "4", func(s *agentmessage.PersonStatement) { s.Time = "2026-11-06T13:01:00Z" })); r.State != Committed {
		t.Fatalf("after the hour got %+v", r)
	}
}

// A phone's Identity Agent forwards with the same timeout; only capacity shrinks.
func TestAPhonesTrailKeepsTheForwardingTimeout(t *testing.T) {
	if DefaultTimeout != limits.Defaults().ForwardTimeout {
		t.Fatal("DefaultTimeout drifted from limits")
	}
	f := newFixture(t)
	phone := New(f.roster, f.app, Options{Agent: testAgent, Limits: limits.Defaults().ForPhone(),
		Countersign: func(r agentmessage.Record) (*didcomm.Envelope, error) { return nil, nil }})
	if phone.ForwardTimeout() != 10*time.Second || phone.lim.EntriesPerConversation != 10_000 {
		t.Fatalf("timeout %v entries %d", phone.ForwardTimeout(), phone.lim.EntriesPerConversation)
	}
}
