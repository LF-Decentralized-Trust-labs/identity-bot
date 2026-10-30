package server

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"testing"

	"identity-agent-core/activitylog"
	"identity-agent-core/agenthost"
	"identity-agent-core/agentmessage"
)

// Every message of a conversation leaves a row in the signed log, filed under
// the conversation: the person's ask, its delivery to the body, the body's
// receipt, and its answer. A refusal in a conversation is filed under it too.
func TestEveryMessageOfAConversationIsInTheSignedLog(t *testing.T) {
	w := newTalkWorld(t)
	code, out := w.personSays(t, w.a, "", "what do you run on?")
	if code != http.StatusCreated {
		t.Fatalf("the person's message: %d %v", code, out)
	}
	conv := out["conversation"].(string)
	brain := scripted{name: "test-brain", act: func(Turn) (string, error) { return "a laptop", nil }}
	if err := w.hostA.Run(context.Background(), agenthost.RunOptions{Brain: brain, Once: true, Workspace: t.TempDir()}); err != nil {
		t.Fatal(err)
	}

	rows, err := w.s.ActivityLog.QueryInvocationEvents(activitylog.InvocationEventFilter{WorkItem: conv})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range rows {
		got = append(got, r.CapabilityID+"="+r.ResultStatus)
	}
	sort.Strings(got)
	want := []string{
		"agent.message.ask=ok", "agent.message.delivered=ok", "agent.message.receipt=ok", "agent.message.reply=ok",
	}
	for _, need := range want {
		if !hasRow(got, need) {
			t.Fatalf("the log for the conversation is %v; it has no %s", got, need)
		}
	}

	// A refused message in the person's own conversation is filed under it,
	// so reading one conversation's log shows its refusals.
	if code, _ := w.personSays(t, w.a, conv, ""); code < 400 {
		t.Fatalf("a message with no words was taken: %d", code)
	}
	rows, _ = w.s.ActivityLog.QueryInvocationEvents(activitylog.InvocationEventFilter{
		WorkItem: conv, ResultStatus: "denied"})
	if len(rows) == 0 {
		t.Fatal("a refusal is not filed under the person's own conversation")
	}
	// One naming a conversation that does not exist is filed under none: a
	// caller does not choose what gets written into a conversation's log.
	if code, _ := w.personSays(t, w.a, "c_never-opened", "hello"); code < 400 {
		t.Fatalf("a message into a conversation that does not exist was taken: %d", code)
	}
	rows, _ = w.s.ActivityLog.QueryInvocationEvents(activitylog.InvocationEventFilter{
		WorkItem: "c_never-opened"})
	if len(rows) != 0 {
		t.Fatalf("a refusal was filed under a conversation that does not exist: %d rows", len(rows))
	}
}

func hasRow(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// A body's refused message is filed under the conversation it tried to speak
// in when its AI agent is in that conversation, so the attempt shows when the
// conversation's log is read. A body whose AI agent is not in it files
// nothing there: it cannot write into a conversation it is not part of.
func TestABodysRefusalIsFiledOnlyUnderAConversationItIsIn(t *testing.T) {
	w := newTalkWorld(t)
	conv, msg := w.openedWith(t)
	denied := func() int {
		rows, _ := w.s.ActivityLog.QueryInvocationEvents(activitylog.InvocationEventFilter{WorkItem: conv, ResultStatus: "denied"})
		return len(rows)
	}

	_, err := w.hostB.Say(context.Background(), agentmessage.KindAsk, conv, w.a.PairwiseAID, msg, "let me in", agentmessage.Brain{})
	refusedWith(t, err, "has not been brought into")
	if n := denied(); n != 0 {
		t.Fatalf("a body outside the conversation put %d rows into its log", n)
	}

	_, err = w.hostA.Say(context.Background(), agentmessage.KindAsk, conv, w.a.PairwiseAID, msg, "ask myself", agentmessage.Brain{})
	refusedWith(t, err, "does not ask itself")
	if n := denied(); n != 1 {
		t.Fatalf("a refusal of the conversation's own AI agent is filed %d times under it; want once", n)
	}
}

// A message handed to a machine is recorded as delivered once, however often
// the machine collects it before sending its receipt.
func TestADeliveryIsRecordedOncePerMachine(t *testing.T) {
	w := newTalkWorld(t)
	_, msg := w.openedWith(t)
	for i := 0; i < 3; i++ {
		got, err := w.hostA.Inbox(context.Background(), false)
		if err != nil || len(got) == 0 {
			t.Fatalf("collection %d: %d messages, %v", i, len(got), err)
		}
	}
	rows, _ := w.s.ActivityLog.QueryInvocationEvents(activitylog.InvocationEventFilter{
		CapabilityID: "agent.message.delivered", CorrelationID: msg})
	if len(rows) != 1 {
		t.Fatalf("a message collected three times is recorded as delivered %d times; want once", len(rows))
	}
}
