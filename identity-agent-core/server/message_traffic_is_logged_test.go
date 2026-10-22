package server

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"testing"

	"identity-agent-core/agenthost"
	"identity-agent-core/agentmessage"
	"identity-agent-core/sandbox"
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

	rows, err := w.s.SandboxManager.Store().QueryInvocationEvents(sandbox.InvocationEventFilter{WorkItem: conv})
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

	// A message refused for the conversation it names is filed under that
	// conversation too, so reading one conversation's log shows its refusals.
	if code, _ := w.personSays(t, w.a, "c_never-opened", "hello"); code < 400 {
		t.Fatalf("a message into a conversation that does not exist was taken: %d", code)
	}
	rows, _ = w.s.SandboxManager.Store().QueryInvocationEvents(sandbox.InvocationEventFilter{
		WorkItem: "c_never-opened", ResultStatus: "denied"})
	if len(rows) == 0 {
		t.Fatal("a refusal is not filed under the conversation it named")
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
// in, so the attempt shows when that conversation's log is read.
func TestABodysRefusalIsFiledUnderTheConversation(t *testing.T) {
	w := newTalkWorld(t)
	conv, msg := w.openedWith(t)
	_, err := w.hostB.Say(context.Background(), agentmessage.KindAsk, conv, w.a.PairwiseAID, msg, "let me in", agentmessage.Brain{})
	refusedWith(t, err, "has not been brought into")
	rows, _ := w.s.SandboxManager.Store().QueryInvocationEvents(sandbox.InvocationEventFilter{WorkItem: conv, ResultStatus: "denied"})
	if len(rows) == 0 {
		t.Fatal("the body's refused message is not filed under the conversation")
	}
}
