package mediation

import (
	"errors"
	"testing"

	"identity-agent-core/limits"
)

// A view that admits some conversations refuses the rest, and shares what is
// held with the queue it was made from; a view of a view admits only what both do.
func TestAViewTakesOnlyTheConversationsItAdmits(t *testing.T) {
	q := New(limits.Defaults(), nil)
	v := q.Admitting(func(c string) bool { return c != "x" })
	w := v.Admitting(func(c string) bool { return c != "y" })
	msg := func(c string) Message { return Message{ID: c + "/e1", Conversation: c, Sender: "s", Recipient: "r", Sealed: []byte("z")} }
	if err := v.Enqueue(msg("a")); err != nil {
		t.Fatal(err)
	}
	for name, err := range map[string]error{"v refuses x": v.Enqueue(msg("x")), "w refuses x": w.Enqueue(msg("x")), "w refuses y": w.Enqueue(msg("y"))} {
		var r *Refusal
		if !errors.As(err, &r) || r.Reason != ReasonNotKept {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if err := v.Enqueue(msg("y")); err != nil {
		t.Fatal(err)
	}
	if q.Len() != 2 || w.Len() != 2 {
		t.Fatalf("the view does not share the queue: %d %d", q.Len(), w.Len())
	}
}
