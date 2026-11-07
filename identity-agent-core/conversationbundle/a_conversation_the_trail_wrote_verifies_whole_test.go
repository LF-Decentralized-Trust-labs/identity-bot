package conversationbundle

import (
	"encoding/base64"
	"strings"
	"testing"

	"identity-agent-core/agentmessage"
	"identity-agent-core/didcomm"
)

// A conversation written through trail.Write, with an AI agent's reply, is
// exported with its key logs, credentials, governance log and anchors, and
// the whole bundle is verified: not only the entry checks the trail's own
// tests run, but every other thing a bundle rests on (T-1022).

func TestAConversationTheTrailWroteVerifiesAsAWholeBundle(t *testing.T) {
	c := aMixedWholeConversation(t)
	b := c.export()
	r := VerifyAgainst(b, b.Root)
	if !r.Verified {
		t.Fatalf("a whole bundle of a conversation the trail wrote does not verify:\n%s", faultsOf(r))
	}
	// e1 kept, e2 its outcome, e3 the AI agent's reply, e4 a refusal, e5 not
	// kept, e6 its outcome.
	if len(r.Messages) != 6 {
		t.Fatalf("the report covers %d entries, want 6", len(r.Messages))
	}
	senders := []string{"statement", "identity agent", "body", "statement", "statement", "identity agent"}
	for i, m := range r.Messages {
		if m.Sender != senders[i] || !m.Holds || !m.Anchored {
			t.Fatalf("entry %d: sender %q, holds %v, anchored %v", m.Seq, m.Sender, m.Holds, m.Anchored)
		}
	}
	if r.Messages[2].Grade != "software" {
		t.Fatalf("the AI agent's reply is not shown with its body's grade: %+v", r.Messages[2])
	}
	if r.AnchoredThrough != 6 {
		t.Fatalf("anchored through entry %d, want 6", r.AnchoredThrough)
	}
	// Checked against another organisation, the same bundle is refused.
	if VerifyAgainst(b, "EAnotherOrganisationAltogether").Verified {
		t.Fatal("checked against another organisation, the bundle verified")
	}
	// And it survives being written out and read back as an exported file.
	raw, err := marshalBundle(b)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Read(raw)
	if err != nil {
		t.Fatal(err)
	}
	if r := Verify(back); !r.Verified {
		t.Fatalf("the exported file does not verify:\n%s", faultsOf(r))
	}
}

// Each kind of tampering with the whole bundle is refused, and the fault is
// found where the change was made.
func TestATamperedWholeBundleOfAConversationTheTrailWroteIsRefused(t *testing.T) {
	c := aMixedWholeConversation(t)
	b := c.export()
	if r := Verify(b); !r.Verified {
		t.Fatalf("the untampered bundle does not verify:\n%s", faultsOf(r))
	}
	words := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	attacker, err := didcomm.GenerateKeySet(c.world.agent.aid)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(b *Bundle)
		where  string
	}{
		{"a changed word of the person's kept statement", func(b *Bundle) { b.Entries[0].Body = words("what is the whether") }, "entry 1"},
		{"a changed word of the AI agent's reply", func(b *Bundle) { b.Entries[2].Body = words("wet and cold") }, "entry 3"},
		{"a dropped entry from the middle", func(b *Bundle) { b.Entries = append(b.Entries[:2:2], b.Entries[3:]...) }, "entry 3"},
		{"the newest entries dropped", func(b *Bundle) { b.Entries = b.Entries[:4] }, "anchor 1"},
		{"the AI agent's reply countersigned by another key", func(b *Bundle) {
			rec, err := agentmessage.Read(b.Entries[2].Envelope)
			if err != nil {
				t.Fatal(err)
			}
			if b.Entries[2].Envelope, err = agentmessage.Countersign(attacker, rec); err != nil {
				t.Fatal(err)
			}
		}, "entry 3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := copyOf(t, b)
			tc.change(changed)
			r := Verify(changed)
			if r.Verified {
				t.Fatalf("%s, and the whole bundle still verifies", tc.name)
			}
			if !strings.Contains(faultsOf(r), tc.where) {
				t.Fatalf("%s: no fault is found at %q:\n%s", tc.name, tc.where, faultsOf(r))
			}
		})
	}
}
