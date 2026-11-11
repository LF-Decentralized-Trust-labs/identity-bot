package conversationbundle

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"identity-agent-core/agentmessage"
	"identity-agent-core/didcomm"
)

// An envelope Read can open and Hash can hash. CheckCopy reads the chain, so
// the countersignature itself is not what these entries test.
func chainEntry(t *testing.T, conversation string, seq int, prev, sig string) *didcomm.Envelope {
	t.Helper()
	body, err := json.Marshal(agentmessage.Record{MessageID: fmt.Sprintf("e%d", seq), Conversation: conversation, Seq: seq, PrevHash: prev})
	if err != nil {
		t.Fatal(err)
	}
	plain, err := json.Marshal(didcomm.JWM{ID: fmt.Sprintf("e%d", seq), Type: agentmessage.TypeRecord, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	return &didcomm.Envelope{Mode: "signed", Plain: base64.RawURLEncoding.EncodeToString(plain), EdSig: sig, DsaSig: "d"}
}

func chainOf(t *testing.T, conversation string, n int) []*didcomm.Envelope {
	var out []*didcomm.Envelope
	prev := ""
	for i := 1; i <= n; i++ {
		e := chainEntry(t, conversation, i, prev, "s")
		out = append(out, e)
		prev = agentmessage.Hash(e)
	}
	return out
}

func headOf(es []*didcomm.Envelope) string {
	if len(es) == 0 {
		return ""
	}
	return agentmessage.Hash(es[len(es)-1])
}

// The four outcomes of checking an app's copy against the Identity Agent's
// head and count (contracts/trail).
func TestAnAppsCopyIsCheckedAgainstTheHeadAndCount(t *testing.T) {
	c := chainOf(t, "c1", 4)
	head := headOf(c)
	other := chainEntry(t, "c1", 4, agentmessage.Hash(c[2]), "forged")
	tests := []struct {
		name    string
		copy    []*didcomm.Envelope
		count   int
		head    string
		outcome CopyOutcome
	}{
		{"the committed chain", c, 4, head, CopyMatches},
		{"an empty conversation", nil, 0, "", CopyMatches},
		{"an uncommitted entry beyond the count is left out", append(append([]*didcomm.Envelope{}, c...), chainEntry(t, "c1", 5, head, "s")), 4, head, CopyMatches},
		{"removed from the end", c[:3], 4, head, CopyRemovedFromTheEnd},
		{"everything removed", nil, 4, head, CopyRemovedFromTheEnd},
		{"removed inside", []*didcomm.Envelope{c[0], c[2], c[3]}, 4, head, CopyRemovedOrReordered},
		{"reordered in the copy but chained", []*didcomm.Envelope{c[0], c[2], c[1], c[3]}, 4, head, CopyMatches},
		{"another conversation's entry", append(append([]*didcomm.Envelope{}, c[:3]...), chainEntry(t, "c2", 4, agentmessage.Hash(c[2]), "s")), 4, head, CopyRemovedOrReordered},
		{"the last entry substituted", []*didcomm.Envelope{c[0], c[1], c[2], other}, 4, head, CopySubstituted},
		{"an entry inside the chain substituted shows as removed or reordered inside", []*didcomm.Envelope{c[0], chainEntry(t, "c1", 2, agentmessage.Hash(c[0]), "forged"), c[2], c[3]}, 4, head, CopyRemovedOrReordered},
		{"any order", []*didcomm.Envelope{c[3], c[1], c[0], c[2]}, 4, head, CopyMatches},
		{"an entry before any is committed is uncommitted", c[:1], 0, "", CopyMatches},
		{"a head for a conversation with none committed", nil, 0, head, CopySubstituted},
	}
	for _, tt := range tests {
		got, err := CheckCopy("c1", tt.copy, tt.count, tt.head, nil)
		if got.Outcome != tt.outcome || (got.Outcome == CopyMatches) != (err == nil) {
			t.Errorf("%s: %q, %v; want %q", tt.name, got.Outcome, err, tt.outcome)
		}
	}
}

// Every entry is kept by the app before it is committed, so two writes racing for
// one place are both held until the loser is discarded by its hash: the copy
// holds more than one entry for a place, and it still matches (ADR-068).
func TestACopyMayHoldTheLoserOfARaceForAPlace(t *testing.T) {
	c := chainOf(t, "c1", 4)
	head := headOf(c)
	loser2 := chainEntry(t, "c1", 2, agentmessage.Hash(c[0]), "lost")
	loser4 := chainEntry(t, "c1", 4, agentmessage.Hash(c[2]), "lost")
	for name, copy := range map[string][]*didcomm.Envelope{
		"loser kept first":     {c[0], loser2, c[1], c[2], loser4, c[3]},
		"loser kept last":      {c[0], c[1], c[2], c[3], loser2, loser4},
		"any order":            {loser4, c[3], loser2, c[2], c[1], c[0]},
		"the same entry twice": {c[0], c[1], c[1], c[2], c[3]},
	} {
		got, err := CheckCopy("c1", copy, 4, head, nil)
		if err != nil || got.Outcome != CopyMatches || len(got.Committed) != 4 {
			t.Fatalf("%s: %q, %v, %d committed", name, got.Outcome, err, len(got.Committed))
		}
		for i, e := range got.Committed {
			if agentmessage.Hash(e) != agentmessage.Hash(c[i]) {
				t.Fatalf("%s: place %d is not the committed entry", name, i+1)
			}
		}
		if name != "the same entry twice" && len(got.Ignored) != 2 {
			t.Fatalf("%s: %d ignored, want the 2 losers", name, len(got.Ignored))
		}
		if name == "the same entry twice" && len(got.Ignored) != 0 {
			t.Fatalf("%s: one entry twice is one entry, but %d ignored", name, len(got.Ignored))
		}
	}
	// A loser at a place with nothing committed before it does not make a
	// removed-from-the-end copy look whole.
	if got, _ := CheckCopy("c1", []*didcomm.Envelope{c[0], loser2}, 4, head, nil); got.Outcome != CopyRemovedFromTheEnd {
		t.Fatalf("a copy holding a loser instead of the committed entry: %q", got.Outcome)
	}
	// A race lost at the last place, the committed one missing: the head is not here.
	if got, _ := CheckCopy("c1", []*didcomm.Envelope{c[0], c[1], c[2], loser4}, 4, head, nil); got.Outcome != CopySubstituted {
		t.Fatalf("a copy holding only the loser at the end: %q", got.Outcome)
	}
}

func TestACopyIsAskedForEveryCommittedEntrysCountersignature(t *testing.T) {
	c := chainOf(t, "c1", 3)
	loser := chainEntry(t, "c1", 2, agentmessage.Hash(c[0]), "lost")
	var asked []*didcomm.Envelope
	got, err := CheckCopy("c1", append([]*didcomm.Envelope{loser}, c...), 3, headOf(c), func(e *didcomm.Envelope) error { asked = append(asked, e); return nil })
	if err != nil || !got.SignaturesChecked || len(asked) != 3 {
		t.Fatalf("%v, checked %v, asked %d", err, got.SignaturesChecked, len(asked))
	}
	got, err = CheckCopy("c1", c, 3, headOf(c), func(e *didcomm.Envelope) error { return fmt.Errorf("no") })
	if err == nil || got.Outcome != CopyNotCountersigned || got.SignaturesChecked || len(got.Committed) != 0 {
		t.Fatalf("an entry that is not countersigned: %q, %v", got.Outcome, err)
	}
	if got, _ := CheckCopy("c1", c, 3, headOf(c), nil); got.Outcome != CopyMatches || got.SignaturesChecked {
		t.Fatalf("with no check given the result must say none was made: %+v", got)
	}
}
