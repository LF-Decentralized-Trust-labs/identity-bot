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
		{"reordered inside", []*didcomm.Envelope{c[0], c[2], c[1], c[3]}, 4, head, CopyRemovedOrReordered},
		{"another conversation's entry", append(append([]*didcomm.Envelope{}, c[:3]...), chainEntry(t, "c2", 4, agentmessage.Hash(c[2]), "s")), 4, head, CopyRemovedOrReordered},
		{"the last entry substituted", []*didcomm.Envelope{c[0], c[1], c[2], other}, 4, head, CopySubstituted},
		{"an entry before any is committed is uncommitted", c[:1], 0, "", CopyMatches},
		{"a head for a conversation with none committed", nil, 0, head, CopySubstituted},
	}
	for _, tt := range tests {
		got, err := CheckCopy("c1", tt.copy, tt.count, tt.head)
		if got != tt.outcome || (got == CopyMatches) != (err == nil) {
			t.Errorf("%s: %q, %v; want %q", tt.name, got, err, tt.outcome)
		}
	}
}
