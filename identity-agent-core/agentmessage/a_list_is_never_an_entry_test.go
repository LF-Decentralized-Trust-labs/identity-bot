package agentmessage

import (
	"testing"

	"identity-agent-core/agentbody"
)

// A list a person signed is answered and spent, never kept in a trail: a record
// that carries one as a person's entry is refused, even when it says exactly
// what the statement said (ADR-072 Amendment 15).
func TestAListIsNeverAnEntryOfATrail(t *testing.T) {
	st, _, key := personFixture(t, "")
	st.Kind, st.Conversation, st.To, st.Audience = PersonKindList, ListConversation, "", "the-central-place"
	if err := st.Check(); err != nil {
		t.Fatalf("the list itself is not well formed: %v", err)
	}
	_, vk, _ := agentbody.Identity(key)
	sig, err := agentbody.Sign(key, st.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	r := Record{MessageID: "e1", Conversation: ListConversation, Seq: 1, IATime: "2026-11-06T10:00:01Z",
		Kind: PersonKindList, From: Person(st.From), BodyHash: st.Fingerprint,
		PersonProof: &PersonProof{Statement: st, Verkey: vk, Signature: sig}}
	if err := r.PersonProof.Verify(); err != nil {
		t.Fatalf("the list's signature does not hold, so the test proves nothing: %v", err)
	}
	if err := r.CheckSenderProof(); err == nil {
		t.Fatal("a list was taken as a person's entry")
	}
}
