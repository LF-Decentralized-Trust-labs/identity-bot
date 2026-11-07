package agentmessage

import (
	"encoding/json"
	"testing"

	"identity-agent-core/agentbody"
)

// When an app's back end speaks for a person, the record carries the person's
// own statement beside the app's signed request, and the record is held to it.
func TestARecordCarriesTheStatementAnAppSpokeWith(t *testing.T) {
	words := "hello"
	request, _ := json.Marshal(PersonMessage{Conversation: "c_person", To: "EAGENT_A", Body: words, Nonce: "n-1"})
	st, _, key := personFixture(t, words)
	st.Conversation, st.MessageID, st.To, st.From, st.Kind = "c_person", "n-1", "EAGENT_A", "EPERSON", PersonKindAsk
	sign := func(s PersonStatement) *PersonProof {
		_, vk, _ := agentbody.Identity(key)
		sig, err := agentbody.Sign(key, s.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		return &PersonProof{Statement: s, Verkey: vk, Signature: sig}
	}
	record := func(p *PersonProof) Record {
		proof := personProof(t, request)
		proof.RequestBytes, proof.PersonStatement = request, p
		return personRecord(proof, words)
	}
	if err := record(sign(st)).CheckSenderProof(); err != nil {
		t.Fatalf("a record with the person's statement was refused: %v", err)
	}
	if err := record(nil).CheckSenderProof(); err != nil {
		t.Fatalf("a record without one (a machine speaking as its signer) was refused: %v", err)
	}
	for name, edit := range map[string]func(*PersonStatement){
		"another conversation": func(s *PersonStatement) { s.Conversation = "c_other" },
		"another recipient":    func(s *PersonStatement) { s.To = "EAGENT_B" },
		"another message":      func(s *PersonStatement) { s.MessageID = "n-2" },
		"another person":       func(s *PersonStatement) { s.From = "EOTHER" },
		"another kind":         func(s *PersonStatement) { s.Kind = PersonKindMessage },
		"an answer":            func(s *PersonStatement) { s.InReplyTo = "e1" },
	} {
		s := st
		edit(&s)
		if err := record(sign(s)).CheckSenderProof(); err == nil {
			t.Errorf("a statement for %s was taken for the record's", name)
		}
	}
	forged := sign(st)
	forged.Statement.Fingerprint = HashBody([]byte("other"))
	if err := record(forged).CheckSenderProof(); err == nil {
		t.Error("a statement whose signature does not hold was taken")
	}
}
