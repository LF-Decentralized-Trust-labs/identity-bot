package agentmessage

import (
	"testing"

	"identity-agent-core/agentbody"
)

// When an app speaks for a person the proof kept holds their statement and not
// the request that carries their words: the record is checked against the
// statement alone, and one that carries the request after all is refused.
func TestAnAppsProofForAPersonKeepsTheStatementNeverTheRequest(t *testing.T) {
	words := "hello"
	st, _, key := personFixture(t, words)
	st.Conversation, st.MessageID, st.To, st.From, st.Kind = "c_person", "n-1", "EAGENT_A", "EPERSON", PersonKindAsk
	_, vk, _ := agentbody.Identity(key)
	sign := func(s PersonStatement) *PersonProof {
		sig, err := agentbody.Sign(key, s.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		return &PersonProof{Statement: s, Verkey: vk, Signature: sig}
	}
	record := func(edit func(*ControllerProof, *Record)) Record {
		proof := ControllerProof{Controller: "EAPPHOST", PublicKey: vk, AppBody: "EBODY", PersonStatement: sign(st)}
		r := personRecord(proof, words)
		r.BodyHash = st.Fingerprint
		if edit != nil {
			edit(r.ControllerProof, &r)
		}
		return r
	}
	good := record(nil)
	if !good.ControllerProof.StatementOnly() {
		t.Fatal("a proof with the app's body and no signed request is not statement-only")
	}
	if err := good.CheckSenderProof(); err != nil {
		t.Fatalf("a record that keeps only the statement was refused: %v", err)
	}
	if v, ok := good.FingerprintVersion(); !ok || v != FingerprintV1 {
		t.Errorf("the entry's fingerprint version is %d, %v, not the statement's", v, ok)
	}
	for name, edit := range map[string]func(*ControllerProof, *Record){
		"request bytes kept":   func(p *ControllerProof, _ *Record) { p.RequestBytes = []byte(`{"body":"hello"}`) },
		"request kept as JSON": func(p *ControllerProof, _ *Record) { p.Request = []byte(`{"body":"hello"}`) },
		"the app's signed request with the words": func(p *ControllerProof, _ *Record) {
			p.SignedString, p.Signature, p.RequestBytes = "IA-BODY-REQ-V3", "sig", []byte(`{"body":"hello"}`)
		},
		"the app's signed request without the words": func(p *ControllerProof, _ *Record) {
			p.SignedString, p.Signature = "IA-BODY-REQ-V3", "sig"
		},
		"no statement":          func(p *ControllerProof, _ *Record) { p.PersonStatement = nil },
		"a digest of the words": func(_ *ControllerProof, r *Record) { r.BodyHash = HashBody([]byte(words)) },
		"another recipient":     func(_ *ControllerProof, r *Record) { r.To = "EAGENT_B" },
		"another conversation":  func(_ *ControllerProof, r *Record) { r.Conversation = "c_other" },
	} {
		r := record(edit)
		if err := r.CheckSenderProof(); err == nil {
			t.Errorf("a proof with %s was taken", name)
		}
	}
}
