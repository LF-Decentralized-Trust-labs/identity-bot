package server

import (
	"encoding/json"
	"strings"
	"testing"

	"identity-agent-core/didcomm"
	"identity-agent-core/store"
)

func credentialBody(t *testing.T, said string) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(credentialDelivery{
		SAID: said, AcdcJSON: `{"v":"ACDC10JSON","d":"` + said + `"}`,
		CredentialType: "employment",
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The issuer is whoever the envelope says sent it, never what the body claims.
// The old path took the issuer from a field an attacker could write.
func TestTheIssuerComesFromTheEnvelopeNotTheBody(t *testing.T) {
	s := agentWithDerivedIdentity(t)
	_ = s.DataStore.SaveContact(store.ContactRecord{AID: "EREALISSUER", Status: "accepted"})

	// A body that tries to name a different issuer — the field does not exist,
	// so there is nothing to honour even if a sender adds one.
	raw := []byte(`{"said":"ECRED1","acdc_json":"{}","issuer_aid":"ESOMEBODY-TRUSTED","credential_type":"employment"}`)

	if err := (credentialIssuance{}).Perform(s, InboundMessage{
		ToAID: "EOURS", FromAID: "EREALISSUER", Type: didcomm.TypeCredentialIssuance, Body: raw,
	}); err != nil {
		t.Fatalf("a credential from an accepted contact was refused: %v", err)
	}

	got, err := s.DataStore.GetCredential("ECRED1")
	if err != nil || got == nil {
		t.Fatal("the credential was not kept")
	}
	if got.IssuerAID != "EREALISSUER" {
		t.Fatalf("issuer recorded as %q — the body was believed over the envelope", got.IssuerAID)
	}
	if got.Status != "pending_inbound" {
		t.Errorf("status %q, want pending_inbound — it should wait to be accepted", got.Status)
	}
}

// Being able to open an envelope to us means a relationship exists. It does not
// mean anyone agreed to receive things from them.
func TestACredentialFromSomebodyWhoIsNotAContactIsRefused(t *testing.T) {
	s := agentWithDerivedIdentity(t)
	err := (credentialIssuance{}).Perform(s, InboundMessage{
		ToAID: "EOURS", FromAID: "ESTRANGER", Body: credentialBody(t, "ECRED2"),
	})
	if err == nil {
		t.Fatal("a stranger put a credential in front of the owner")
	}
	if !strings.Contains(err.Error(), "not a contact") {
		t.Errorf("the reason is unclear: %v", err)
	}
	if got, _ := s.DataStore.GetCredential("ECRED2"); got != nil {
		t.Error("it was kept anyway")
	}
}

// A credential missing what makes it a credential is refused rather than stored
// as an empty record somebody later has to explain.
func TestAnIncompleteCredentialIsRefused(t *testing.T) {
	s := agentWithDerivedIdentity(t)
	_ = s.DataStore.SaveContact(store.ContactRecord{AID: "EISSUER", Status: "accepted"})

	for _, body := range []string{`{"acdc_json":"{}"}`, `{"said":"ECRED3"}`, `not json`} {
		if err := (credentialIssuance{}).Perform(s, InboundMessage{
			FromAID: "EISSUER", Body: []byte(body),
		}); err == nil {
			t.Errorf("accepted: %s", body)
		}
	}
}

// The action must be reachable, or it is a handler nothing can deliver to.
func TestCredentialIssuanceIsRegisteredAndDeliverable(t *testing.T) {
	a, ok := lookupInboundAction(didcomm.TypeCredentialIssuance)
	if !ok {
		t.Fatal("nothing is registered for credential issuance")
	}
	if a.Type() != didcomm.TypeCredentialIssuance {
		t.Errorf("registered under %q", a.Type())
	}
	if !didcomm.KnownType(a.Type()) {
		t.Error("the envelope layer would reject this type, so nothing could ever deliver it")
	}
}
