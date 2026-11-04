package keymath

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/presentation"
)

func credentialBytes(t *testing.T, issuer, recipient string) []byte {
	t.Helper()
	raw, err := keri.BuildCredential(keri.CredentialInput{SchemaSAID: "Eschema", Issuer: issuer,
		Recipient: recipient, Data: json.RawMessage(`{"name":"Ada","dt":"2026-11-04T00:00:00.000000+00:00"}`)})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func ask(op string, raw []byte) ([]byte, error) {
	req, _ := json.Marshal(map[string]string{"raw_b64": base64.StdEncoding.EncodeToString(raw)})
	return Do(op, req)
}

// A credential is read with its identifier checked, and says who issued it, to
// whom, and under which schema; one changed after it was identified is refused.
func TestACredentialIsReadAndItsIdentifierChecked(t *testing.T) {
	raw := credentialBytes(t, "Eissuer", "Eholder")
	out, err := ask("check_credential", raw)
	if err != nil {
		t.Fatal(err)
	}
	var c Credential
	if err := json.Unmarshal(out, &c); err != nil {
		t.Fatal(err)
	}
	want, _ := keri.VerifyCredential(raw)
	if c.SAID != want.SAID || c.Issuer != "Eissuer" || c.Recipient != "Eholder" || c.Schema != "Eschema" {
		t.Fatalf("read %+v", c)
	}
	if _, err := ask("check_credential", []byte(strings.Replace(string(raw), "Ada", "Bob", 1))); err == nil {
		t.Fatal("a credential changed after it was identified was read")
	}
}

// A presentation is read only as its one serialisation, and a key event is
// never one.
func TestAPresentationIsReadAndAKeyEventIsNot(t *testing.T) {
	_, raw, err := presentation.Build("Ecred", "Eholder", "Eissuer", "")
	if err != nil {
		t.Fatal(err)
	}
	out, err := ask("check_presentation", raw)
	if err != nil {
		t.Fatal(err)
	}
	var p Presentation
	if err := json.Unmarshal(out, &p); err != nil || p.Credential != "Ecred" || p.Holder != "Eholder" || p.Issuer != "Eissuer" {
		t.Fatalf("read %+v %v", p, err)
	}
	var withExtra map[string]any
	json.Unmarshal(raw, &withExtra)
	withExtra["t"] = "ixn"
	extra, _ := json.Marshal(withExtra)
	if _, err := ask("check_presentation", extra); err == nil {
		t.Fatal("a presentation carrying an event type was read")
	}
	ixn, err := keri.BuildInteraction(keri.InteractionInput{Prefix: "Eprefix", PriorSAID: "Eprior", SN: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ask("check_presentation", ixn); err == nil {
		t.Fatal("a key event was read as a presentation")
	}
	// A field beyond the presentation's own changes no identifier, so only the
	// one-serialisation check refuses it.
	withExtra = map[string]any{}
	json.Unmarshal(raw, &withExtra)
	delete(withExtra, "t")
	withExtra["x"] = "unsigned extra"
	extra, _ = json.Marshal(withExtra)
	if _, err := ask("check_presentation", extra); err == nil {
		t.Fatal("a presentation with a field of its own beyond the format was read")
	}
	if _, err := ask("check_presentation", []byte(strings.Replace(string(raw), "Ecred", "Eother", 1))); err == nil {
		t.Fatal("a presentation changed after it was identified was read")
	}
}
