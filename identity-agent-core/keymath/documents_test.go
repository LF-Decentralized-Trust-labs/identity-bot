package keymath

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
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

// A credential names every top-level field it carries, so a caller can refuse
// a rules block, a salt or an unknown field it did not ask for, and a document
// with an event type is not a credential at all.
func TestACredentialNamesEveryFieldItCarries(t *testing.T) {
	read := func(raw []byte) []string {
		t.Helper()
		out, err := ask("check_credential", raw)
		if err != nil {
			t.Fatal(err)
		}
		var c Credential
		if err := json.Unmarshal(out, &c); err != nil {
			t.Fatal(err)
		}
		return c.Fields
	}
	plain := read(credentialBytes(t, "Eissuer", "Eholder"))
	if strings.Join(plain, ",") != "a,d,i,s,v" {
		t.Fatalf("a plain credential carries %v", plain)
	}

	withRules, err := keri.BuildCredential(keri.CredentialInput{SchemaSAID: "Eschema", Issuer: "Eissuer", Recipient: "Eholder",
		Data:  json.RawMessage(`{"name":"Ada","dt":"2026-11-04T00:00:00.000000+00:00"}`),
		Rules: json.RawMessage(`{"d":"","waiver":"the issuer accepts all liability"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(read(withRules), ","); got != "a,d,i,r,s,v" {
		t.Fatalf("a credential with a rules block carries %v", got)
	}
	private, err := keri.BuildCredential(keri.CredentialInput{SchemaSAID: "Eschema", Issuer: "Eissuer", Recipient: "Eholder",
		Data: json.RawMessage(`{"name":"Ada","dt":"2026-11-04T00:00:00.000000+00:00"}`), Private: true, Salt: "0AAAAAAAAAAAAAAAAAAAAAAA"})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(read(private), ","); !strings.Contains(got, "u") {
		t.Fatalf("a credential with a salt carries %v", got)
	}

	// An unknown field and an event type, each with the identifier recomputed
	// so that nothing but the field itself is wrong.
	raw := credentialBytes(t, "Eissuer", "Eholder")
	for name, insert := range map[string]string{"unknown": `"z":"x",`, "event type": `"t":"iss",`} {
		hostile := withFieldAndIdentifier(t, raw, insert)
		out, err := ask("check_credential", hostile)
		if name == "event type" {
			if err == nil {
				t.Fatalf("a document with an event type was read as a credential: %s", out)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var c Credential
		json.Unmarshal(out, &c)
		if got := strings.Join(c.Fields, ","); got != "a,d,i,s,v,z" {
			t.Fatalf("a credential with an unknown field carries %v", got)
		}
	}
}

// withFieldAndIdentifier is raw with insert (a `"name":value,` member) after
// its version string, its length and its identifier made right again.
func withFieldAndIdentifier(t *testing.T, raw []byte, insert string) []byte {
	t.Helper()
	c, err := keri.VerifyCredential(raw)
	if err != nil {
		t.Fatal(err)
	}
	blank := strings.Repeat("#", len(c.SAID))
	s := strings.Replace(string(raw), `"d":"`+c.SAID+`"`, `"d":"`+blank+`"`, 1)
	at := strings.Index(s, `",`) + 2
	s = s[:at] + insert + s[at:]
	s = s[:16] + fmt.Sprintf("%06x", len(s)) + s[22:]
	said, err := keri.Blake3SAID([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return []byte(strings.Replace(s, blank, said, 1))
}
