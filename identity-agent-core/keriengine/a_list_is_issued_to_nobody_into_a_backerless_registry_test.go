package keriengine

import (
	"encoding/base64"
	"strings"
	"testing"

	keri "github.com/grapeid/keri-go"
)

// A public statement is issued into a registry that can never have backers, and
// to nobody: the registry says so in its own inception, the credential's
// attribute block has no holder, and the issuer is not made its own holder.
func TestAPublicStatementIsIssuedToNobodyIntoABackerlessRegistry(t *testing.T) {
	e := New()
	pub, next, _ := keys(t)
	inc, err := e.CreateInceptionNamed(pub, next, "publisher")
	if err != nil {
		t.Fatal(err)
	}
	reg, err := e.InceptBackerlessRegistry("publisher")
	if err != nil {
		t.Fatal(err)
	}
	vcp, _ := base64.StdEncoding.DecodeString(reg.VcpJsonB64)
	ev, err := keri.VerifyTELEvent(vcp)
	if err != nil {
		t.Fatal(err)
	}
	if len(ev.Traits) != 1 || ev.Traits[0] != "NB" || len(ev.Backers) != 0 || ev.BackerThreshold != "0" || ev.Issuer != inc.AID {
		t.Fatalf("the registry is %+v", ev)
	}
	if !strings.Contains(string(vcp), `"c":["NB"],"bt":"0","b":[]`) {
		t.Fatalf("not written as keripy writes a backerless registry: %s", vcp)
	}

	schema, _ := keri.Blake3SAID([]byte("a test schema"))
	got, err := e.IssueUntargetedCredentialInRegistry("publisher", map[string]interface{}{"sequence": 7}, schema, reg.RegistrySaid)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(got.AcdcJsonB64)
	cred, err := keri.VerifyCredential(raw)
	if err != nil {
		t.Fatal(err)
	}
	if cred.Recipient != "" || strings.Contains(string(cred.Attributes), `"i"`) {
		t.Fatalf("the credential names a holder: %s", raw)
	}
	if cred.Issuer != inc.AID || cred.Registry != reg.RegistrySaid {
		t.Fatalf("issuer %s registry %s", cred.Issuer, cred.Registry)
	}
	// and it can be withdrawn
	if _, err := e.RevokeCredential("publisher", got.AcdcSaid, reg.RegistrySaid, ""); err != nil {
		t.Fatalf("withdrawing: %v", err)
	}
}

// A registry that is not backerless says nothing of the kind, so the two are
// different registries.
func TestARegistryWithoutTheTraitIsNotBackerless(t *testing.T) {
	e := New()
	pub, next, _ := keys(t)
	if _, err := e.CreateInceptionNamed(pub, next, "x"); err != nil {
		t.Fatal(err)
	}
	reg, err := e.InceptRegistry("x")
	if err != nil {
		t.Fatal(err)
	}
	vcp, _ := base64.StdEncoding.DecodeString(reg.VcpJsonB64)
	ev, _ := keri.VerifyTELEvent(vcp)
	if len(ev.Traits) != 0 {
		t.Fatalf("traits %v", ev.Traits)
	}
}
