package keriengine

import (
	"encoding/json"
	"strings"
	"testing"

	keri "github.com/grapeid/keri-go"
)

// Each kind's check of what is anchored still refuses an interaction that
// anchors another seal, even one in the right place and well formed.
func TestEveryKindsAnchorCheckRefusesAWrongSeal(t *testing.T) {
	e, reg, schema, holder := preparedWorld(t)
	issued, err := e.IssueCredentialInRegistry("issuer", map[string]interface{}{"role": "engineer"}, schema, holder, nil, reg)
	if err != nil {
		t.Fatal(err)
	}
	// An interaction at the tip anchoring a seal of something else.
	elsewhere := func(prior string, sn int) []byte {
		seal, err := eventSeal(issued.AcdcSaid, "0", issued.AcdcSaid)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := keri.BuildInteraction(keri.InteractionInput{Prefix: issued.AID, PriorSAID: prior, SN: sn,
			Data: []json.RawMessage{seal}})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	events := func(name string) int {
		kel, err := e.GetKel(name)
		if err != nil {
			t.Fatal(err)
		}
		return kel.EventCount
	}
	refused := func(kind, want string, err error, name string, before int) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: an interaction anchoring another seal: %v, want %q", kind, err, want)
		}
		if got := events(name); got != before {
			t.Fatalf("%s: a refused interaction was added: %d events, was %d", kind, got, before)
		}
	}
	before := events("issuer")

	r, err := e.PrepareRegistryInception("issuer")
	if err != nil {
		t.Fatal(err)
	}
	r.IxnRaw = elsewhere(r.Prior, r.SN)
	_, err = e.AppendPreparedRegistry("issuer", r)
	refused("registry", "does not anchor the prepared registry", err, "issuer", before)

	i, err := e.PrepareCredentialInRegistry("issuer", map[string]interface{}{"role": "other"}, schema, holder, nil, reg)
	if err != nil {
		t.Fatal(err)
	}
	i.IxnRaw = elsewhere(i.Prior, i.SN)
	_, err = e.AppendPreparedIssuance("issuer", i)
	refused("issuance", "does not anchor the prepared issuance", err, "issuer", before)

	v, err := e.PrepareRevocation("issuer", issued.AcdcSaid, reg)
	if err != nil {
		t.Fatal(err)
	}
	v.IxnRaw = elsewhere(v.Prior, v.SN)
	_, err = e.AppendPreparedRevocation("issuer", v)
	refused("revocation", "does not anchor the prepared revocation", err, "issuer", before)

	pub, next, _ := keys(t)
	d, err := e.PrepareDelegatedInception("issuer", pub, next, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	d.IxnRaw = elsewhere(d.Prior, d.SN)
	_, err = e.AppendPreparedDelegation("issuer", "agent", d, nil)
	refused("delegation", "does not approve the prepared inception", err, "issuer", before)

	// And each of them, unaltered, is still added.
	for name, add := range map[string]func() error{
		"registry": func() error {
			r, _ := e.PrepareRegistryInception("issuer")
			_, err := e.AppendPreparedRegistry("issuer", r)
			return err
		},
		"revocation": func() error {
			v, _ := e.PrepareRevocation("issuer", issued.AcdcSaid, reg)
			_, err := e.AppendPreparedRevocation("issuer", v)
			return err
		},
	} {
		if err := add(); err != nil {
			t.Fatalf("an unaltered %s: %v", name, err)
		}
	}
}
