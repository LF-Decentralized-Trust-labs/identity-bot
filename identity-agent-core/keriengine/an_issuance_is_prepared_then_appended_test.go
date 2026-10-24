package keriengine

import (
	"errors"
	"testing"

	"identity-agent-core/drivers"

	keri "github.com/grapeid/keri-go"
)

func preparedWorld(t *testing.T) (*Engine, string, string, string) {
	t.Helper()
	e := New()
	pub, next, _ := keys(t)
	if _, err := e.CreateInceptionNamed(pub, next, "issuer"); err != nil {
		t.Fatal(err)
	}
	reg, err := e.InceptRegistry("issuer")
	if err != nil {
		t.Fatal(err)
	}
	schema, _ := keri.Blake3SAID([]byte("a test schema"))
	return e, reg.RegistrySaid, schema, "EHolder000000000000000000000000000000000000"
}

// An issuance prepared and appended later is appended exactly as prepared.
func TestAPreparedIssuanceIsAppendedAsPrepared(t *testing.T) {
	e, reg, schema, holder := preparedWorld(t)
	p, err := e.PrepareCredentialInRegistry("issuer", map[string]interface{}{"role": "engineer"}, schema, holder, nil, reg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.AppendPreparedIssuance("issuer", p)
	if err != nil {
		t.Fatal(err)
	}
	if got.AcdcSaid != p.AcdcSAID || got.IxnSaid != p.IxnSAID || got.IssSaid != p.IssSAID || got.SequenceNumber != p.SN {
		t.Fatalf("appended %+v, prepared %+v", got, p)
	}
	if _, err := e.AppendPreparedIssuance("issuer", p); !errors.Is(err, drivers.ErrStalePreparation) {
		t.Fatalf("the same preparation appended twice: %v", err)
	}
}

// A preparation the key log has moved past is refused.
func TestAStalePreparationIsRefused(t *testing.T) {
	e, reg, schema, holder := preparedWorld(t)
	p, err := e.PrepareCredentialInRegistry("issuer", map[string]interface{}{"role": "engineer"}, schema, holder, nil, reg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.IssueCredentialInRegistry("issuer", map[string]interface{}{"role": "other"}, schema, holder, nil, reg); err != nil {
		t.Fatal(err)
	}
	if _, err := e.AppendPreparedIssuance("issuer", p); !errors.Is(err, drivers.ErrStalePreparation) {
		t.Fatalf("a stale preparation: %v", err)
	}
}

// A preparation altered after it was made is refused.
func TestAnAlteredPreparationIsRefused(t *testing.T) {
	e, reg, schema, holder := preparedWorld(t)
	p, _ := e.PrepareCredentialInRegistry("issuer", map[string]interface{}{"role": "engineer"}, schema, holder, nil, reg)
	other, _ := e.PrepareCredentialInRegistry("issuer", map[string]interface{}{"role": "other"}, schema, holder, nil, reg)
	swapped := *p
	swapped.IssRaw, swapped.IssSAID = other.IssRaw, other.IssSAID
	if _, err := e.AppendPreparedIssuance("issuer", &swapped); err == nil {
		t.Fatal("an interaction appended with another credential's issuance")
	}
	swapped = *p
	swapped.AcdcRaw, swapped.AcdcSAID = other.AcdcRaw, other.AcdcSAID
	if _, err := e.AppendPreparedIssuance("issuer", &swapped); err == nil {
		t.Fatal("an interaction appended with another credential")
	}
	if _, err := e.AppendPreparedIssuance("issuer", p); err != nil {
		t.Fatalf("the unaltered preparation: %v", err)
	}
}
