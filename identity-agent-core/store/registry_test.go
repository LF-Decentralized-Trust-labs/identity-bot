package store

import "testing"

func TestCredentialRegistryRoundTrip(t *testing.T) {
	s, err := NewSQLiteStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if r, err := s.GetRegistryByIssuer("EIssuer"); err != nil || r != nil {
		t.Fatalf("expected no registry initially, got %v err=%v", r, err)
	}
	if err := s.SaveRegistry(CredentialRegistry{RegistrySAID: "EReg1", IssuerAID: "EIssuer", VcpJson: "{}", CreatedAt: "now"}); err != nil {
		t.Fatal(err)
	}
	r, err := s.GetRegistryByIssuer("EIssuer")
	if err != nil || r == nil || r.RegistrySAID != "EReg1" {
		t.Fatalf("registry round-trip failed: %v err=%v", r, err)
	}
	// TEL fields on a credential round-trip.
	if err := s.SaveCredential(CredentialRecord{SAID: "ECred", Status: "issued", RegistrySAID: "EReg1", IssSAID: "EIss1"}); err != nil {
		t.Fatal(err)
	}
	c, err := s.GetCredential("ECred")
	if err != nil || c == nil || c.RegistrySAID != "EReg1" || c.IssSAID != "EIss1" {
		t.Fatalf("credential TEL fields round-trip failed: %+v err=%v", c, err)
	}
}

// A credential's log keeps each event once, reads back in order, survives a
// reopen, and refuses a second, different event at a place already taken.
func TestACredentialLogIsKeptOnceInOrderAndDoesNotFork(t *testing.T) {
	dir := t.TempDir()
	s, err := NewSQLiteStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	iss := CredentialTELEvent{RegistrySAID: "EReg", AcdcSAID: "ECred", Seq: 0, SAID: "EIss", Kind: "iss", RawB64: "aXNz"}
	rev := CredentialTELEvent{RegistrySAID: "EReg", AcdcSAID: "ECred", Seq: 1, SAID: "ERev", Kind: "rev", RawB64: "cmV2"}
	for _, ev := range []CredentialTELEvent{rev, iss, iss} {
		if err := s.AppendCredentialTELEvent(ev); err != nil {
			t.Fatal(err)
		}
	}
	forked := rev
	forked.SAID, forked.RawB64 = "ERevOther", "b3RoZXI="
	if err := s.AppendCredentialTELEvent(forked); err == nil {
		t.Fatal("a second revocation at the same place was kept")
	}
	again, err := NewSQLiteStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := again.GetCredentialTEL("EReg", "ECred")
	if err != nil || len(got) != 2 || got[0].SAID != "EIss" || got[1].SAID != "ERev" {
		t.Fatalf("log read back as %+v %v; want the issuance then the revocation", got, err)
	}
	if err := again.SaveRegistry(CredentialRegistry{RegistrySAID: "EReg", IssuerAID: "EI", VcpRawB64: "dmNw"}); err != nil {
		t.Fatal(err)
	}
	if err := again.SaveRegistry(CredentialRegistry{RegistrySAID: "EReg", IssuerAID: "EI", VcpJson: "{}"}); err != nil {
		t.Fatal(err)
	}
	if r, _ := again.GetRegistry("EReg"); r == nil || r.VcpRawB64 != "dmNw" {
		t.Fatalf("a later save without the bytes wiped the kept inception: %+v", r)
	}
}
