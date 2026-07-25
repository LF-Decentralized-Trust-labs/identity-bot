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
