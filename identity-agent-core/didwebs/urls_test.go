package didwebs

import "testing"

func TestDeriveFromDID(t *testing.T) {
	u, err := DeriveFromDID("did:webs:alice.example.com:EAliceAID0123456789ABCDEFGHIJK")
	if err != nil {
		t.Fatal(err)
	}
	want := "https://alice.example.com/EAliceAID0123456789ABCDEFGHIJK/did.json"
	if u.DidJSONURL != want {
		t.Fatalf("did.json url: %s want %s", u.DidJSONURL, want)
	}
	if u.CesrURL != "https://alice.example.com/EAliceAID0123456789ABCDEFGHIJK/keri.cesr" {
		t.Fatalf("cesr url: %s", u.CesrURL)
	}
}
