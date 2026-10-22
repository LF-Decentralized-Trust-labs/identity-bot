package mobilecore

import (
	"os"
	"testing"
)

func TestAnAppNamesItsRelays(t *testing.T) {
	t.Setenv("RELAY_BASE_URL", "")
	t.Setenv("PUBLIC_RELAY_BASE_URL", "")
	if err := DeclareRelays("https://relay.example.org/", "https://example.org"); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("RELAY_BASE_URL"); got != "https://relay.example.org" {
		t.Fatalf("private relay: %q", got)
	}
	if got := os.Getenv("PUBLIC_RELAY_BASE_URL"); got != "https://example.org" {
		t.Fatalf("public relay: %q", got)
	}
}

func TestTheEnvironmentStillWins(t *testing.T) {
	t.Setenv("RELAY_BASE_URL", "https://mine.example.net")
	t.Setenv("PUBLIC_RELAY_BASE_URL", "")
	if err := DeclareRelays("https://relay.example.org", ""); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("RELAY_BASE_URL"); got != "https://mine.example.net" {
		t.Fatalf("private relay: %q", got)
	}
	if got := os.Getenv("PUBLIC_RELAY_BASE_URL"); got != "" {
		t.Fatalf("an empty public relay was named: %q", got)
	}
}

func TestARelayIsAnHTTPSAddress(t *testing.T) {
	t.Setenv("RELAY_BASE_URL", "")
	for _, bad := range []string{"http://relay.example.org", "relay.example.org", "https://"} {
		if err := DeclareRelays(bad, ""); err == nil {
			t.Fatalf("%q was accepted", bad)
		}
	}
}
