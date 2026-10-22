package mobilecore

import (
	"fmt"
	"os"
	"strings"

	"identity-agent-core/relay"
)

// Naming the relays this Identity Agent is reached through.
//
// The core bundles no relay operator. A product that runs one, or has chosen
// one, names it here so the embedded core can be reached without the person
// having to type an address first: the private relay for per-relationship
// addresses, the public relay for a public name. Either may be empty, which
// leaves it unnamed. A relay the person chooses in settings still wins.
//
// Must be called before StartServer, which reads them once.
func DeclareRelays(privateRelay, publicRelay string) error {
	relays := []struct{ env, value string }{
		{"RELAY_BASE_URL", strings.TrimRight(strings.TrimSpace(privateRelay), "/")},
		{"PUBLIC_RELAY_BASE_URL", strings.TrimRight(strings.TrimSpace(publicRelay), "/")},
	}
	// Both are checked before either is set, so a bad one never leaves the
	// other half applied.
	for _, r := range relays {
		if r.value == "" {
			continue
		}
		if err := relay.CheckBaseURL(r.value); err != nil {
			return fmt.Errorf("%q is not an https address of a relay", r.value)
		}
	}
	for _, r := range relays {
		if r.value == "" || strings.TrimSpace(os.Getenv(r.env)) != "" {
			continue
		}
		if err := os.Setenv(r.env, r.value); err != nil {
			return err
		}
	}
	return nil
}
