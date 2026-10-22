package mobilecore

import (
	"fmt"
	"net/url"
	"os"
	"strings"
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
	for _, r := range []struct{ env, value string }{
		{"RELAY_BASE_URL", privateRelay},
		{"PUBLIC_RELAY_BASE_URL", publicRelay},
	} {
		v := strings.TrimRight(strings.TrimSpace(r.value), "/")
		if v == "" {
			continue
		}
		if u, err := url.Parse(v); err != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("%q is not an https address of a relay", r.value)
		}
		if strings.TrimSpace(os.Getenv(r.env)) != "" {
			continue
		}
		if err := os.Setenv(r.env, v); err != nil {
			return err
		}
	}
	return nil
}
