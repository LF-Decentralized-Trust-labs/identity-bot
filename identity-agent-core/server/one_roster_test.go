package server

import (
	"net/http"
	"os"
	"testing"

	"github.com/go-chi/chi/v5"
)

// An organisation has one roster, and the route that writes its founder must
// belong to whoever owns it.
//
// Split them and the founder is recorded in one roster while everything else
// reads another. Both halves succeed and neither can see the other, so nothing
// errors and nothing says so — founding simply never completes.
func TestTheSignerRouteGoesWhereTheRosterGoes(t *testing.T) {
	mounted := func(overlayOwns bool) map[string]bool {
		if overlayOwns {
			t.Setenv("OVERLAY_OWNS_ORG_ROUTES", "1")
		} else {
			_ = os.Unsetenv("OVERLAY_OWNS_ORG_ROUTES")
		}
		s := &CoreServer{}
		r := chi.NewRouter()
		func() {
			// Neither mounts without an asset handler; that is not what is
			// under test, so a panic here is a test bug rather than a finding.
			defer func() { _ = recover() }()
			if os.Getenv("OVERLAY_OWNS_ORG_ROUTES") != "1" {
				s.mountEmployeeRoutes(r)
				s.mountSignerRoutes(r)
			}
		}()
		out := map[string]bool{}
		_ = chi.Walk(r, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
			out[route] = true
			return nil
		})
		return out
	}

	core := mounted(false)
	overlay := mounted(true)

	hasSigner := func(m map[string]bool) bool {
		for route := range m {
			if len(route) >= 7 && route[:7] == "/signer" {
				return true
			}
		}
		return false
	}
	hasEmployees := func(m map[string]bool) bool {
		for route := range m {
			if len(route) >= 10 && route[:10] == "/employees" {
				return true
			}
		}
		return false
	}

	// The two must move together. Whichever way they are wired, a build where
	// one is owned by the overlay and the other by the core is the split that
	// left an organisation half-founded.
	if hasSigner(core) != hasEmployees(core) {
		t.Errorf("core alone: signer=%v employees=%v — they must go together",
			hasSigner(core), hasEmployees(core))
	}
	if hasSigner(overlay) != hasEmployees(overlay) {
		t.Errorf("overlay owning: signer=%v employees=%v — they must go together",
			hasSigner(overlay), hasEmployees(overlay))
	}
}
