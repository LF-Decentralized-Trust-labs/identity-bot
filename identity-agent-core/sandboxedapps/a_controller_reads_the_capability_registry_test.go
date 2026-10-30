package sandboxedapps

import (
	"identity-agent-core/internal/addonhost"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fixtures are the worlds the core's tests build, for these.
var fixtures = addonhost.TestFixtures()

// An authorized controller does the application's work (ADR-044), so reading
// the capability registry no longer re-checks the owner inside the handler: the
// router-wide gate decides who may reach it, and admits the owner's authorized
// controller as it admits the owner. Importing a capability pack, which defines
// the capabilities, with their host-control and egress rules, that the gateway
// trusts at invoke time, stays owner-only.

func TestCapabilityRegistryListNoLongerOwnerGatedInHandler(t *testing.T) {
	s := fixtures.NewAuthTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/capability-registry", nil)
	rec := httptest.NewRecorder()

	of(s).handleListCapabilityRegistry(rec, req)

	if rec.Code == http.StatusForbidden {
		t.Fatalf("reading the capability registry still returns 403 from the handler, so "+
			"a controller acting for the owner would be refused; body: %s", rec.Body.String())
	}
}

func TestCapabilityPackImportStaysOwnerOnly(t *testing.T) {
	s := fixtures.NewAuthTestServer(t)
	// A request that is not the owner: not from this machine, not sealed by the
	// owner's identity, not owner-signed. isOwner is false, so import must refuse it.
	req := httptest.NewRequest(http.MethodPost, "/api/capability-registry/packs",
		strings.NewReader(`{"pack":"x","capabilities":[]}`))
	rec := httptest.NewRecorder()

	of(s).handleImportCapabilityPack(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("importing a capability pack returned %d, but it defines the capabilities "+
			"the gateway trusts and must stay owner-only — not reachable by a controller",
			rec.Code)
	}
}

// Installing software on this computer is closed to a machine acting for the
// owner, at any score, by this add-on's own rule (ADR-050).
func TestNoControllerInstallsSoftwareOnThisComputer(t *testing.T) {
	if why := helpers.ControllerOwnerOnly()["POST /api/sandbox/podman/setup"]; why == "" {
		t.Fatal("setting up the container runtime is open to a controller")
	}
}
