package relay

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type stubSigner struct{}

func (stubSigner) SignCanonical(aid string, body map[string]interface{}) (string, error) {
	return "0Bstub", nil
}

// relayServer stands in for an operator, serving just enough of the protocol to
// exercise the manager's ordering: descriptor, then enroll, then allocate.
func relayServer(t *testing.T, tunnelEndpoint string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/url-relay-service.json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(ServiceDescriptor{
			V: JSONVersion, ProtocolVersion: "1.0", RelayAID: "ERelayOperator",
			TunnelEndpoint: tunnelEndpoint,
		})
	})
	mux.HandleFunc("/enroll", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		// The operator must never be handed the root. If this ever flips, an
		// operator can tie every allocation back to one identity.
		if body["root_aid_enrollment"] == true {
			t.Error("enrollment offered the root AID to a relay operator")
		}
		json.NewEncoder(w).Encode(map[string]any{
			"enrolled": true, "enrollment_aid": body["enrollment_aid"],
			"enrollment_token": "tok", "tunnel_endpoint": tunnelEndpoint,
		})
	})
	mux.HandleFunc("/allocate", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"public_url": "https://k7f2pq9r.relay-a.test", "public_hostname": "k7f2pq9r.relay-a.test",
			"allocation_token": "alloc", "tunnel_endpoint": tunnelEndpoint,
		})
	})
	return httptest.NewServer(mux)
}

func testConfig(base string) Config {
	return Config{
		BaseURL: base, EnrollmentAID: "EPairwiseForThisRelay",
		PublicKeyB64: "cHVi", OOBIUrl: "https://old.test/oobi/EAbc",
		RAID: "ERelationshipAID", LocalBase: "http://127.0.0.1:5050",
	}
}

// An allocation is a promise of an address, not a working one. Until the socket
// is up, publishing it would send counterparties somewhere nothing is
// listening.
func TestAllocatedButUnconnectedIsNotReachable(t *testing.T) {
	srv := relayServer(t, "ws://127.0.0.1:1/never")
	defer srv.Close()

	m := NewManager(testConfig(srv.URL), stubSigner{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := m.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer m.Stop()

	if url := m.URL(); url != "" {
		t.Errorf("URL() returned %q before the tunnel connected — an allocated "+
			"address that nothing is listening on must not be published", url)
	}
	st := m.GetStatus()
	if st.Active {
		t.Error("status reported active before the socket was up")
	}
	// The allocated address is still recorded, just not offered as reachable.
	if st.URL == "" {
		t.Error("the allocated address should be recorded even while unreachable")
	}
}

// Each step depends on the one before it. An allocation obtained without a
// successful enrollment would be a hostname nobody can prove belongs here.
func TestStartFailsWhenTheOperatorIsUnreachable(t *testing.T) {
	m := NewManager(testConfig("http://127.0.0.1:1"), stubSigner{})
	err := m.Start(context.Background())
	if err == nil {
		t.Fatal("expected a failure when the operator cannot be reached")
	}
	if !strings.Contains(err.Error(), "discover") {
		t.Errorf("error should name the step that failed, got: %v", err)
	}
	if m.GetStatus().Active {
		t.Error("a relay that never started must not report active")
	}
}

// An enrollment AID is what makes an allocation provably somebody's. Without
// one there is nothing to sign with and nothing to authenticate.
func TestEnrollmentAIDIsRequired(t *testing.T) {
	cfg := testConfig("https://relay.test")
	cfg.EnrollmentAID = ""
	err := NewManager(cfg, stubSigner{}).Start(context.Background())
	if err == nil {
		t.Fatal("expected refusal without an enrollment AID")
	}
}

// The operator is identified by host so somebody can see which operators they
// are relying on, and so selection can spread across them.
func TestProviderNameIsTheOperatorHost(t *testing.T) {
	for in, want := range map[string]string{
		"https://relay.grapeid.org":       "relay.grapeid.org",
		"https://relay-b.example.com/api": "relay-b.example.com",
		"http://127.0.0.1:9999":           "127.0.0.1:9999",
	} {
		if got := providerName(in); got != want {
			t.Errorf("providerName(%q) = %q, want %q", in, got, want)
		}
	}
}
