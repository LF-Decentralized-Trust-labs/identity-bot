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

// An operator that remembers, as a real one does: a second enrolment or
// allocation for the same identity is answered "already done", with no token.
func rememberingRelay(t *testing.T, released *int, signed *bool) *httptest.Server {
	t.Helper()
	enrolled, allocated := map[string]bool{}, map[string]bool{}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/url-relay-service.json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(ServiceDescriptor{V: JSONVersion, ProtocolVersion: "1.0", TunnelEndpoint: "ws://127.0.0.1:1/tunnel"})
	})
	mux.HandleFunc("/enroll", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		if body["signature"] != nil {
			*signed = true
		}
		aid, _ := body["enrollment_aid"].(string)
		if enrolled[aid] {
			http.Error(w, `{"error":"already_enrolled"}`, http.StatusConflict)
			return
		}
		enrolled[aid] = true
		json.NewEncoder(w).Encode(map[string]any{"enrolled": true, "enrollment_aid": aid, "enrollment_token": "tok-" + aid})
	})
	mux.HandleFunc("/allocate", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		raid, _ := body["raid"].(string)
		if allocated[raid] {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]any{"error": "already_allocated",
				"public_hostname": "k7f2pq9r.relay-a.test", "public_url": "https://k7f2pq9r.relay-a.test"})
			return
		}
		allocated[raid] = true
		json.NewEncoder(w).Encode(map[string]any{"public_url": "https://k7f2pq9r.relay-a.test",
			"public_hostname": "k7f2pq9r.relay-a.test", "allocation_token": "alloc-" + raid})
	})
	mux.HandleFunc("/release", func(w http.ResponseWriter, r *http.Request) { *released++ })
	return httptest.NewServer(mux)
}

// A restarted agent comes back at the same address: it signs its enrolment,
// keeps a permanent address when it stops, and reconnects with the tokens it
// remembered when the operator says it is already enrolled and allocated.
func TestARestartedAgentKeepsItsAddress(t *testing.T) {
	released, signed := 0, false
	srv := rememberingRelay(t, &released, &signed)
	defer srv.Close()

	first := NewManager(testConfig(srv.URL), stubSigner{})
	if err := first.Start(context.Background()); err != nil {
		t.Fatalf("first start: %v", err)
	}
	if !signed {
		t.Error("the enrolment was not signed")
	}
	url := first.GetStatus().URL
	enrollment, allocation := first.Tokens()
	first.Stop()
	if released != 0 {
		t.Fatal("stopping gave up a permanent address")
	}

	cfg := testConfig(srv.URL)
	cfg.EnrollmentToken, cfg.AllocationToken = enrollment, allocation
	second := NewManager(cfg, stubSigner{})
	if err := second.Start(context.Background()); err != nil {
		t.Fatalf("restart: %v", err)
	}
	defer second.Stop()
	if got := second.GetStatus().URL; got != url {
		t.Fatalf("the address moved on restart: %q then %q", url, got)
	}
	if _, a := second.Tokens(); a != allocation {
		t.Fatalf("the restarted agent does not hold its allocation: %q", a)
	}
}
