package tunnel

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"identity-agent-core/relay"
)

// A hub that checks requests the way the Grape ID hub does: a claim is signed by
// the key it presents and carries a key log, and every later request is signed
// by the key that claimed the name.
type fakeHub struct {
	mu       sync.Mutex
	owner    string
	key      string
	claims   int
	rejoins  int
	releases int
	problems []string
}

func (h *fakeHub) verify(raw []byte, key string) bool {
	var body map[string]interface{}
	if json.Unmarshal(raw, &body) != nil {
		return false
	}
	sig, _ := base64.RawURLEncoding.DecodeString(body["signature"].(string))
	pub, _ := base64.RawURLEncoding.DecodeString(key)
	canonical, _ := relay.CanonicalBody(body)
	return len(pub) == ed25519.PublicKeySize && ed25519.Verify(pub, canonical, sig)
}

func (h *fakeHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var body map[string]interface{}
	_ = json.Unmarshal(raw, &body)
	h.mu.Lock()
	defer h.mu.Unlock()
	switch r.URL.Path {
	case "/claim-name":
		h.claims++
		key, _ := body["public_key_b64"].(string)
		if kel, _ := body["kel_cesr_b64"].(string); kel == "" {
			h.problems = append(h.problems, "a claim carried no key log")
		}
		if !h.verify(raw, key) {
			h.problems = append(h.problems, "a claim was not signed by the key it presents")
		}
		h.owner, h.key = body["aid"].(string), key
		json.NewEncoder(w).Encode(map[string]any{"name": body["name"], "port": 40001, "tunnel_path": "/tunnel"})
	case "/reconnect":
		if h.owner == "" {
			http.Error(w, `{"error":"name not found"}`, http.StatusNotFound)
			return
		}
		h.rejoins++
		if body["aid"] != h.owner || !h.verify(raw, h.key) {
			h.problems = append(h.problems, "a reconnect was not signed by the name's owner")
		}
		json.NewEncoder(w).Encode(map[string]any{"name": body["name"], "port": 40001, "tunnel_path": "/tunnel"})
	case "/release-name":
		h.releases++
	default:
		http.NotFound(w, r)
	}
}

func testOwner(t *testing.T) *NameOwner {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 9
	key := ed25519.NewKeyFromSeed(seed)
	return &NameOwner{
		AID:          "ENameOwner",
		PublicKeyB64: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)),
		KELCESRB64:   "a2Vs",
		Sign: func(c []byte) (string, error) {
			return base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, c)), nil
		},
	}
}

// A Grape ID tunnel name is claimed with a signed request that proves which key
// owns it, kept when the agent stops, and reconnected to with that key after a
// restart — so the agent's address survives it.
func TestATunnelNameIsClaimedOnceAndKeptAcrossRestarts(t *testing.T) {
	hub := &fakeHub{}
	srv := httptest.NewServer(hub)
	defer srv.Close()
	// A domain naming localhost is reached over plain HTTP, which the test hub serves.
	cfg := Config{Provider: ProviderGrapeID, TunnelExtension: "acme", NameOwner: testOwner(t),
		TunnelDomain: strings.Replace(strings.TrimPrefix(srv.URL, "http://"), "127.0.0.1", "localhost", 1)}

	for i := 0; i < 2; i++ {
		p := NewGrapeIDProvider(cfg)
		if err := p.Start(context.Background(), 5050); err != nil {
			t.Fatalf("start %d: %v", i+1, err)
		}
		if err := p.Stop(); err != nil {
			t.Fatal(err)
		}
	}
	hub.mu.Lock()
	defer hub.mu.Unlock()
	for _, p := range hub.problems {
		t.Error(p)
	}
	if hub.claims != 1 || hub.rejoins != 1 {
		t.Fatalf("expected one claim then one reconnect, got %d claims and %d reconnects", hub.claims, hub.rejoins)
	}
	if hub.releases != 0 {
		t.Fatal("stopping gave the name back, so the next start could lose the address")
	}
}

// Without an identity to own the name, nothing is sent: the hub would refuse
// it, and an unsigned claim is exactly what it exists to refuse.
func TestATunnelNameIsNotClaimedWithoutAnOwner(t *testing.T) {
	hub := &fakeHub{}
	srv := httptest.NewServer(hub)
	defer srv.Close()
	p := NewGrapeIDProvider(Config{Provider: ProviderGrapeID,
		TunnelDomain: strings.Replace(strings.TrimPrefix(srv.URL, "http://"), "127.0.0.1", "localhost", 1), TunnelExtension: "acme"})
	if err := p.Start(context.Background(), 5050); err == nil {
		t.Fatal("started a Grape ID tunnel with nobody to own its name")
	}
	if hub.claims != 0 {
		t.Fatal("an unsigned claim was sent")
	}
}
