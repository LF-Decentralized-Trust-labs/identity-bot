package watcher

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"identity-agent-core/witness"
)

// A peer, or a hint a peer's introduction carried, whose name was public when
// it was recorded and points at an internal service when dialled is not called,
// on either layer, and a client that was not guarded would have reached it
// (foo.localhost resolves to loopback without any help from the test).
func TestAPeerNameThatPointsInwardIsNotCalled(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	base := "http://foo.localhost:" + port

	// Control: the name does resolve, so an unguarded call lands.
	if resp, err := http.DefaultClient.Get(base); err != nil {
		t.Skipf("this machine does not resolve foo.localhost: %v", err)
	} else {
		resp.Body.Close()
	}
	hits.Store(0)
	restore := witness.UseDialResolverForTest(func(string) ([]string, error) { return []string{"127.0.0.1"}, nil })
	defer restore()

	if _, _, err := NewL2Client().QueryDigest(context.Background(), base, "EAlice", 0); err == nil {
		t.Error("L2: a name that resolves inward was called")
	}
	if _, err := NewL3Client().CrossCheck(context.Background(), base, KelCheckRequest{AID: "EAlice"}); err == nil {
		t.Error("L3: a name that resolves inward was called")
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the internal service was reached %d times", n)
	}

	// The owner having recorded the peer lets L3 reach a local one.
	l3 := NewL3Client()
	l3.AllowLocal = func(string) bool { return true }
	if _, err := l3.CrossCheck(context.Background(), srv.URL, KelCheckRequest{AID: "EAlice"}); err != nil {
		t.Errorf("L3: a local peer the owner recorded was refused: %v", err)
	}
}
