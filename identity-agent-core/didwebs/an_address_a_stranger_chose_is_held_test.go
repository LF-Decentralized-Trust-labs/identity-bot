package didwebs

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// The URLs come from a link someone else wrote; a local service must not be
// reached through them.
func TestTheResolverDoesNotReachAnInternalService(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	r := NewResolver(nil)
	_, status, _ := r.Resolve(context.Background(), &ArtifactURLs{
		DID: "did:webs:x:EA", AID: "EA", Host: "x",
		DidJSONURL: srv.URL + "/EA/did.json", CesrURL: srv.URL + "/EA/keri.cesr", OobiURL: srv.URL + "/oobi/EA",
	})
	if n := hits.Load(); n != 0 {
		t.Fatalf("the internal service was reached %d times (status %v)", n, status)
	}
}
