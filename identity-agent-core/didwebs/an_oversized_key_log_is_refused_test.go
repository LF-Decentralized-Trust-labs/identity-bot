package didwebs

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/internal/boundedread"
)

// A key log longer than the limit is refused. Cut at the limit it could still
// parse, as a shorter and valid log, so the resolver must never see the cut.
func TestAKeyLogOverTheLimitIsRefusedNotCut(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"kel":[],"aid":"E1","pad":"` + strings.Repeat("a", int(maxKeyLogAnswer)) + `"}`))
	}))
	defer srv.Close()
	r := &Resolver{HTTPClient: srv.Client()}
	if res, err := r.fetch(context.Background(), srv.URL); !errors.Is(err, boundedread.ErrTooLarge) || res != nil {
		t.Fatalf("fetch: %v %v", res, err)
	}
	if kel, err := r.fetchOOBIKEL(context.Background(), srv.URL); !errors.Is(err, boundedread.ErrTooLarge) || kel != nil {
		t.Fatalf("fetchOOBIKEL: %v %v", kel, err)
	}
}

// One just under it is read whole.
func TestAKeyLogAtTheLimitIsRead(t *testing.T) {
	body := strings.Repeat("a", int(maxKeyLogAnswer))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
	defer srv.Close()
	res, err := (&Resolver{HTTPClient: srv.Client()}).fetch(context.Background(), srv.URL)
	if err != nil || len(res.body) != len(body) {
		t.Fatalf("%v", err)
	}
}
