package server

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"identity-agent-core/asset"
	"identity-agent-core/store"
	"identity-agent-core/watcher"
	"identity-agent-core/witness"

	"github.com/go-chi/chi/v5"
)

// T-594. classify exact-matches "METHOD /pattern" against publicRoutes and
// falls through to owner-only, so a route mounted as peer-facing and never
// declared answers 403 to the peer it exists for, before its handler runs.
// That broke the watcher cross-check (recorded as the peer being "unavailable")
// and witness withdrawal (no witness could stand down). The same omission was
// already documented for invites, employees and DIDComm.

// servedThroughTheRealRouter exposes an agent at an address a peer can reach,
// behind the router a running agent really has, authorisation included. The
// bare route mounts startPeer uses skip that gate, which is how this went
// unseen.
func servedThroughTheRealRouter(t *testing.T, p *peerAgent) string {
	t.Helper()
	srv := httptest.NewServer(p.core.buildRouter())
	t.Cleanup(srv.Close)
	return srv.URL
}

// watcherAgent is an agent with a watcher that has seen one event.
func watcherAgent(t *testing.T, aid string, seq int, digest string) *CoreServer {
	t.Helper()
	ds, err := store.NewSQLiteStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ds.Close() })
	var db *sql.DB = ds.DB()
	ws := watcher.NewService(watcher.NewSQLiteStore(db))
	if err := ws.RecordFirstSeen(aid, seq, digest, watcher.SourceOOBI, "http://test/oobi"); err != nil {
		t.Fatalf("watcher store: %v", err)
	}
	s := newAuthTestServer(t)
	s.WatcherService = ws
	s.WitnessService = witness.NewService(witness.NewSQLiteStore(db), ds, nil, witness.BackendDesktop)
	return s
}

// Every route the code mounts under /public/ must be declared public. Walks the
// router, as TestEveryOpenRouteIsMountedWhereItSaysItIs does for the other
// direction, because asking classify only confirms what the map says.
func TestEveryRouteMountedUnderPublicIsDeclaredPublic(t *testing.T) {
	s := watcherAgent(t, "EAID", 1, "Edigest")
	ah, err := asset.NewHandler(s.DataDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.assetHandler = ah

	var seen []string
	if err := chi.Walk(s.buildRouter(),
		func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
			if strings.HasPrefix(route, "/public/") {
				seen = append(seen, method+" "+route)
				if classify(method, route) != accessPublic {
					t.Errorf("%s %s is mounted under /public/ but is not in publicRoutes, "+
						"so every peer is refused 403 before its handler runs", method, route)
				}
			}
			return nil
		}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"GET /public/kel-digest", "POST /public/kel-check"} {
		found := false
		for _, g := range seen {
			found = found || g == want
		}
		if !found {
			t.Errorf("%s was not among the /public/ routes walked (%v), so this test no longer covers it", want, seen)
		}
	}
}

// The witnessing protocol is declared public in both directions: a peer
// relationship that can be created remotely can be ended remotely.
func TestEveryWitnessProtocolRouteIsDeclaredPublic(t *testing.T) {
	for _, key := range []string{
		"POST /api/witness/request", "POST /api/witness/accept",
		"POST /api/witness/withdraw", "POST /api/witness/withdraw/confirm",
	} {
		parts := strings.SplitN(key, " ", 2)
		if classify(parts[0], parts[1]) != accessPublic {
			t.Errorf("%s is part of the witnessing protocol and is owner-gated", key)
		}
	}
}

// Two agents complete the watcher cross-check over the network, and a peer is
// told the truth about a digest that does not match.
func TestTwoWatchersCrossCheckEachOtherOverTheNetwork(t *testing.T) {
	bob := watcherAgent(t, "EAID", 1, "Edigest")
	srv := httptest.NewServer(bob.buildRouter())
	defer srv.Close()

	// Alice's watcher asks bob's. The default HTTP client reaches bob from
	// loopback without the owner secret, i.e. as a peer.
	alice := watcher.NewService(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	resp, err := alice.L3.CrossCheck(ctx, srv.URL, watcher.KelCheckRequest{AID: "EAID", Seq: 1, Digest: "Edigest"})
	if err != nil {
		t.Fatalf("a peer's cross-check was refused: %v", err)
	}
	if !resp.Match || resp.OurDigest == nil {
		t.Fatalf("matching digest reported as %+v", resp)
	}
	resp, err = alice.L3.CrossCheck(ctx, srv.URL, watcher.KelCheckRequest{AID: "EAID", Seq: 1, Digest: "Eother"})
	if err != nil || resp.Match {
		t.Fatalf("a different digest was reported as a match: %+v, %v", resp, err)
	}
	if err := alice.CrossCheck(ctx, srv.URL, "EAID", 1, "Edigest"); err != nil {
		t.Fatalf("Service.CrossCheck against a peer: %v", err)
	}

	get, err := http.Get(srv.URL + "/public/kel-digest?aid=EAID&seq=1")
	if err != nil {
		t.Fatal(err)
	}
	get.Body.Close()
	if get.StatusCode != http.StatusOK {
		t.Fatalf("kel-digest answered a peer with %d", get.StatusCode)
	}
}

// The T-595 exchange again, but each agent is reached through its full router.
func TestWithdrawalCompletesBetweenTwoAgentsBehindTheirAuthorisation(t *testing.T) {
	routed := map[*peerAgent]string{}
	withdrawalBetweenTwoAgents(t, func(p *peerAgent) string {
		if u, ok := routed[p]; ok {
			return u
		}
		u := servedThroughTheRealRouter(t, p)
		routed[p] = u
		return u
	})
}
