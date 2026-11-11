package watcher

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// peer stands up an agent that answers a cross-check the way a real one does.
//
// digest nil means it has never seen the identity, which is the case that must
// not be confused with agreement.
func peer(t *testing.T, digest *string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req KelCheckRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		resp := KelCheckResponse{Match: digest != nil && *digest == req.Digest}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// peerService is a service whose chosen contacts are the given peers, each one
// where this agent first met EAlice's log, so each is a plausible knower.
func peerService(t *testing.T, peers ...*httptest.Server) *Service {
	t.Helper()
	s := storedService(t)
	s.SignRequest = func(string, string) (string, string, error) { return "Ewatcher", "sig", nil }
	// These peers are on loopback; a peer the owner recorded at a local address
	// is one an agent may call (see TestAPeerNameThatPointsInwardIsNotCalled).
	s.L3.AllowLocal = func(string) bool { return true }
	if err := s.SetPeerWatchEnabled(true); err != nil {
		t.Fatal(err)
	}
	s.PeerWatchers = func() []PeerWatcher {
		var out []PeerWatcher
		for i, p := range peers {
			out = append(out, PeerWatcher{AID: "EContact" + string(rune('A'+i)), URL: p.URL})
		}
		return out
	}
	for i, p := range peers {
		if err := s.RecordFirstSeen("EAlice", 100+i, "Ex", SourceOOBI, p.URL+"/public/oobi/EAlice"); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func TestPeersHoldingTheSameHistoryAgree(t *testing.T) {
	d := "EdigestAtSeqZero"
	s := peerService(t, peer(t, &d), peer(t, &d))
	outcomes, agreed := s.crossCheckPeers(context.Background(), "EAlice", 0, d, "")
	if agreed != 2 {
		t.Fatalf("agreed=%d, expected both peers to agree", agreed)
	}
	for _, o := range outcomes {
		if o.Outcome != "match" {
			t.Errorf("peer %s reported %q", o.URL, o.Outcome)
		}
	}
}

// A peer that does not match, whether it holds another history or none, is
// recorded as no_match and is neither agreement nor a disagreement.
func TestAPeerThatDoesNotMatchIsNotAgreement(t *testing.T) {
	other := "EtheirDigest"
	s := peerService(t, peer(t, &other), peer(t, nil))
	outcomes, agreed := s.crossCheckPeers(context.Background(), "EAlice", 0, "Edigest", "")
	if agreed != 0 || len(outcomes) != 2 {
		t.Fatalf("agreed=%d outcomes=%+v", agreed, outcomes)
	}
	for _, o := range outcomes {
		if o.Outcome != "no_match" {
			t.Errorf("expected no_match, got %q", o.Outcome)
		}
	}
}

func TestAnUnreachablePeerIsRecordedRatherThanIgnored(t *testing.T) {
	s := storedService(t)
	s.SignRequest = func(string, string) (string, string, error) { return "Ewatcher", "sig", nil }
	s.L3.AllowLocal = func(string) bool { return true }
	s.PeerWatchers = func() []PeerWatcher { return []PeerWatcher{{AID: "EPeer", URL: "http://127.0.0.1:1"}} }
	if err := s.SetPeerWatchEnabled(true); err != nil {
		t.Fatal(err)
	}
	outcomes, agreed := s.crossCheckPeers(context.Background(), "EAlice", 0, "Edigest", "http://127.0.0.1:1/public/oobi/EAlice")
	if agreed != 0 || len(outcomes) != 1 || outcomes[0].Outcome != "unavailable" {
		t.Fatalf("expected the failure recorded, got %+v", outcomes)
	}
}

func TestTheBoundaryIsAppliedWhenChoosingPeersAsWell(t *testing.T) {
	d := "Edigest"
	s := peerService(t, peer(t, &d))
	s.PeerAllowed = func(string) bool { return false }
	outcomes, agreed := s.crossCheckPeers(context.Background(), "EAlice", 0, d, "")
	if len(outcomes) != 0 || agreed != 0 {
		t.Fatalf("a peer the boundary refuses was queried anyway: %+v", outcomes)
	}
}

func TestNoPeersMeansNoCorroboration(t *testing.T) {
	s := &Service{L3: NewL3Client()}
	outcomes, agreed := s.crossCheckPeers(context.Background(), "EAlice", 0, "Edigest", "")
	if len(outcomes) != 0 || agreed != 0 {
		t.Fatalf("peers appeared from nowhere: %+v", outcomes)
	}
}
